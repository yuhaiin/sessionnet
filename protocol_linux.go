//go:build linux

package sessionnet

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

// The helper and its parent exchange one JSON document per SOCK_SEQPACKET
// datagram. Descriptors travel as SCM_RIGHTS on the same datagram. Every
// message from the helper is treated as untrusted once the helper has
// dropped its privileges, because session processes run as the same user.
const (
	maxMessageSize = 256 << 10
	maxMessageFDs  = 3

	opInit    = "init"
	opReady   = "ready"
	opFailed  = "failed"
	opSpawn   = "spawn"
	opStarted = "started"
	opSignal  = "signal"
	opKill    = "kill"
	opExit    = "exit"

	opSupervising = "supervising"
)

type message struct {
	Op     string        `json:"op"`
	ID     uint64        `json:"id,omitempty"`
	PID    int           `json:"pid,omitempty"`
	Signal int           `json:"signal,omitempty"`
	Status uint32        `json:"status,omitempty"`
	Init   *initRequest  `json:"init,omitempty"`
	Ready  *readyReply   `json:"ready,omitempty"`
	Spawn  *spawnRequest `json:"spawn,omitempty"`
	Error  *wireError    `json:"error,omitempty"`
}

// initRequest is sent once the parent has written the ID maps.
type initRequest struct {
	Mode        Mode     `json:"mode"`
	UID         uint32   `json:"uid"`
	GID         uint32   `json:"gid"`
	Groups      []uint32 `json:"groups"`
	SetGroups   bool     `json:"setGroups"`
	Interface   string   `json:"interface"`
	MTU         int      `json:"mtu"`
	IPv6        bool     `json:"ipv6"`
	SessionIPv4 string   `json:"sessionIPv4"`
	GatewayIPv4 string   `json:"gatewayIPv4"`
	SessionIPv6 string   `json:"sessionIPv6,omitempty"`
	GatewayIPv6 string   `json:"gatewayIPv6,omitempty"`
	IsolateDNS  bool     `json:"isolateDNS"`
}

// readyReply carries the TUN, sock_diag and network namespace descriptors.
type readyReply struct {
	Interface string `json:"interface"`
	// Phase durations measured inside the helper, in nanoseconds.
	Credentials int64 `json:"credentials"`
	Mounts      int64 `json:"mounts"`
	TUN         int64 `json:"tun"`
	Network     int64 `json:"network"`
	Diagnostics int64 `json:"diagnostics"`
}

type spawnRequest struct {
	Argv    []string `json:"argv"`
	Env     []string `json:"env"`
	Dir     string   `json:"dir"`
	TTY     bool     `json:"tty"`
	Setpgid bool     `json:"setpgid"`
}

type wireError struct {
	Stage   Stage  `json:"stage"`
	Message string `json:"message"`
	Detail  string `json:"detail,omitempty"`
	Errno   int    `json:"errno,omitempty"`
}

func (e *wireError) toError() error {
	if e == nil {
		return &SetupError{Stage: StageHelper, Message: "session helper failed without a reason"}
	}
	var cause error
	if e.Errno != 0 {
		cause = syscall.Errno(e.Errno)
		if e.Detail != "" {
			cause = fmt.Errorf("%s: %w", e.Detail, cause)
		}
	} else if e.Detail != "" {
		cause = errors.New(e.Detail)
	}
	return &SetupError{Stage: e.Stage, Message: e.Message, Err: cause}
}

func newWireError(stage Stage, message string, err error) *wireError {
	w := &wireError{Stage: stage, Message: message}
	if err == nil {
		return w
	}
	w.Detail = err.Error()
	if errno, ok := errnoOf(err); ok {
		w.Errno = int(errno)
		// Keep the detail free of the errno text added back by toError.
		if w.Detail == errno.Error() {
			w.Detail = ""
		} else if suffix := ": " + errno.Error(); len(w.Detail) > len(suffix) && w.Detail[len(w.Detail)-len(suffix):] == suffix {
			w.Detail = w.Detail[:len(w.Detail)-len(suffix)]
		}
	}
	return w
}

// controlConn wraps one end of the SOCK_SEQPACKET socketpair.
type controlConn struct{ conn *net.UnixConn }

func newSocketPair() (parent *controlConn, child *os.File, err error) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, nil, fmt.Errorf("create control socket: %w", err)
	}
	child = os.NewFile(uintptr(fds[1]), "sessionnet-control")
	parentFile := os.NewFile(uintptr(fds[0]), "sessionnet-control")
	parent, err = fileControlConn(parentFile)
	if err != nil {
		_ = child.Close()
		return nil, nil, err
	}
	return parent, child, nil
}

// fileControlConn takes ownership of file.
func fileControlConn(file *os.File) (*controlConn, error) {
	defer file.Close()
	conn, err := net.FileConn(file)
	if err != nil {
		return nil, err
	}
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		_ = conn.Close()
		return nil, errors.New("control descriptor is not a Unix socket")
	}
	return &controlConn{conn: unixConn}, nil
}

func (c *controlConn) send(m *message, files ...*os.File) error {
	data, err := json.Marshal(m)
	if err != nil {
		return err
	}
	if len(data) > maxMessageSize {
		return errors.New("control message too large")
	}
	var oob []byte
	if len(files) != 0 {
		fds := make([]int, len(files))
		for i, file := range files {
			fds[i] = int(file.Fd())
		}
		oob = unix.UnixRights(fds...)
	}
	n, oobn, err := c.conn.WriteMsgUnix(data, oob, nil)
	if err == nil && (n != len(data) || oobn != len(oob)) {
		err = errors.New("short control message write")
	}
	return err
}

// receive returns the next message and exactly the descriptors it carried.
// The caller owns the returned files. Truncated messages close all received
// descriptors and fail, so a peer cannot leak descriptors into this process.
func (c *controlConn) receive() (*message, []*os.File, error) {
	data := make([]byte, maxMessageSize+1)
	oob := make([]byte, unix.CmsgSpace(4*maxMessageFDs))
	n, oobn, flags, _, err := c.conn.ReadMsgUnix(data, oob)
	if err != nil {
		return nil, nil, err
	}
	files, parseErr := parseRights(oob[:oobn])
	if parseErr == nil && flags&(unix.MSG_TRUNC|unix.MSG_CTRUNC) != 0 {
		parseErr = errors.New("truncated control message")
	}
	if parseErr == nil && n == 0 {
		parseErr = errors.New("control peer closed")
	}
	var m message
	if parseErr == nil {
		parseErr = json.Unmarshal(data[:n], &m)
	}
	if parseErr != nil {
		closeFiles(files)
		return nil, nil, parseErr
	}
	return &m, files, nil
}

func parseRights(oob []byte) ([]*os.File, error) {
	if len(oob) == 0 {
		return nil, nil
	}
	messages, err := unix.ParseSocketControlMessage(oob)
	if err != nil {
		return nil, err
	}
	var files []*os.File
	var failure error
	for _, cmsg := range messages {
		fds, err := unix.ParseUnixRights(&cmsg)
		if err != nil {
			failure = errors.Join(failure, err)
			continue
		}
		for _, fd := range fds {
			// Go requests MSG_CMSG_CLOEXEC, so received descriptors are
			// already close-on-exec. Enforce it in case that ever changes.
			unix.CloseOnExec(fd)
			files = append(files, os.NewFile(uintptr(fd), "sessionnet-received"))
		}
	}
	if failure != nil {
		closeFiles(files)
		return nil, failure
	}
	return files, nil
}

func closeFiles(files []*os.File) {
	for _, file := range files {
		if file != nil {
			_ = file.Close()
		}
	}
}

func (c *controlConn) Close() error { return c.conn.Close() }

func errnoOf(err error) (syscall.Errno, bool) {
	var errno syscall.Errno
	ok := errors.As(err, &errno)
	return errno, ok
}
