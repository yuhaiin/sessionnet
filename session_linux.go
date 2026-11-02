//go:build linux

package sessionnet

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

const (
	tunSetIFF = 0x400454ca
	iffTUN    = 0x0001
	iffNoPI   = 0x1000
)

// Session owns a paused process in its own network+mount namespaces.
// Call DupTun, connect it to the packet stack and then Release. If packet
// processing cannot be initialized, call Close without releasing the child.
type Session struct {
	cmd         *exec.Cmd
	tun         *os.File
	name        string
	ready       *os.File
	done        chan struct{}
	stopContext func() bool
	mu          sync.Mutex
	finished    error
	released    bool
	closed      bool
	closeOnce   sync.Once
	cgroup      *sessionCgroup
	closeErr    error
}

func validate(c Config) error {
	if len(c.Command) == 0 || strings.TrimSpace(c.Command[0]) == "" {
		return errors.New("sessionnet: command is required")
	}
	if c.Credential == nil || c.Credential.UID == 0 || c.Credential.GID == 0 {
		return errors.New("sessionnet: an unprivileged uid/gid is required")
	}
	for _, group := range c.Credential.Groups {
		if group == 0 {
			return errors.New("sessionnet: supplementary root group is forbidden")
		}
	}
	if c.MTU != 0 && (c.MTU < 1280 || c.MTU > 9000) {
		return errors.New("sessionnet: MTU must be 1280..9000")
	}
	if c.PTYSlave != nil && (c.Stdin != nil || c.Stdout != nil || c.Stderr != nil) {
		return errors.New("sessionnet: PTYSlave conflicts with stdio")
	}
	return nil
}

// Open sets up a network namespace and a kernel TUN, but leaves the command
// blocked on an inherited private pipe until Release is called. Nothing is
// routed through the host default route. No packet forwarding occurs in this
// package, and the caller MUST provide a working packet handler before Release.
func Open(ctx context.Context, cfg Config) (_ *Session, err error) {
	if err := validate(cfg); err != nil {
		return nil, err
	}
	addresses, err := cfg.Addresses.Resolve(cfg.IPv6)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var group *sessionCgroup
	if cfg.Cgroup != nil {
		group, err = cfg.Cgroup.newGroup()
		if err != nil {
			return nil, err
		}
		defer func() {
			if err != nil {
				err = errors.Join(err, group.Close())
			}
		}()
	}
	name, err := randomInterfaceName()
	if err != nil {
		return nil, err
	}
	tun, err := createTun(name)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			_ = tun.Close()
		}
	}()

	r, w, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	defer r.Close()
	// Execute argv via positional shell arguments, not string interpolation.
	// File descriptor 3 is a one-time startup gate.
	shell := `IFS= read -r startup <&3 || exit 125; [ "$startup" = READY ] || exit 125; exec "$@"`
	args := append([]string{"-c", shell, "sessionnet-gate"}, cfg.Command...)
	cmd := exec.Command("/bin/sh", args...)
	cmd.Dir, cmd.Env = cfg.Dir, cfg.Env
	if cfg.Env == nil {
		cmd.Env = os.Environ()
	}
	cmd.ExtraFiles = []*os.File{r}
	if cfg.PTYSlave != nil {
		cmd.Stdin, cmd.Stdout, cmd.Stderr = cfg.PTYSlave, cfg.PTYSlave, cfg.PTYSlave
	} else {
		cmd.Stdin, cmd.Stdout, cmd.Stderr = cfg.Stdin, cfg.Stdout, cfg.Stderr
	}
	cmd.WaitDelay = 2 * time.Second // Bound waits for inherited stdout/stderr pipes.
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags: uintptr(syscall.CLONE_NEWNET | syscall.CLONE_NEWNS),
		Credential: &syscall.Credential{Uid: cfg.Credential.UID, Gid: cfg.Credential.GID, Groups: append([]uint32{}, cfg.Credential.Groups...)},
		Setpgid:    cfg.PTYSlave == nil,
		Setsid:     cfg.PTYSlave != nil,
		Setctty:    cfg.PTYSlave != nil,
		Ctty:       0,
	}
	if group != nil {
		cmd.SysProcAttr.UseCgroupFD = true
		cmd.SysProcAttr.CgroupFD = int(group.fd.Fd())
	}
	if err = cmd.Start(); err != nil {
		_ = w.Close()
		return nil, fmt.Errorf("sessionnet: spawn isolated process: %w", err)
	}
	s := &Session{cmd: cmd, tun: tun, name: name, ready: w, done: make(chan struct{}), cgroup: group}
	go func() {
		result := cmd.Wait()
		s.mu.Lock()
		s.finished = result
		s.mu.Unlock()
		close(s.done)
	}()
	defer func() {
		if err != nil {
			_ = s.Close()
		}
	}()
	mtu := cfg.MTU
	if mtu == 0 {
		mtu = DefaultMTU
	}
	if err = configureNetwork(ctx, cmd.Process.Pid, name, mtu, cfg.IPv6, addresses); err != nil {
		return nil, fmt.Errorf("sessionnet: configure isolated network: %w", err)
	}
	if err = configureResolver(cmd.Process.Pid, addresses.GatewayIPv4.String(), cfg.IsolateDNS); err != nil {
		return nil, fmt.Errorf("sessionnet: configure isolated resolver: %w", err)
	}
	s.stopContext = context.AfterFunc(ctx, func() { _ = s.Close() })
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	select {
	case <-s.done:
		return nil, errors.New("sessionnet: session command exited during network setup")
	default:
	}
	return s, nil
}

// DupTun returns an independently owned duplicate of the raw IP packet FD.
// The caller must close it, normally by giving it to its packet stack.
func (s *Session) DupTun() (*os.File, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, os.ErrClosed
	}
	fd, err := syscall.Dup(int(s.tun.Fd()))
	if err != nil {
		return nil, err
	}
	syscall.CloseOnExec(fd)
	// os.NewFile enrolls a nonblocking descriptor in Go's poller. Without
	// this, Close cannot interrupt a blocked TUN read and packet-stack
	// shutdown can wait indefinitely for another incoming packet.
	if err := syscall.SetNonblock(fd, true); err != nil {
		_ = syscall.Close(fd)
		return nil, err
	}
	return os.NewFile(uintptr(fd), s.name+"-packets"), nil
}

// Interface returns the isolated kernel TUN interface name.
func (s *Session) Interface() string { return s.name }
func (s *Session) PID() int          { return s.cmd.Process.Pid }

// Signal forwards a signal to the session command. os.Process synchronizes
// signaling with Wait so an already-reaped PID cannot target a new process.
// For terminal-generated job-control signals, use the controlling PTY instead.
func (s *Session) Signal(signal os.Signal) error { return s.cmd.Process.Signal(signal) }

// Release starts the isolated command after the caller's packet stack is ready.
func (s *Session) Release() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return os.ErrClosed
	}
	if s.released {
		return errors.New("sessionnet: already released")
	}
	s.released = true
	_, err := io.WriteString(s.ready, "READY\n")
	return errors.Join(err, s.ready.Close())
}

func (s *Session) Done() <-chan struct{} { return s.done }
func (s *Session) Wait() error {
	<-s.done
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.finished
}

// Close kills all processes in the managed cgroup, or falls back to the
// process group if no cgroup was configured. It also closes its TUN and
// waits for the namespace owner. Duplicated TUN descriptors remain caller-owned.
func (s *Session) Close() error {
	s.closeOnce.Do(func() {
		s.mu.Lock()
		s.closed = true
		_ = s.ready.Close()
		s.mu.Unlock()
		if s.cgroup != nil {
			s.closeErr = errors.Join(s.closeErr, s.cgroup.Close())
		}
		select {
		case <-s.done:
		default:
			_ = syscall.Kill(-s.cmd.Process.Pid, syscall.SIGKILL)
			_ = s.cmd.Process.Kill()
		}
		<-s.done
		s.closeErr = errors.Join(s.closeErr, s.tun.Close())
		if s.stopContext != nil {
			s.stopContext()
		}
	})
	return s.closeErr
}

func randomInterfaceName() (string, error) {
	var b [5]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return "snt" + hex.EncodeToString(b[:]), nil
}

func createTun(name string) (*os.File, error) {
	fd, err := syscall.Open("/dev/net/tun", syscall.O_RDWR|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("sessionnet: open /dev/net/tun: %w", err)
	}
	// struct ifreq starts with IFNAMSIZ name bytes + uint16 flags.
	// A 40-byte buffer accommodates the Linux ifreq ABI on amd64/arm64.
	var ifr [40]byte
	copy(ifr[:16], name)
	binary.NativeEndian.PutUint16(ifr[16:18], iffTUN|iffNoPI)
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), uintptr(tunSetIFF), uintptr(unsafe.Pointer(&ifr[0])))
	if errno != 0 {
		_ = syscall.Close(fd)
		return nil, fmt.Errorf("sessionnet: TUNSETIFF: %w", errno)
	}
	return os.NewFile(uintptr(fd), name), nil
}
