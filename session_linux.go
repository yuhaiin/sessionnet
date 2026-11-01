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
	"path/filepath"
	"strconv"
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
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	ipPath, err := exec.LookPath("ip")
	if err != nil {
		return nil, fmt.Errorf("sessionnet: iproute2 is required: %w", err)
	}
	nsenterPath, err := exec.LookPath("nsenter")
	if err != nil {
		return nil, fmt.Errorf("sessionnet: util-linux nsenter is required: %w", err)
	}
	mountPath, err := exec.LookPath("mount")
	if err != nil {
		return nil, fmt.Errorf("sessionnet: mount is required: %w", err)
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
	if err = cmd.Start(); err != nil {
		_ = w.Close()
		return nil, fmt.Errorf("sessionnet: spawn isolated process: %w", err)
	}
	s := &Session{cmd: cmd, tun: tun, name: name, ready: w, done: make(chan struct{})}
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
	pid := strconv.Itoa(cmd.Process.Pid)
	run := func(path string, args ...string) error {
		command := exec.CommandContext(ctx, path, args...)
		command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C"}
		output, runErr := command.CombinedOutput()
		if runErr != nil {
			return fmt.Errorf("%s %s: %w: %s", filepath.Base(path), strings.Join(args, " "), runErr, strings.TrimSpace(string(output)))
		}
		return nil
	}
	enter := func(args ...string) error {
		return run(nsenterPath, append([]string{"-t", pid, "-n", "--", ipPath}, args...)...)
	}
	// Interface starts in the host namespace without any routes; move it
	// into the private namespace while keeping the host-side FD open.
	if err = run(ipPath, "link", "set", "dev", name, "netns", pid); err != nil {
		return nil, err
	}
	if err = enter("link", "set", "dev", "lo", "up"); err != nil {
		return nil, err
	}
	mtu := cfg.MTU
	if mtu == 0 {
		mtu = DefaultMTU
	}
	if err = enter("link", "set", "dev", name, "mtu", strconv.Itoa(mtu)); err != nil {
		return nil, err
	}
	if err = enter("addr", "add", SessionIPv4, "dev", name); err != nil {
		return nil, err
	}
	if cfg.IPv6 {
		if err = enter("-6", "addr", "add", SessionIPv6, "dev", name, "nodad"); err != nil {
			return nil, err
		}
	}
	if err = enter("link", "set", "dev", name, "up"); err != nil {
		return nil, err
	}
	if err = enter("route", "replace", "default", "dev", name); err != nil {
		return nil, err
	}
	if cfg.IPv6 {
		if err = enter("-6", "route", "replace", "default", "dev", name); err != nil {
			return nil, err
		}
	}
	// A separate mount namespace is required to bind-mount a resolver file
	// without modifying the host's /etc/resolv.conf.
	tmp, err := os.MkdirTemp("", "sessionnet-resolv-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmp)
	resolvPath := filepath.Join(tmp, "resolv.conf")
	if err = os.WriteFile(resolvPath, []byte("nameserver "+GatewayIPv4+"\noptions timeout:2 attempts:2\n"), 0644); err != nil {
		return nil, err
	}
	mountEnter := func(args ...string) error {
		return run(nsenterPath, append([]string{"-t", pid, "-m", "--", mountPath}, args...)...)
	}
	if err = mountEnter("--make-rprivate", "/"); err != nil {
		return nil, err
	}
	if err = mountEnter("--bind", resolvPath, "/etc/resolv.conf"); err != nil {
		return nil, err
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
	return os.NewFile(uintptr(fd), s.name+"-packets"), nil
}

// Interface returns the isolated kernel TUN interface name.
func (s *Session) Interface() string { return s.name }
func (s *Session) PID() int          { return s.cmd.Process.Pid }

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

// Close kills the session process group, closes its TUN, and waits for exit.
// The caller must separately close its duplicated TUN FD and packet stack.
// Daemonized children which deliberately escape the process group require an
// enclosing cgroup; this package does not claim to provide a sandbox.
func (s *Session) Close() error {
	s.closeOnce.Do(func() {
		s.mu.Lock()
		s.closed = true
		_ = s.ready.Close()
		s.mu.Unlock()
		select {
		case <-s.done:
		default:
			_ = syscall.Kill(-s.cmd.Process.Pid, syscall.SIGKILL)
			_ = s.cmd.Process.Kill()
		}
		<-s.done
		_ = s.tun.Close()
		if s.stopContext != nil {
			s.stopContext()
		}
	})
	return nil
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
