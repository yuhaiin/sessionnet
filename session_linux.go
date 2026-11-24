//go:build linux

package sessionnet

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// ErrSupervisorExited reports that the session supervisor, and with it every
// process of the session, terminated.
var ErrSupervisorExited = errors.New("sessionnet: session supervisor exited")

// Session owns one helper process and therefore one set of namespaces, one
// TUN and one PID namespace. Call DupTun, connect it to the packet stack and
// then Release. If packet processing cannot be initialized, Close the
// session without releasing it.
type Session struct {
	mode    Mode
	helper  *exec.Cmd
	ctl     *controlConn
	tun     *os.File
	diag    *os.File
	netns   *os.File
	name    string
	cred    Credential
	cgroup  *sessionCgroup
	ctx     context.Context
	initial *Config
	timings SetupTimings

	helperDone chan struct{}
	readerDone chan struct{}
	done       chan struct{}

	mu          sync.Mutex
	nextID      uint64
	procs       map[uint64]*Process
	first       *Process
	finished    error
	released    bool
	closed      bool
	closeOnce   sync.Once
	closeErr    error
	stopContext func() bool
}

func validate(c Config, mode Mode, cred Credential) error {
	if c.Command != nil && (len(c.Command) == 0 || strings.TrimSpace(c.Command[0]) == "") {
		return errors.New("sessionnet: command must not be empty")
	}
	// Rootless sessions may keep the caller's root identity: the user namespace
	// cannot grant more than the caller already holds.
	if mode == ModeRootful {
		if cred.UID == 0 || cred.GID == 0 {
			return errors.New("sessionnet: rootful mode requires an unprivileged uid/gid")
		}
		for _, group := range cred.Groups {
			if group == 0 {
				return errors.New("sessionnet: supplementary root group is forbidden in rootful mode")
			}
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

// resolveCredential applies the rootless default of running as the caller.
func resolveCredential(mode Mode, cred *Credential) (Credential, error) {
	if cred == nil {
		if mode == ModeRootful {
			return Credential{}, errors.New("sessionnet: rootful mode requires an explicit credential")
		}
		return Credential{UID: uint32(os.Geteuid()), GID: uint32(os.Getegid())}, nil
	}
	return Credential{UID: cred.UID, GID: cred.GID, Groups: append([]uint32{}, cred.Groups...)}, nil
}

// Open creates the session namespaces, its TUN, routes and resolver and a
// capability-free supervisor. Commands do not run until Release (for
// Config.Command) or Spawn. No traffic can leave the session except through
// the TUN; the caller MUST provide a working packet handler before Release.
// Open never falls back to the host network.
func Open(ctx context.Context, cfg Config) (_ *Session, err error) {
	mode, err := cfg.Mode.Resolve()
	if err != nil {
		return nil, err
	}
	cred, err := resolveCredential(mode, cfg.Credential)
	if err != nil {
		return nil, err
	}
	if err := validate(cfg, mode, cred); err != nil {
		return nil, err
	}
	addresses, err := cfg.Addresses.Resolve(cfg.IPv6)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var plan idMapPlan
	if mode == ModeRootless {
		if plan, err = planIDMaps(currentIdentity(), cred); err != nil {
			return nil, err
		}
	}
	mtu := cfg.MTU
	if mtu == 0 {
		mtu = DefaultMTU
	}
	helperPath := cfg.HelperPath
	if helperPath == "" {
		helperPath = "/proc/self/exe"
	}

	var group *sessionCgroup
	if cfg.Cgroup != nil {
		if group, err = cfg.Cgroup.newGroup(); err != nil {
			return nil, &SetupError{Stage: StageCgroup, Message: "cgroup delegation is unavailable: cannot create the session cgroup", Err: err}
		}
		defer func() {
			if err != nil {
				err = errors.Join(err, group.Close())
			}
		}()
	}
	ctl, child, err := newSocketPair()
	if err != nil {
		return nil, err
	}
	helper := &exec.Cmd{
		Path:       helperPath,
		Args:       []string{helperArgv0, helperArg},
		Env:        helperEnvironment(),
		Dir:        "/",
		ExtraFiles: []*os.File{child},
	}
	flags := uintptr(syscall.CLONE_NEWNET | syscall.CLONE_NEWNS | syscall.CLONE_NEWPID)
	helper.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if mode == ModeRootless {
		flags |= syscall.CLONE_NEWUSER
		// The first process of a new user namespace has every capability in
		// it, but execve would drop them for a non-zero UID. Keep only what
		// setup needs; the helper clears all of them before running anything
		// on behalf of the session.
		helper.SysProcAttr.AmbientCaps = []uintptr{unix.CAP_NET_ADMIN, unix.CAP_SYS_ADMIN,
			unix.CAP_SETUID, unix.CAP_SETGID, unix.CAP_SETPCAP}
	}
	helper.SysProcAttr.Cloneflags = flags
	if group != nil {
		helper.SysProcAttr.UseCgroupFD = true
		helper.SysProcAttr.CgroupFD = int(group.fd.Fd())
	}
	began := time.Now()
	startErr := helper.Start()
	_ = child.Close()
	if startErr != nil {
		_ = ctl.Close()
		return nil, classifyStartError(mode, startErr)
	}
	spawned := time.Now()
	s := &Session{
		mode: mode, helper: helper, ctl: ctl, name: DefaultInterface, cred: cred, cgroup: group, ctx: ctx,
		helperDone: make(chan struct{}), readerDone: make(chan struct{}), procs: make(map[uint64]*Process),
	}
	go func() {
		_ = helper.Wait()
		close(s.helperDone)
	}()
	defer func() {
		if err != nil {
			// A canceled context kills the helper, so later setup steps fail
			// with incidental errors; report the cancellation instead.
			if ctxErr := ctx.Err(); ctxErr != nil {
				err = ctxErr
			}
			s.abortSetup()
		}
	}()
	// Cancellation during setup kills the helper, which unblocks receive.
	stopSetup := context.AfterFunc(ctx, func() { _ = helper.Process.Kill() })
	defer stopSetup()

	s.timings.Spawn = spawned.Sub(began)
	if mode == ModeRootless {
		if err = writeIDMaps(helper.Process.Pid, plan); err != nil {
			return nil, err
		}
	}
	mapped := time.Now()
	s.timings.IDMap = mapped.Sub(spawned)
	init := &initRequest{
		Mode: mode, UID: cred.UID, GID: cred.GID, Groups: cred.Groups, SetGroups: plan.setGroups || mode == ModeRootful,
		Interface: s.name, MTU: mtu, IPv6: cfg.IPv6, IsolateDNS: cfg.IsolateDNS,
		SessionIPv4: addresses.SessionIPv4.String(), GatewayIPv4: addresses.GatewayIPv4.String(),
	}
	if init.Groups == nil {
		init.Groups = []uint32{}
	}
	if cfg.IPv6 {
		init.SessionIPv6, init.GatewayIPv6 = addresses.SessionIPv6.String(), addresses.GatewayIPv6.String()
	}
	if err = ctl.send(&message{Op: opInit, Init: init}); err != nil {
		return nil, s.setupFailure(ctx, err)
	}
	ready, files, err := ctl.receive()
	if err != nil {
		return nil, s.setupFailure(ctx, err)
	}
	if ready.Op == opFailed {
		closeFiles(files)
		return nil, annotate(mode, ready.Error.toError())
	}
	if ready.Op != opReady || len(files) != 3 {
		closeFiles(files)
		return nil, &SetupError{Stage: StageHandshake, Message: "the session helper sent an invalid handshake"}
	}
	s.tun, s.diag, s.netns = files[0], files[1], files[2]
	handshake := time.Now()
	if r := ready.Ready; r != nil {
		s.timings.Credentials, s.timings.Mounts, s.timings.TUN = time.Duration(r.Credentials), time.Duration(r.Mounts), time.Duration(r.TUN)
		s.timings.Network, s.timings.Diagnostics = time.Duration(r.Network), time.Duration(r.Diagnostics)
	}
	s.timings.Handshake = handshake.Sub(mapped)
	supervising, extra, err := ctl.receive()
	closeFiles(extra)
	if err != nil {
		return nil, s.setupFailure(ctx, err)
	}
	if supervising.Op == opFailed {
		return nil, annotate(mode, supervising.Error.toError())
	}
	if supervising.Op != opSupervising {
		return nil, &SetupError{Stage: StageHandshake, Message: "the session supervisor did not start"}
	}
	s.timings.Supervisor = time.Since(handshake)
	s.timings.Total = time.Since(began)
	if !stopSetup() || ctx.Err() != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, context.Canceled
	}
	if cfg.Command != nil {
		initial := cfg
		s.initial = &initial
		s.done = make(chan struct{})
	} else {
		s.done = s.helperDone
	}
	go s.readLoop()
	s.stopContext = context.AfterFunc(ctx, func() { _ = s.Close() })
	return s, nil
}

func annotate(mode Mode, err error) error {
	var setup *SetupError
	if mode == ModeRootless && errors.As(err, &setup) && setup.Stage != StageTUN {
		setup.Message += userNamespacePolicyHint()
	}
	return err
}

// setupFailure explains a broken handshake: a canceled context, or a helper
// that died before it could report a classified error.
func (s *Session) setupFailure(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	<-s.helperDone
	status := ""
	if state := s.helper.ProcessState; state != nil {
		status = ": " + state.String()
	}
	return &SetupError{Stage: StageHelper, Message: "the session helper exited during setup" + status, Err: err}
}

func (s *Session) abortSetup() {
	_ = s.helper.Process.Kill()
	<-s.helperDone
	_ = s.ctl.Close()
	closeFiles([]*os.File{s.tun, s.diag, s.netns})
}

// readLoop dispatches supervisor messages until the control socket closes.
func (s *Session) readLoop() {
	defer close(s.readerDone)
	for {
		m, files, err := s.ctl.receive()
		if err != nil {
			break
		}
		// The supervisor never sends descriptors after setup.
		closeFiles(files)
		s.mu.Lock()
		p := s.procs[m.ID]
		if p != nil && (m.Op == opExit || m.Op == opFailed) {
			delete(s.procs, m.ID)
		}
		s.mu.Unlock()
		if p == nil {
			continue
		}
		switch m.Op {
		case opStarted:
			p.markStarted(m.PID, nil)
		case opFailed:
			p.markStarted(0, m.Error.toError())
			p.finish(m.Error.toError())
		case opExit:
			if m.Status == 0 {
				p.finish(nil)
			} else {
				p.finish(&ExitError{Status: m.Status})
			}
		}
	}
	s.mu.Lock()
	procs := s.procs
	s.procs = map[uint64]*Process{}
	s.mu.Unlock()
	for _, p := range procs {
		p.markStarted(0, ErrSupervisorExited)
		p.finish(ErrSupervisorExited)
	}
}

// DupTun returns an independently owned duplicate of the raw IP packet FD.
// The caller must close it, normally by giving it to its packet stack.
func (s *Session) DupTun() (*os.File, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, os.ErrClosed
	}
	fd, err := unix.FcntlInt(s.tun.Fd(), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	// os.NewFile enrolls a nonblocking descriptor in Go's poller. Without
	// this, Close cannot interrupt a blocked TUN read and packet-stack
	// shutdown can wait indefinitely for another incoming packet.
	if err := unix.SetNonblock(fd, true); err != nil {
		_ = unix.Close(fd)
		return nil, err
	}
	return os.NewFile(uintptr(fd), s.name+"-packets"), nil
}

// DupDiag returns a duplicate of a NETLINK_SOCK_DIAG socket that was created
// inside the session network namespace. Queries on it see only the session's
// sockets, so process lookup never needs setns. UIDs are reported in the
// session user namespace, which uses identity mappings.
func (s *Session) DupDiag() (*os.File, error) { return s.dup(s.diag, "sock_diag") }

// DupNetNS returns a duplicate of the session's network namespace handle.
// It identifies the namespace (its inode); joining it is neither needed nor,
// in rootless mode, permitted for the caller.
func (s *Session) DupNetNS() (*os.File, error) { return s.dup(s.netns, "netns") }

func (s *Session) dup(file *os.File, name string) (*os.File, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, os.ErrClosed
	}
	fd, err := unix.FcntlInt(file.Fd(), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), name), nil
}

// SetupTimings reports how long each phase of Open took.
func (s *Session) SetupTimings() SetupTimings { return s.timings }

// Interface returns the TUN interface name inside the session.
func (s *Session) Interface() string { return s.name }

// PID returns the host PID of the session helper, which owns the session
// namespaces and is PID 1 of the session PID namespace.
func (s *Session) PID() int { return s.helper.Process.Pid }

// Mode reports how the session namespaces were created.
func (s *Session) Mode() Mode { return s.mode }

// Credential returns the IDs every session process runs as.
func (s *Session) Credential() Credential {
	return Credential{UID: s.cred.UID, GID: s.cred.GID, Groups: append([]uint32{}, s.cred.Groups...)}
}

// Signal forwards a signal to the initial command. The supervisor only
// signals a registered child it has not reaped, so a recycled PID is never
// targeted. For terminal-generated job-control signals, use the PTY instead.
func (s *Session) Signal(signal os.Signal) error {
	s.mu.Lock()
	first := s.first
	s.mu.Unlock()
	if first == nil {
		return errors.New("sessionnet: no initial command is running")
	}
	return first.Signal(signal)
}

// Release marks the packet path ready and starts Config.Command, if any.
func (s *Session) Release() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return os.ErrClosed
	}
	if s.released {
		s.mu.Unlock()
		return errors.New("sessionnet: already released")
	}
	s.released = true
	initial := s.initial
	s.mu.Unlock()
	if initial == nil {
		return nil
	}
	first, err := s.spawn(s.ctx, *initial, false)
	if err != nil {
		s.finishSession(err)
		return err
	}
	s.mu.Lock()
	s.first = first
	s.mu.Unlock()
	go func() {
		s.finishSession(first.Wait())
	}()
	return nil
}

func (s *Session) finishSession(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	select {
	case <-s.done:
		return
	default:
	}
	s.finished = err
	close(s.done)
}

// Done closes when the initial command exits. Without an initial command it
// closes when the session supervisor exits.
func (s *Session) Done() <-chan struct{} { return s.done }

// Wait reports the initial command's exit status, including nonzero exit
// codes as *ExitError. Without an initial command it waits for Close.
func (s *Session) Wait() error {
	<-s.done
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.finished
}

// Close terminates every process of the session and releases the
// namespaces. With a cgroup, cgroup.kill removes the whole tree atomically;
// in any case, killing PID 1 makes the kernel kill all remaining processes
// of the PID namespace, including daemonized and detached descendants.
// When Close returns, the PID namespace is empty. Duplicated descriptors
// remain owned by the caller.
func (s *Session) Close() error {
	s.closeOnce.Do(func() {
		s.mu.Lock()
		s.closed = true
		s.mu.Unlock()
		if s.cgroup != nil {
			s.closeErr = errors.Join(s.closeErr, s.cgroup.Close())
		}
		if err := s.helper.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
			s.closeErr = errors.Join(s.closeErr, fmt.Errorf("sessionnet: kill session supervisor: %w", err))
		}
		<-s.helperDone
		s.closeErr = errors.Join(s.closeErr, s.ctl.Close())
		<-s.readerDone
		s.closeErr = errors.Join(s.closeErr, s.tun.Close(), s.diag.Close(), s.netns.Close())
		if s.initial != nil {
			s.finishSession(ErrSupervisorExited)
		}
		if s.stopContext != nil {
			s.stopContext()
		}
	})
	return s.closeErr
}

// Probe creates and immediately closes a session with cfg's namespace,
// credential and address settings. It lets an application refuse to start a
// listener when this host cannot create sessions, with a classified error.
func Probe(ctx context.Context, cfg Config) error {
	cfg.Command, cfg.Stdin, cfg.Stdout, cfg.Stderr, cfg.PTYSlave = nil, nil, nil, nil, nil
	s, err := Open(ctx, cfg)
	if err != nil {
		return err
	}
	return s.Close()
}
