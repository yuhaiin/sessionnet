//go:build linux

package sessionnet

import (
	"errors"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"
)

// supervisor is PID 1 of the session PID namespace. It holds no capability.
// It is the only process that reaps in the namespace: it never uses os/exec,
// whose per-child wait would race a wait4(-1) reaper for exit statuses.
type supervisor struct {
	conn *controlConn
	// mu serializes fork+registration against reaping. A child cannot be
	// reaped, and its PID recycled, between ForkExec and registration, and
	// "started" is always delivered before the same child's "exit".
	mu       sync.Mutex
	children map[int]*supervisedChild
	byID     map[uint64]*supervisedChild
}

type supervisedChild struct {
	id    uint64
	pid   int
	group bool
}

func supervise(conn *controlConn) int {
	// Same-user session processes must not be able to ptrace PID 1 and use
	// its control socket to impersonate the supervisor.
	if err := unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0); err != nil {
		_ = conn.send(&message{Op: opFailed, Error: newWireError(StagePrivileges, "cannot protect the session supervisor", err)})
		return 1
	}
	if err := verifyNoPrivileges(); err != nil {
		_ = conn.send(&message{Op: opFailed, Error: newWireError(StagePrivileges, "the session supervisor still holds privileges", err)})
		return 1
	}
	s := &supervisor{conn: conn, children: make(map[int]*supervisedChild), byID: make(map[uint64]*supervisedChild)}
	// Signals from inside the namespace only reach PID 1 if it handles them.
	// Handle (and discard) the usual termination signals instead of ignoring
	// them: an ignored disposition would be inherited by every session child.
	discard := make(chan os.Signal, 8)
	signal.Notify(discard, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT,
		syscall.SIGUSR1, syscall.SIGUSR2, syscall.SIGPIPE, syscall.SIGTTIN, syscall.SIGTTOU, syscall.SIGTSTP)
	go func() {
		for range discard {
		}
	}()
	childSignals := make(chan os.Signal, 1)
	signal.Notify(childSignals, syscall.SIGCHLD)
	go func() {
		for range childSignals {
			s.reap()
		}
	}()
	if err := conn.send(&message{Op: opSupervising}); err != nil {
		return 1
	}
	for {
		m, files, err := conn.receive()
		if err != nil {
			// The parent closed the session or died. Returning from PID 1
			// makes the kernel kill every remaining process in the namespace.
			return 0
		}
		switch m.Op {
		case opSpawn:
			s.spawn(m, files)
		case opSignal:
			closeFiles(files)
			s.signal(m.ID, m.Signal, false)
		case opKill:
			closeFiles(files)
			s.signal(m.ID, int(unix.SIGKILL), true)
		default:
			closeFiles(files)
		}
	}
}

func (s *supervisor) spawn(m *message, files []*os.File) {
	defer closeFiles(files)
	req := m.Spawn
	reply := func(err error) {
		_ = s.conn.send(&message{Op: opFailed, ID: m.ID, Error: newWireError(StageHelper, "cannot start the session command", err)})
	}
	if req == nil || len(req.Argv) == 0 || m.ID == 0 {
		reply(errors.New("invalid spawn request"))
		return
	}
	if len(files) != 3 {
		reply(errors.New("spawn request requires three stdio descriptors"))
		return
	}
	path, err := lookPath(req.Argv[0], req.Env)
	if err != nil {
		reply(err)
		return
	}
	attr := &syscall.ProcAttr{
		Dir:   req.Dir,
		Env:   req.Env,
		Files: []uintptr{files[0].Fd(), files[1].Fd(), files[2].Fd()},
		Sys: &syscall.SysProcAttr{
			Setsid:  req.TTY,
			Setctty: req.TTY,
			Ctty:    0,
			Setpgid: !req.TTY && req.Setpgid,
		},
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.byID[m.ID]; exists {
		reply(errors.New("duplicate spawn identifier"))
		return
	}
	pid, err := syscall.ForkExec(path, req.Argv, attr)
	if err != nil {
		reply(err)
		return
	}
	child := &supervisedChild{id: m.ID, pid: pid, group: req.TTY || req.Setpgid}
	s.children[pid], s.byID[m.ID] = child, child
	_ = s.conn.send(&message{Op: opStarted, ID: m.ID, PID: pid})
}

// signal delivers sig to a live, still-unreaped child. Holding mu while the
// child is registered guarantees its PID has not been reused.
func (s *supervisor) signal(id uint64, sig int, group bool) {
	if sig <= 0 || sig > 64 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	child, ok := s.byID[id]
	if !ok {
		return
	}
	if group && child.group {
		_ = unix.Kill(-child.pid, unix.Signal(sig))
	}
	_ = unix.Kill(child.pid, unix.Signal(sig))
}

// reap collects every exited child, including orphans re-parented to PID 1.
func (s *supervisor) reap() {
	var exits []*message
	s.mu.Lock()
	for {
		var status unix.WaitStatus
		pid, err := unix.Wait4(-1, &status, unix.WNOHANG, nil)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil || pid <= 0 {
			break
		}
		if child, ok := s.children[pid]; ok {
			delete(s.children, pid)
			delete(s.byID, child.id)
			exits = append(exits, &message{Op: opExit, ID: child.id, Status: uint32(status)})
		}
	}
	s.mu.Unlock()
	for _, exit := range exits {
		_ = s.conn.send(exit)
	}
}

// lookPath resolves a bare command name with the session's own PATH, since
// the supervisor's environment is intentionally empty.
func lookPath(file string, env []string) (string, error) {
	if strings.Contains(file, "/") {
		return file, nil
	}
	path := "/usr/local/bin:/usr/bin:/bin"
	for _, entry := range env {
		if value, ok := strings.CutPrefix(entry, "PATH="); ok {
			path = value
		}
	}
	for _, dir := range filepath.SplitList(path) {
		if dir == "" || !filepath.IsAbs(dir) {
			continue
		}
		candidate := filepath.Join(dir, file)
		if unix.Access(candidate, unix.X_OK) == nil {
			if info, err := os.Stat(candidate); err == nil && info.Mode().IsRegular() {
				return candidate, nil
			}
		}
	}
	return "", errors.New("executable file not found in $PATH")
}
