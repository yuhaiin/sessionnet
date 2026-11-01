//go:build linux

package sessionnet

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// Process is a child command launched in an existing Session's network and
// mount namespaces. It owns its process group, but not the Session's TUN.
// Process groups are not a complete sandbox for daemonized grandchildren.
type Process struct {
	cmd       *exec.Cmd
	done      chan struct{}
	mu        sync.Mutex
	err       error
	closeOnce sync.Once
	stop      func() bool
}

// Spawn starts another command in the live Session's network and mount
// namespaces without creating another namespace or TUN. The caller must keep
// the original Session alive until every spawned Process has been closed.
//
// Spawn uses a locked OS thread for setns and restores both namespaces before
// the thread can be reused. CAP_SYS_ADMIN is required for joining mount
// namespaces. The child always runs as the explicitly configured non-root user.
func (s *Session) Spawn(ctx context.Context, config Config) (*Process, error) {
	if err := validate(config); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	if s.closed || !s.released {
		s.mu.Unlock()
		return nil, errors.New("sessionnet: cannot spawn in a closed or unreleased session")
	}
	pid := s.cmd.Process.Pid
	s.mu.Unlock()
	select {
	case <-s.done:
		return nil, errors.New("sessionnet: namespace owner has exited")
	default:
	}
	targetNet, err := os.Open(fmt.Sprintf("/proc/%d/ns/net", pid))
	if err != nil {
		return nil, fmt.Errorf("sessionnet: open target network namespace: %w", err)
	}
	defer targetNet.Close()
	targetMount, err := os.Open(fmt.Sprintf("/proc/%d/ns/mnt", pid))
	if err != nil {
		return nil, fmt.Errorf("sessionnet: open target mount namespace: %w", err)
	}
	defer targetMount.Close()
	originalNet, err := os.Open("/proc/self/ns/net")
	if err != nil {
		return nil, err
	}
	defer originalNet.Close()
	originalMount, err := os.Open("/proc/self/ns/mnt")
	if err != nil {
		return nil, err
	}
	defer originalMount.Close()

	command := exec.Command(config.Command[0], config.Command[1:]...)
	command.Dir, command.Env = config.Dir, config.Env
	if config.Env == nil {
		command.Env = os.Environ()
	}
	if config.PTYSlave != nil {
		command.Stdin, command.Stdout, command.Stderr = config.PTYSlave, config.PTYSlave, config.PTYSlave
	} else {
		command.Stdin, command.Stdout, command.Stderr = config.Stdin, config.Stdout, config.Stderr
	}
	command.WaitDelay = 2 * time.Second
	command.SysProcAttr = &syscall.SysProcAttr{
		Credential: &syscall.Credential{
			Uid: config.Credential.UID, Gid: config.Credential.GID,
			Groups: append([]uint32{}, config.Credential.Groups...),
		},
		Setpgid: config.PTYSlave == nil,
		Setsid:  config.PTYSlave != nil,
		Setctty: config.PTYSlave != nil,
		Ctty:    0,
	}

	type started struct{ err error }
	result := make(chan started, 1)
	go func() {
		runtime.LockOSThread()
		if err := unix.Unshare(unix.CLONE_FS); err != nil {
			runtime.UnlockOSThread()
			result <- started{fmt.Errorf("sessionnet: unshare filesystem attributes: %w", err)}
			return
		}
		enteredNet, enteredMount := false, false
		var startErr error
		if startErr = unix.Setns(int(targetNet.Fd()), unix.CLONE_NEWNET); startErr == nil {
			enteredNet = true
			if startErr = unix.Setns(int(targetMount.Fd()), unix.CLONE_NEWNS); startErr == nil {
				enteredMount = true
				if ctx.Err() != nil {
					startErr = ctx.Err()
				} else {
					startErr = command.Start()
				}
			}
		}
		var restoreErr error
		if enteredMount {
			restoreErr = errors.Join(restoreErr, unix.Setns(int(originalMount.Fd()), unix.CLONE_NEWNS))
		}
		if enteredNet {
			restoreErr = errors.Join(restoreErr, unix.Setns(int(originalNet.Fd()), unix.CLONE_NEWNET))
		}
		if restoreErr != nil {
			if command.Process != nil {
				_ = command.Process.Kill()
				_ = command.Wait()
			}
			result <- started{errors.Join(startErr, fmt.Errorf("sessionnet: restore host namespaces: %w", restoreErr))}
			// The thread might still be in a foreign namespace; discard it.
			runtime.Goexit()
		}
		runtime.UnlockOSThread()
		result <- started{startErr}
	}()
	if res := <-result; res.err != nil {
		return nil, fmt.Errorf("sessionnet: spawn in existing namespace: %w", res.err)
	}
	p := &Process{cmd: command, done: make(chan struct{})}
	go func() {
		err := command.Wait()
		p.mu.Lock()
		p.err = err
		p.mu.Unlock()
		close(p.done)
	}()
	p.mu.Lock()
	p.stop = context.AfterFunc(ctx, func() { _ = p.Close() })
	p.mu.Unlock()
	return p, nil
}

// PID returns the child command's process ID.
func (p *Process) PID() int { return p.cmd.Process.Pid }

// Done closes when the child command exits.
func (p *Process) Done() <-chan struct{} { return p.done }

// Wait reports the command's exit status, including nonzero exit codes.
func (p *Process) Wait() error {
	<-p.done
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.err
}

// Close kills the command process group without closing the shared TUN.
func (p *Process) Close() error {
	p.closeOnce.Do(func() {
		select {
		case <-p.done:
		default:
			_ = syscall.Kill(-p.cmd.Process.Pid, syscall.SIGKILL)
			_ = p.cmd.Process.Kill()
		}
		<-p.done
		p.mu.Lock()
		stop := p.stop
		p.mu.Unlock()
		if stop != nil {
			stop()
		}
	})
	return nil
}
