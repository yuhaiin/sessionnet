//go:build linux

package sessionnet

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"syscall"
	"time"
)

// waitDelay bounds how long Wait keeps copying output after the command has
// exited, for example when a background job inherited stdout.
const waitDelay = 2 * time.Second

// Process is a command started by the session supervisor. It runs in the
// session's namespaces as the session credential. Closing it kills its
// process group; processes that left the group are killed when the Session
// closes, together with the whole PID namespace.
type Process struct {
	session *Session
	id      uint64

	started  chan struct{}
	pid      int
	startErr error

	exited  chan struct{}
	done    chan struct{}
	err     error
	once    sync.Once
	startMu sync.Once

	copies      sync.WaitGroup
	readers     []*os.File
	outputs     []pendingCopy
	stdin       *os.File
	stdinSource io.Reader
	closeOnce   sync.Once
	stop        func() bool
	mu          sync.Mutex
}

// Spawn starts another command in the live Session's namespaces, sharing
// its TUN, resolver and PID namespace. Credential, if set, must equal the
// session credential: the supervisor holds no privilege to change IDs.
func (s *Session) Spawn(ctx context.Context, config Config) (*Process, error) {
	if len(config.Command) == 0 {
		return nil, errors.New("sessionnet: command is required")
	}
	if config.Credential != nil {
		c := config.Credential
		if c.UID != s.cred.UID || c.GID != s.cred.GID || (c.Groups != nil && !sameIDs(c.Groups, s.cred.Groups)) {
			return nil, errors.New("sessionnet: spawned commands must use the session credential")
		}
	}
	if config.PTYSlave != nil && (config.Stdin != nil || config.Stdout != nil || config.Stderr != nil) {
		return nil, errors.New("sessionnet: PTYSlave conflicts with stdio")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	if s.closed || !s.released {
		s.mu.Unlock()
		return nil, errors.New("sessionnet: cannot spawn in a closed or unreleased session")
	}
	s.mu.Unlock()
	return s.spawn(ctx, config, true)
}

func sameIDs(a, b []uint32) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func (s *Session) spawn(ctx context.Context, config Config, cancelProcess bool) (_ *Process, err error) {
	select {
	case <-s.helperDone:
		return nil, ErrSupervisorExited
	default:
	}
	env := config.Env
	if env == nil {
		env = os.Environ()
	}
	p := &Process{session: s, started: make(chan struct{}), exited: make(chan struct{}), done: make(chan struct{})}
	var childFiles []*os.File
	var closeAfterStart []*os.File
	defer func() {
		closeFiles(closeAfterStart)
		if err != nil {
			for range p.outputs {
				p.copies.Done()
			}
			closeFiles(p.readers)
			if p.stdin != nil {
				_ = p.stdin.Close()
			}
		}
	}()
	if config.PTYSlave != nil {
		childFiles = []*os.File{config.PTYSlave, config.PTYSlave, config.PTYSlave}
	} else {
		var nullFile *os.File
		devNull := func() (*os.File, error) {
			if nullFile == nil {
				f, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
				if err != nil {
					return nil, err
				}
				nullFile = f
				closeAfterStart = append(closeAfterStart, f)
			}
			return nullFile, nil
		}
		stdin, err := p.stdinFile(config.Stdin, devNull, &closeAfterStart)
		if err != nil {
			return nil, err
		}
		stdout, err := p.outputFile(config.Stdout, devNull, &closeAfterStart)
		if err != nil {
			return nil, err
		}
		stderr := stdout
		if !sameWriter(config.Stdout, config.Stderr) {
			if stderr, err = p.outputFile(config.Stderr, devNull, &closeAfterStart); err != nil {
				return nil, err
			}
		}
		childFiles = []*os.File{stdin, stdout, stderr}
	}

	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil, os.ErrClosed
	}
	s.nextID++
	p.id = p.session.nextID
	s.procs[p.id] = p
	s.mu.Unlock()
	request := &message{Op: opSpawn, ID: p.id, Spawn: &spawnRequest{
		Argv: config.Command, Env: env, Dir: config.Dir,
		TTY: config.PTYSlave != nil, Setpgid: config.PTYSlave == nil,
	}}
	if err := s.ctl.send(request, childFiles...); err != nil {
		s.forget(p.id)
		return nil, fmt.Errorf("sessionnet: send spawn request: %w", err)
	}
	// The child holds its own copies now; ours must not keep pipes open.
	closeFiles(closeAfterStart)
	closeAfterStart = nil
	<-p.started
	if p.startErr != nil {
		return nil, fmt.Errorf("sessionnet: spawn in session: %w", p.startErr)
	}
	p.startCopies()
	if cancelProcess {
		p.mu.Lock()
		p.stop = context.AfterFunc(ctx, func() { _ = p.Close() })
		p.mu.Unlock()
	}
	return p, nil
}

func (s *Session) forget(id uint64) {
	s.mu.Lock()
	delete(s.procs, id)
	s.mu.Unlock()
}

func sameWriter(a, b io.Writer) bool {
	if a == nil || b == nil {
		return false
	}
	defer func() { _ = recover() }() // uncomparable dynamic types
	return a == b
}

type pendingCopy struct {
	reader io.Reader
	writer io.Writer
}

// stdinFile and outputFile prepare the child's stdio. Non-file streams use
// pipes whose copying starts only after the command has started.
func (p *Process) stdinFile(r io.Reader, devNull func() (*os.File, error), closeAfterStart *[]*os.File) (*os.File, error) {
	if r == nil {
		return devNull()
	}
	if f, ok := r.(*os.File); ok {
		return f, nil
	}
	pr, pw, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	*closeAfterStart = append(*closeAfterStart, pr)
	p.stdin, p.stdinSource = pw, r
	return pr, nil
}

func (p *Process) outputFile(w io.Writer, devNull func() (*os.File, error), closeAfterStart *[]*os.File) (*os.File, error) {
	if w == nil {
		return devNull()
	}
	if f, ok := w.(*os.File); ok {
		return f, nil
	}
	pr, pw, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	*closeAfterStart = append(*closeAfterStart, pw)
	p.readers = append(p.readers, pr)
	p.outputs = append(p.outputs, pendingCopy{reader: pr, writer: w})
	// Count the copy before the command can exit: finish waits for it.
	p.copies.Add(1)
	return pw, nil
}

func (p *Process) startCopies() {
	if p.stdin != nil {
		go func() {
			_, _ = io.Copy(p.stdin, p.stdinSource)
			_ = p.stdin.Close()
		}()
	}
	for _, c := range p.outputs {
		go func() {
			defer p.copies.Done()
			_, _ = io.Copy(c.writer, c.reader)
		}()
	}
	p.outputs = nil
}

func (p *Process) markStarted(pid int, err error) {
	p.startMu.Do(func() {
		p.pid, p.startErr = pid, err
		close(p.started)
	})
}

// finish records the exit status, then drains output for at most waitDelay
// before closing the pipes, as os/exec does with Cmd.WaitDelay.
func (p *Process) finish(err error) {
	p.once.Do(func() {
		p.err = err
		close(p.exited)
		go func() {
			drained := make(chan struct{})
			go func() { p.copies.Wait(); close(drained) }()
			select {
			case <-drained:
			case <-time.After(waitDelay):
			}
			closeFiles(p.readers)
			<-drained
			if p.stdin != nil {
				_ = p.stdin.Close()
			}
			close(p.done)
		}()
	})
}

// PID returns the command's process ID inside the session PID namespace.
func (p *Process) PID() int { return p.pid }

// Done closes when the command has exited and its output has been copied.
func (p *Process) Done() <-chan struct{} { return p.done }

// Wait reports the command's exit status. A nonzero exit is an *ExitError.
func (p *Process) Wait() error {
	<-p.done
	return p.err
}

// Signal forwards sig to the command.
func (p *Process) Signal(sig os.Signal) error {
	number, ok := sig.(syscall.Signal)
	if !ok {
		return errors.New("sessionnet: unsupported signal")
	}
	select {
	case <-p.exited:
		return os.ErrProcessDone
	default:
	}
	return p.session.ctl.send(&message{Op: opSignal, ID: p.id, Signal: int(number)})
}

// Close kills the command and its process group without closing the
// shared session, then waits for the exit to be reported.
func (p *Process) Close() error {
	p.closeOnce.Do(func() {
		select {
		case <-p.exited:
		default:
			if err := p.session.ctl.send(&message{Op: opKill, ID: p.id}); err != nil {
				p.finish(ErrSupervisorExited)
			}
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
