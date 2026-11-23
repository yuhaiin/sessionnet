//go:build !linux

package sessionnet

import (
	"context"
	"os"
)

// Session is unavailable on non-Linux platforms.
type Session struct{}

// Open reports that the Linux isolation backend is unavailable.
func Open(context.Context, Config) (*Session, error) { return nil, ErrUnsupported }

// Probe reports that the Linux isolation backend is unavailable.
func Probe(context.Context, Config) error    { return ErrUnsupported }
func (*Session) DupTun() (*os.File, error)   { return nil, ErrUnsupported }
func (*Session) DupDiag() (*os.File, error)  { return nil, ErrUnsupported }
func (*Session) DupNetNS() (*os.File, error) { return nil, ErrUnsupported }
func (*Session) Interface() string           { return "" }
func (*Session) SetupTimings() SetupTimings  { return SetupTimings{} }
func (*Session) PID() int                    { return 0 }
func (*Session) Mode() Mode                  { return "" }
func (*Session) Credential() Credential      { return Credential{} }
func (*Session) Signal(os.Signal) error      { return ErrUnsupported }
func (*Session) Release() error              { return ErrUnsupported }
func (*Session) Done() <-chan struct{}       { return nil }
func (*Session) Wait() error                 { return ErrUnsupported }
func (*Session) Close() error                { return nil }
