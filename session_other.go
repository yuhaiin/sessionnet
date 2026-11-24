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

// Identity reports that the Linux isolation backend is unavailable.
func (*Session) Identity() (SessionIdentity, error)   { return SessionIdentity{}, ErrUnsupported }
func (*Session) UIDToCaller(id uint32) (uint32, bool) { return id, false }

// CurrentUserNamespace reports that user namespaces are Linux-only.
func CurrentUserNamespace() (UserNamespace, error) { return UserNamespace{}, ErrUnsupported }

// DefaultCredential reports that the Linux isolation backend is unavailable.
func DefaultCredential() (Credential, error) { return Credential{}, ErrUnsupported }

// Inspect reports that the Linux isolation backend is unavailable.
func Inspect(_ context.Context, cfg Config) Report {
	return Report{Mode: cfg.Mode, Error: &SetupError{Stage: StageHelper, Message: "isolated sessions require Linux", Err: ErrUnsupported}}
}
