// Package sessionnet provides isolated process networking sessions.
// The Linux backend configures private network and mount namespaces with a
// TUN device. The integrating application owns packet processing and policy.
// It is not a general-purpose filesystem or privilege sandbox.
package sessionnet

import (
	"errors"
	"io"
	"os"
)

const (
	// Each session uses these addresses in its own network namespace.
	GatewayIPv4 = "198.18.0.1"
	SessionIPv4 = "198.18.0.2/30"
	GatewayIPv6 = "fd7a:115c:a1e0::1"
	SessionIPv6 = "fd7a:115c:a1e0::2/64"
	DefaultMTU  = 1500
)

var ErrUnsupported = errors.New("sessionnet: platform is not supported")

// Credential names a non-root Unix user. Supplementary groups are explicitly
// replaced with Groups, including when it is empty.
type Credential struct {
	UID    uint32
	GID    uint32
	Groups []uint32
}

// Config describes an isolated command. Its network namespace has no host
// uplink. Callers must provide a working packet handler before Release.
//
// This does not restrict filesystem access, Unix sockets, inherited file
// descriptors or setuid executables. Do not expose a shell to untrusted users
// without an additional sandbox and a narrowly scoped privileged helper.
type Config struct {
	Command    []string
	Env        []string
	Dir        string
	Credential *Credential
	Stdin      io.Reader
	Stdout     io.Writer
	Stderr     io.Writer
	// PTYSlave, when non-nil, becomes the controlling terminal. Ownership
	// stays with the caller, which is responsible for PTY allocation.
	PTYSlave *os.File
	MTU      int
	IPv6     bool
}
