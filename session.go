// Package sessionnet provides isolated process networking sessions.
//
// On Linux every session is owned by a helper process that the integrating
// binary re-executes from HelperPath (/proc/self/exe by default). The helper
// is cloned into private network, mount and PID namespaces, and in the
// default rootless mode into a user namespace as well, so no host privilege
// is required. It creates the TUN inside its own network namespace, passes
// the packet descriptor to the caller over SCM_RIGHTS, drops every
// capability and then supervises the session's processes as PID 1.
//
// The package dispatches the helper from an init function, so any binary
// that imports it can act as its own helper; no change to main is needed.
//
// The integrating application owns packet processing and policy. This is
// network isolation, not a general-purpose filesystem or privilege sandbox.
package sessionnet

import (
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"time"
)

const (
	// Each session uses these addresses in its own network namespace.
	GatewayIPv4 = "172.31.254.1"
	SessionIPv4 = "172.31.254.2/30"
	GatewayIPv6 = "fd42:7d2a:9b31::1"
	SessionIPv6 = "fd42:7d2a:9b31::2/64"
	DefaultMTU  = 1500
)

// AddressConfig selects the addresses of the isolated network link.
// Zero values use the defaults. IPv4 and IPv6 can be customized separately.
// Address prefixes must contain the gateway and have distinct endpoint IPs.
type AddressConfig struct {
	GatewayIPv4 netip.Addr
	SessionIPv4 netip.Prefix
	GatewayIPv6 netip.Addr
	SessionIPv6 netip.Prefix
}

// DefaultAddresses avoids common FakeIP ranges and Tailscale's ULA prefix.
// Integrators still need to reject overlaps with their active address pools.
func DefaultAddresses() AddressConfig {
	return AddressConfig{
		GatewayIPv4: netip.MustParseAddr(GatewayIPv4),
		SessionIPv4: netip.MustParsePrefix(SessionIPv4),
		GatewayIPv6: netip.MustParseAddr(GatewayIPv6),
		SessionIPv6: netip.MustParsePrefix(SessionIPv6),
	}
}

// Resolve fills unset families and verifies that both endpoints are on the
// configured link. It never consults or modifies the host routing table.
func (a AddressConfig) Resolve(ipv6 bool) (AddressConfig, error) {
	defaults := DefaultAddresses()
	if !a.GatewayIPv4.IsValid() && !a.SessionIPv4.IsValid() {
		a.GatewayIPv4, a.SessionIPv4 = defaults.GatewayIPv4, defaults.SessionIPv4
	}
	if err := validateLink(a.GatewayIPv4, a.SessionIPv4, false); err != nil {
		return AddressConfig{}, fmt.Errorf("sessionnet: invalid IPv4 link: %w", err)
	}
	if ipv6 {
		if !a.GatewayIPv6.IsValid() && !a.SessionIPv6.IsValid() {
			a.GatewayIPv6, a.SessionIPv6 = defaults.GatewayIPv6, defaults.SessionIPv6
		}
		if err := validateLink(a.GatewayIPv6, a.SessionIPv6, true); err != nil {
			return AddressConfig{}, fmt.Errorf("sessionnet: invalid IPv6 link: %w", err)
		}
	} else if a.GatewayIPv6.IsValid() || a.SessionIPv6.IsValid() {
		return AddressConfig{}, fmt.Errorf("sessionnet: IPv6 addresses require IPv6 to be enabled")
	}
	return a, nil
}

func validateLink(gateway netip.Addr, session netip.Prefix, ipv6 bool) error {
	if !gateway.IsValid() || !session.IsValid() ||
		gateway.Is6() != ipv6 || session.Addr().Is6() != ipv6 ||
		gateway.Is4In6() || session.Addr().Is4In6() {
		return fmt.Errorf("invalid address family")
	}
	if gateway.IsUnspecified() || gateway.IsMulticast() || gateway.IsLoopback() ||
		session.Addr().IsUnspecified() || session.Addr().IsMulticast() ||
		session.Addr().IsLoopback() || gateway == session.Addr() {
		return fmt.Errorf("invalid or duplicate interface endpoints")
	}
	if (ipv6 && session.Bits() != 64) || (!ipv6 && session.Bits() != 30) {
		return fmt.Errorf("expected /64 IPv6 or /30 IPv4 link")
	}
	if !session.Contains(gateway) {
		return fmt.Errorf("gateway must be in the session subnet")
	}
	if !ipv6 {
		network := session.Masked().Addr()
		if gateway == network || session.Addr() == network ||
			gateway == network.Next().Next().Next() ||
			session.Addr() == network.Next().Next().Next() {
			return fmt.Errorf("IPv4 endpoints must not be network or broadcast addresses")
		}
	}
	return nil
}

var ErrUnsupported = errors.New("sessionnet: platform is not supported")

// Mode selects how the session namespaces are created.
type Mode string

const (
	// ModeRootless creates a user namespace first, so no host capability is
	// required. It is the default. The TUN, routes, resolver and process
	// supervisor all live inside namespaces owned by that user namespace.
	ModeRootless Mode = "rootless"
	// ModeRootful creates network, mount and PID namespaces in the caller's
	// user namespace. The caller needs CAP_SYS_ADMIN and CAP_NET_ADMIN there.
	ModeRootful Mode = "rootful"
)

// Resolve returns ModeRootless for the zero value and rejects unknown modes.
func (m Mode) Resolve() (Mode, error) {
	switch m {
	case "", ModeRootless:
		return ModeRootless, nil
	case ModeRootful:
		return ModeRootful, nil
	default:
		return "", fmt.Errorf("sessionnet: unknown namespace mode %q", string(m))
	}
}

// Credential names the Unix identity of session processes by host IDs: IDs
// of the initial user namespace, also when the caller runs inside a user
// namespace (see README "Credentials"). When the caller's namespace cannot
// be resolved to the host, they are IDs of the caller's namespace and only
// the caller's own identity is accepted. Unmappable IDs are rejected.
//
// A rootless session with the caller's own identity and no Groups keeps the
// caller's supplementary groups. Otherwise, in rootful mode and in rootless
// mode when the caller may call setgroups(2) for the session (CAP_SETGID in
// a namespace that allows it, or newgidmap), supplementary groups are
// replaced with Groups; if not, Groups must be empty and the caller's groups
// are inherited.
type Credential struct {
	UID    uint32
	GID    uint32
	Groups []uint32
	// ParentUID and ParentGID optionally name, for rootless sessions, the IDs
	// of the caller's own user namespace (the session's immediate parent)
	// that UID and GID map to, instead of the automatic translation. They
	// are IDs of that namespace, never host IDs: under `podman unshare`
	// session UID 1009 has parent UID 0. Use them only when the automatic
	// translation cannot resolve the caller's namespace (it is nested more
	// than one level deep); where it can, an override must agree with it.
	// The kernel still decides whether the caller may map the ID, and the
	// session verifies the result from inside.
	ParentUID *uint32
	ParentGID *uint32
}

// Config describes an isolated session. Its network namespace has no host
// uplink. Callers must provide a working packet handler before Release.
//
// This does not restrict filesystem access, filesystem Unix sockets or
// inherited file descriptors. Do not expose a shell to untrusted users
// without an additional filesystem sandbox.
type Config struct {
	// Mode defaults to ModeRootless.
	Mode Mode
	// Command optionally names the session's initial command. It is started
	// by Release. Without a command, the session is an idle namespace that
	// Spawn can use; Done and Wait then track the session supervisor.
	Command []string
	Env     []string
	Dir     string
	// Credential is required in rootful mode. In rootless mode a nil
	// credential selects the caller's effective UID and GID.
	Credential *Credential
	Stdin      io.Reader
	Stdout     io.Writer
	Stderr     io.Writer
	// PTYSlave, when non-nil, becomes the controlling terminal. Ownership
	// stays with the caller, which is responsible for PTY allocation.
	PTYSlave  *os.File
	MTU       int
	IPv6      bool
	Addresses AddressConfig
	// IsolateDNS forces libc hostname lookups through the session resolver.
	// It replaces only the hosts entry in a private nsswitch.conf and masks
	// known host nscd socket directories. Other NSS databases are preserved.
	IsolateDNS bool
	// Cgroup places this session and all commands spawned from it in a
	// managed cgroup v2. Without it, the PID namespace supervisor still kills
	// every descendant when the session closes; the cgroup additionally lets
	// a restarted supervisor reap sessions orphaned by a crash.
	Cgroup *CgroupManager
	// HelperPath is the executable re-executed as the session helper. It
	// defaults to /proc/self/exe; see the package documentation.
	HelperPath string
}

// SetupTimings breaks down how long Open took.
type SetupTimings struct {
	// Spawn covers clone(2) of the namespaces and the helper's execve.
	Spawn time.Duration
	// IDMap covers writing the user namespace UID/GID maps (rootless).
	IDMap time.Duration
	// Handshake runs from sending the init request to receiving the TUN
	// descriptor; it includes the helper's runtime start and the phases below.
	Handshake   time.Duration
	Credentials time.Duration
	Mounts      time.Duration
	TUN         time.Duration
	Network     time.Duration
	Diagnostics time.Duration
	// Supervisor covers dropping privileges and starting the supervisor.
	Supervisor time.Duration
	Total      time.Duration
}

// Stage identifies the part of session setup that failed.
type Stage string

const (
	StageUserNamespace Stage = "user-namespace"
	StageNamespaces    Stage = "namespaces"
	StagePIDNamespace  Stage = "pid-namespace"
	StageUIDMap        Stage = "uid-map"
	StageGIDMap        Stage = "gid-map"
	StageCredentials   Stage = "credentials"
	StageMount         Stage = "mount"
	StageResolver      Stage = "resolver"
	StageTUN           Stage = "tun"
	StageNetwork       Stage = "network"
	StageDiagnostics   Stage = "diagnostics"
	StagePrivileges    Stage = "privileges"
	StageCgroup        Stage = "cgroup"
	StageHelper        Stage = "helper"
	StageHandshake     Stage = "handshake"
)

// SetupError reports why a session could not be created. Message is a
// complete, user-facing explanation including the likely remedy; Err holds
// the underlying system error for logs and errors.Is.
type SetupError struct {
	Stage   Stage
	Message string
	Err     error
}

func (e *SetupError) Error() string {
	if e.Err == nil {
		return "sessionnet: " + e.Message
	}
	return "sessionnet: " + e.Message + ": " + e.Err.Error()
}

func (e *SetupError) Unwrap() error { return e.Err }

// ExitError reports that a session command did not exit successfully.
type ExitError struct {
	// Status is the raw wait(2) status.
	Status uint32
}

// Exited reports whether the command terminated normally.
func (e *ExitError) Exited() bool { return e.Status&0x7f == 0 }

// Signal returns the terminating signal number, or 0 if the command exited.
func (e *ExitError) Signal() int {
	if e.Exited() {
		return 0
	}
	return int(e.Status & 0x7f)
}

// ExitCode returns the exit code, or -1 if the command was killed by a signal.
func (e *ExitError) ExitCode() int {
	if !e.Exited() {
		return -1
	}
	return int(e.Status>>8) & 0xff
}

func (e *ExitError) Error() string {
	if e.Exited() {
		return fmt.Sprintf("exit status %d", e.ExitCode())
	}
	return fmt.Sprintf("signal %d", e.Signal())
}
