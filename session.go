// Package sessionnet provides isolated process networking sessions.
// The Linux backend configures private network and mount namespaces with a
// TUN device. The integrating application owns packet processing and policy.
// It is not a general-purpose filesystem or privilege sandbox.
package sessionnet

import (
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
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
	PTYSlave  *os.File
	MTU       int
	IPv6      bool
	Addresses AddressConfig
	// Cgroup places this session and all commands spawned from it in a
	// managed cgroup v2. When unset, process-group cleanup is best-effort.
	Cgroup *CgroupManager
}
