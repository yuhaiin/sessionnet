package sessionnet

import (
	"fmt"
	"net/netip"
)

// LoopbackForward reserves a loopback endpoint inside the session network
// namespace for the caller: the session helper binds a socket at exactly that
// address (a listening TCP socket or a bound UDP socket) and hands it over
// with the session (Session.LoopbackSockets). A session process connecting
// to 127.0.0.1:5432 therefore reaches the caller, which runs in its own
// network namespace and can serve the connection, for example by relaying it
// to its own loopback. The process sees an ordinary connection to the address
// it used, replies come from that address, and nothing is translated: no NAT
// rule, route or sysctl is installed anywhere.
//
// Why not NAT: redirecting loopback traffic through the TUN with DNAT works
// for IPv4 only with route_localnet, and cannot work for IPv6, because the
// kernel drops replies whose destination becomes ::1 after the reverse
// translation on a non-loopback device (Ip6InAddrErrors). Sockets in the
// namespace serve both families identically.
//
// The endpoint is unavailable to session processes, which get EADDRINUSE if
// they bind it themselves. Unforwarded ports stay ordinary session loopback.
type LoopbackForward struct {
	// Network is "tcp" or "udp".
	Network string
	// Address is 127.0.0.1:port or [::1]:port. IPv4 and IPv6 are
	// independent: a process connecting to the other family's loopback is
	// not forwarded.
	Address netip.AddrPort
}

func (f LoopbackForward) String() string { return fmt.Sprintf("%s %s", f.Network, f.Address) }

// MaxLoopbackForwards bounds the forwards of one session.
const MaxLoopbackForwards = 64

// validateLoopbackForwards rejects anything but explicit loopback endpoints
// and duplicates.
func validateLoopbackForwards(forwards []LoopbackForward) error {
	if len(forwards) > MaxLoopbackForwards {
		return fmt.Errorf("sessionnet: %d loopback forwards; at most %d are supported", len(forwards), MaxLoopbackForwards)
	}
	seen := make(map[LoopbackForward]bool, len(forwards))
	for _, f := range forwards {
		if f.Network != "tcp" && f.Network != "udp" {
			return fmt.Errorf("sessionnet: loopback forward network %q must be tcp or udp", f.Network)
		}
		addr := f.Address.Addr()
		if addr != netip.AddrFrom4([4]byte{127, 0, 0, 1}) && addr != netip.IPv6Loopback() {
			return fmt.Errorf("sessionnet: loopback forward address %s must be 127.0.0.1 or ::1", f.Address)
		}
		if f.Address.Port() == 0 {
			return fmt.Errorf("sessionnet: loopback forward %s needs a port", f)
		}
		if seen[f] {
			return fmt.Errorf("sessionnet: duplicate loopback forward %s", f)
		}
		seen[f] = true
	}
	return nil
}
