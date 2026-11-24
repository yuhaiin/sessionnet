//go:build linux

package sessionnet

import (
	"fmt"
	"net/netip"
	"os"

	"golang.org/x/sys/unix"
)

// LoopbackSocket is a socket the session helper bound inside the session
// network namespace for one LoopbackForward: a listening TCP socket or a
// bound UDP socket. The caller owns the File and must close it.
type LoopbackSocket struct {
	Forward LoopbackForward
	File    *os.File
}

// createLoopbackSockets runs in the session helper after loopback is up. The
// sockets are created in the session network namespace and keep belonging to
// it wherever the descriptor goes, so the caller can accept and read on them
// without ever joining the namespace. They are close-on-exec and never
// reach session processes.
func createLoopbackSockets(req *initRequest) ([]*os.File, error) {
	forwards, err := req.loopbackForwards()
	if err != nil {
		return nil, fail(StageLoopbackForward, "invalid loopback forward", err)
	}
	files := make([]*os.File, 0, len(forwards))
	for _, f := range forwards {
		file, err := bindLoopbackSocket(f)
		if err != nil {
			closeFiles(files)
			return nil, err
		}
		files = append(files, file)
	}
	return files, nil
}

func bindLoopbackSocket(f LoopbackForward) (*os.File, error) {
	var domain int
	var sa unix.Sockaddr
	if f.Address.Addr().Is4() {
		domain, sa = unix.AF_INET, &unix.SockaddrInet4{Port: int(f.Address.Port()), Addr: f.Address.Addr().As4()}
	} else {
		domain, sa = unix.AF_INET6, &unix.SockaddrInet6{Port: int(f.Address.Port()), Addr: f.Address.Addr().As16()}
	}
	kind := unix.SOCK_STREAM
	if f.Network == "udp" {
		kind = unix.SOCK_DGRAM
	}
	fd, err := unix.Socket(domain, kind|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, 0)
	if err != nil {
		return nil, fail(StageLoopbackForward, fmt.Sprintf("cannot create the socket for loopback forward %s", f), err)
	}
	if domain == unix.AF_INET6 {
		// Only ::1, never IPv4-mapped traffic.
		if err := unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_V6ONLY, 1); err != nil {
			_ = unix.Close(fd)
			return nil, fail(StageLoopbackForward, fmt.Sprintf("cannot configure loopback forward %s", f), err)
		}
	}
	if kind == unix.SOCK_STREAM {
		_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_REUSEADDR, 1)
	}
	if err := unix.Bind(fd, sa); err != nil {
		_ = unix.Close(fd)
		message := fmt.Sprintf("cannot bind loopback forward %s in the session network namespace", f)
		if f.Address.Addr().Is6() && (err == unix.EADDRNOTAVAIL || err == unix.EAFNOSUPPORT) {
			message = fmt.Sprintf("Loopback forward %s needs IPv6 on the session loopback, which is unavailable (IPv6 disabled in the kernel)", f)
		}
		return nil, fail(StageLoopbackForward, message, err)
	}
	if kind == unix.SOCK_STREAM {
		if err := unix.Listen(fd, unix.SOMAXCONN); err != nil {
			_ = unix.Close(fd)
			return nil, fail(StageLoopbackForward, fmt.Sprintf("cannot listen on loopback forward %s", f), err)
		}
	}
	return os.NewFile(uintptr(fd), "loopback-"+f.Network+"-"+f.Address.String()), nil
}

// loopbackForwards decodes and revalidates the forwards of an init request;
// the helper never trusts the wire format.
func (req *initRequest) loopbackForwards() ([]LoopbackForward, error) {
	forwards := make([]LoopbackForward, 0, len(req.LoopbackForwards))
	for _, w := range req.LoopbackForwards {
		addr, err := netip.ParseAddrPort(w.Address)
		if err != nil {
			return nil, err
		}
		forwards = append(forwards, LoopbackForward{Network: w.Network, Address: addr})
	}
	if err := validateLoopbackForwards(forwards); err != nil {
		return nil, err
	}
	return forwards, nil
}

func wireLoopbackForwards(forwards []LoopbackForward) []wireLoopbackForward {
	out := make([]wireLoopbackForward, len(forwards))
	for i, f := range forwards {
		out[i] = wireLoopbackForward{Network: f.Network, Address: f.Address.String()}
	}
	return out
}

// LoopbackSockets returns independently owned duplicates of the sockets of
// Config.LoopbackForwards, in configuration order. The caller must close
// them; closing the Session closes the originals.
func (s *Session) LoopbackSockets() ([]LoopbackSocket, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, os.ErrClosed
	}
	out := make([]LoopbackSocket, 0, len(s.loopback))
	for _, sock := range s.loopback {
		fd, err := unix.FcntlInt(sock.File.Fd(), unix.F_DUPFD_CLOEXEC, 0)
		if err != nil {
			for _, o := range out {
				_ = o.File.Close()
			}
			return nil, err
		}
		out = append(out, LoopbackSocket{Forward: sock.Forward, File: os.NewFile(uintptr(fd), sock.File.Name())})
	}
	return out, nil
}
