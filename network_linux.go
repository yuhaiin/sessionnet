//go:build linux

package sessionnet

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"unsafe"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const (
	tunSetIFF = 0x400454ca
	iffTUN    = 0x0001
	iffNoPI   = 0x1000
	// DefaultInterface is the TUN name inside every session. Each session
	// has its own network namespace, so the name cannot collide.
	DefaultInterface = "sessionnet0"
)

// The helper is itself a member of the session network namespace, so its
// netlink sockets are created there. No setns is needed and the host is
// never touched.
func enableLoopback(h *netlink.Handle) error {
	lo, err := h.LinkByName("lo")
	if err != nil {
		return fail(StageNetwork, "cannot find the session loopback interface", err)
	}
	if err := h.LinkSetUp(lo); err != nil {
		return fail(StageNetwork, "cannot enable the session loopback interface", err)
	}
	return nil
}

func createTun(name string) (*os.File, error) {
	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		switch {
		case errors.Is(err, unix.ENOENT), errors.Is(err, unix.ENXIO), errors.Is(err, unix.ENODEV):
			return nil, fail(StageTUN, "/dev/net/tun does not exist; load the tun kernel module (modprobe tun) or expose the device to this environment", err)
		case errors.Is(err, unix.EACCES), errors.Is(err, unix.EPERM):
			return nil, fail(StageTUN, "/dev/net/tun is not accessible to the Yuhaiin user; it must be a character device with mode 0666 (the kernel default)", err)
		default:
			return nil, fail(StageTUN, "cannot open /dev/net/tun", err)
		}
	}
	// struct ifreq starts with IFNAMSIZ name bytes + uint16 flags.
	// A 40-byte buffer accommodates the Linux ifreq ABI on amd64/arm64.
	var ifr [40]byte
	copy(ifr[:unix.IFNAMSIZ-1], name)
	binary.NativeEndian.PutUint16(ifr[16:18], iffTUN|iffNoPI)
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(tunSetIFF), uintptr(unsafe.Pointer(&ifr[0]))); errno != 0 {
		_ = unix.Close(fd)
		if errno == unix.EPERM {
			return nil, fail(StageTUN, "creating a TUN device is not permitted in the session network namespace", errno)
		}
		if errno == unix.ENOTTY || errno == unix.EBADFD || errno == unix.EINVAL {
			return nil, fail(StageTUN, "/dev/net/tun is not a usable TUN device", errno)
		}
		return nil, fail(StageTUN, "cannot create the session TUN device", errno)
	}
	return os.NewFile(uintptr(fd), name), nil
}

func configureTun(h *netlink.Handle, req *initRequest) error {
	link, err := h.LinkByName(req.Interface)
	if err != nil {
		return fail(StageNetwork, "cannot find the session TUN interface", err)
	}
	if err := h.LinkSetMTU(link, req.MTU); err != nil {
		return fail(StageNetwork, fmt.Sprintf("cannot set the TUN MTU to %d", req.MTU), err)
	}
	addr, err := netlink.ParseAddr(req.SessionIPv4)
	if err != nil {
		return fail(StageNetwork, "invalid session IPv4 address", err)
	}
	if err := h.AddrAdd(link, addr); err != nil {
		return fail(StageNetwork, "cannot add the session IPv4 address", err)
	}
	if req.IPv6 {
		addr6, err := netlink.ParseAddr(req.SessionIPv6)
		if err != nil {
			return fail(StageNetwork, "invalid session IPv6 address", err)
		}
		addr6.Flags = unix.IFA_F_NODAD
		if err := h.AddrAdd(link, addr6); err != nil {
			return fail(StageNetwork, "cannot add the session IPv6 address", err)
		}
	}
	if err := h.LinkSetUp(link); err != nil {
		return fail(StageNetwork, "cannot enable the session TUN interface", err)
	}
	_, dst4, _ := net.ParseCIDR("0.0.0.0/0")
	if err := h.RouteReplace(&netlink.Route{LinkIndex: link.Attrs().Index, Dst: dst4}); err != nil {
		return fail(StageNetwork, "cannot install the session IPv4 default route", err)
	}
	if req.IPv6 {
		_, dst6, _ := net.ParseCIDR("::/0")
		if err := h.RouteReplace(&netlink.Route{LinkIndex: link.Attrs().Index, Dst: dst6}); err != nil {
			return fail(StageNetwork, "cannot install the session IPv6 default route", err)
		}
	}
	return nil
}
