//go:build linux

package sessionnet

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

// configureNetwork uses namespace-bound netlink sockets. It never changes the
// calling goroutine's network namespace or the host's routing table.
func configureNetwork(ctx context.Context, pid int, name string, mtu int, ipv6 bool, addresses AddressConfig) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	ns, err := netns.GetFromPid(pid)
	if err != nil {
		return fmt.Errorf("open child network namespace: %w", err)
	}
	defer ns.Close()

	host, err := netlink.NewHandle(syscall.NETLINK_ROUTE)
	if err != nil {
		return fmt.Errorf("open host netlink handle: %w", err)
	}
	defer host.Close()
	link, err := host.LinkByName(name)
	if err != nil {
		return fmt.Errorf("find TUN %q: %w", name, err)
	}
	if err := host.LinkSetNsFd(link, int(ns)); err != nil {
		return fmt.Errorf("move TUN into child namespace: %w", err)
	}

	h, err := netlink.NewHandleAt(ns, syscall.NETLINK_ROUTE)
	if err != nil {
		return fmt.Errorf("open child netlink handle: %w", err)
	}
	defer h.Close()
	lo, err := h.LinkByName("lo")
	if err != nil {
		return fmt.Errorf("find loopback: %w", err)
	}
	if err := h.LinkSetUp(lo); err != nil {
		return fmt.Errorf("enable loopback: %w", err)
	}
	link, err = h.LinkByName(name)
	if err != nil {
		return fmt.Errorf("find moved TUN: %w", err)
	}
	if err := h.LinkSetMTU(link, mtu); err != nil {
		return fmt.Errorf("set TUN MTU: %w", err)
	}
	addr, err := netlink.ParseAddr(addresses.SessionIPv4.String())
	if err != nil {
		return err
	}
	if err := h.AddrAdd(link, addr); err != nil {
		return fmt.Errorf("add IPv4 address: %w", err)
	}
	if ipv6 {
		addr6, err := netlink.ParseAddr(addresses.SessionIPv6.String())
		if err != nil {
			return err
		}
		addr6.Flags = unix.IFA_F_NODAD
		if err := h.AddrAdd(link, addr6); err != nil {
			return fmt.Errorf("add IPv6 address: %w", err)
		}
	}
	if err := h.LinkSetUp(link); err != nil {
		return fmt.Errorf("enable TUN: %w", err)
	}
	_, dst4, _ := net.ParseCIDR("0.0.0.0/0")
	if err := h.RouteReplace(&netlink.Route{LinkIndex: link.Attrs().Index, Dst: dst4}); err != nil {
		return fmt.Errorf("install IPv4 default route: %w", err)
	}
	if ipv6 {
		_, dst6, _ := net.ParseCIDR("::/0")
		if err := h.RouteReplace(&netlink.Route{LinkIndex: link.Attrs().Index, Dst: dst6}); err != nil {
			return fmt.Errorf("install IPv6 default route: %w", err)
		}
	}
	return ctx.Err()
}

// configureResolver mounts a dedicated resolver into the child's private
// mount namespace without changing the host's /etc/resolv.conf.
func configureResolver(pid int, gateway string, isolateDNS bool) error {
	dir, err := os.MkdirTemp("", "sessionnet-resolv-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "resolv.conf")
	if err := os.WriteFile(path, []byte("nameserver "+gateway+"\noptions timeout:2 attempts:2\n"), 0644); err != nil {
		return err
	}
	if isolateDNS {
		original, err := os.ReadFile("/etc/nsswitch.conf")
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if err := os.WriteFile(filepath.Join(dir, "nsswitch.conf"), []byte(isolatedNSS(string(original))), 0644); err != nil {
			return err
		}
	}
	return mountResolverInNamespace(pid, path, isolateDNS)
}

func isolatedNSS(original string) string {
	var result strings.Builder
	for _, line := range strings.Split(original, "\n") {
		key, _, found := strings.Cut(line, ":")
		if found && strings.TrimSpace(key) == "hosts" {
			continue
		}
		if line != "" {
			result.WriteString(line)
			result.WriteByte('\n')
		}
	}
	result.WriteString("hosts: files dns\n")
	return result.String()
}

// mountResolverInNamespace isolates CLONE_FS on a single locked OS thread
// before setns(CLONE_NEWNS). A dedicated goroutine is used so a failed restore
// can terminate the contaminated OS thread without returning it to the pool.
// Do not add Go work to this thread after a failed restoration.
func mountResolverInNamespace(pid int, source string, isolateDNS bool) error {
	target, err := os.Open(fmt.Sprintf("/proc/%d/ns/mnt", pid))
	if err != nil {
		return err
	}
	defer target.Close()
	original, err := os.Open("/proc/self/ns/mnt")
	if err != nil {
		return err
	}
	defer original.Close()

	result := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		if err := unix.Unshare(unix.CLONE_FS); err != nil {
			runtime.UnlockOSThread()
			result <- fmt.Errorf("unshare filesystem attributes: %w", err)
			return
		}
		if err := unix.Setns(int(target.Fd()), unix.CLONE_NEWNS); err != nil {
			runtime.UnlockOSThread()
			result <- fmt.Errorf("enter child mount namespace: %w", err)
			return
		}

		mountErr := unix.Mount("", "/", "", unix.MS_PRIVATE|unix.MS_REC, "")
		if mountErr == nil {
			mountErr = unix.Mount(source, "/etc/resolv.conf", "", unix.MS_BIND, "")
		}
		if mountErr == nil && isolateDNS {
			mountErr = unix.Mount(filepath.Join(filepath.Dir(source), "nsswitch.conf"), "/etc/nsswitch.conf", "", unix.MS_BIND, "")
			// glibc can consult nscd before invoking any hosts NSS module.
			// Mask only its runtime directory in this private mount namespace.
			seen := make(map[string]bool)
			for _, path := range []string{"/run/nscd", "/var/run/nscd"} {
				if mountErr != nil {
					break
				}
				target, err := filepath.EvalSymlinks(path)
				if errors.Is(err, os.ErrNotExist) {
					continue
				}
				if err != nil {
					mountErr = err
					break
				}
				if !seen[target] {
					seen[target] = true
					mountErr = unix.Mount("tmpfs", target, "tmpfs", unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC, "size=4096,mode=0755")
				}
			}
		}
		restoreErr := unix.Setns(int(original.Fd()), unix.CLONE_NEWNS)
		if restoreErr != nil {
			result <- errors.Join(mountErr, fmt.Errorf("restore host mount namespace: %w", restoreErr))
			// Goexit terminates the permanently locked OS thread.
			runtime.Goexit()
		}
		runtime.UnlockOSThread()
		if mountErr != nil {
			mountErr = fmt.Errorf("bind-mount isolated resolver: %w", mountErr)
		}
		result <- mountErr
	}()
	return <-result
}
