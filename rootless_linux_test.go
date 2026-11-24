//go:build linux

package sessionnet

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// requireRootlessEnv makes environment limitations a failure instead of a
// skip. CI sets it so that a skip can never be mistaken for verification.
const requireRootlessEnv = "SESSIONNET_REQUIRE_ROOTLESS"

func TestMain(m *testing.M) {
	switch mode := os.Getenv("SESSIONNET_TEST_MODE"); {
	case mode == "":
	case strings.HasPrefix(mode, "scenario:"):
		os.Exit(runFailureScenario(strings.TrimPrefix(mode, "scenario:")))
	case mode == "crash-parent":
		os.Exit(runCrashParent())
	case mode == "nest-deeper":
		os.Exit(runNestDeeper())
	case mode == "manual-parent":
		os.Exit(runManualParent())
	case mode == "loopback-client":
		os.Exit(runLoopbackClient())
	case mode == "listen":
		os.Exit(runListener())
	default:
		fmt.Fprintln(os.Stderr, "unknown test mode", mode)
		os.Exit(2)
	}
	os.Exit(m.Run())
}

// requireRootless skips only when this host cannot create rootless sessions
// at all, and reports why.
func requireRootless(t testing.TB) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := Probe(ctx, Config{IPv6: true}); err != nil {
		if os.Getenv(requireRootlessEnv) == "1" {
			t.Fatalf("rootless sessions are required but unavailable: %v", err)
		}
		t.Skipf("rootless sessions are unavailable on this host: %v", err)
	}
}

func effectiveCapabilities(t testing.TB) uint64 {
	t.Helper()
	header := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	var data [2]unix.CapUserData
	if err := unix.Capget(&header, &data[0]); err != nil {
		t.Fatal(err)
	}
	return uint64(data[1].Effective)<<32 | uint64(data[0].Effective)
}

// TestRootlessCallerIsUnprivileged is the proof that the rootless tests in
// this package exercised the real feature: the test process is a normal
// user in the initial user namespace without any effective capability.
func TestRootlessCallerIsUnprivileged(t *testing.T) {
	self, err := os.Readlink("/proc/self/ns/user")
	if err != nil {
		t.Fatal(err)
	}
	init, initErr := os.Readlink("/proc/1/ns/user")
	switch {
	case os.Geteuid() == 0 || effectiveCapabilities(t) != 0:
		if os.Getenv(requireRootlessEnv) == "1" {
			t.Fatalf("rootless verification must run as a normal user: euid=%d capEff=%#x", os.Geteuid(), effectiveCapabilities(t))
		}
		t.Skip("running with privileges; this run does not prove rootless operation")
	case initErr == nil && self != init:
		t.Logf("note: test runs inside a nested user namespace %s", self)
	}
	requireRootless(t)
	t.Logf("verified: euid=%d, no effective capabilities, no sudo or file capabilities", os.Geteuid())
}

type hostNetwork struct {
	links, routes4, routes6, addresses, rules string
}

func snapshotHostNetwork(t testing.TB) hostNetwork {
	t.Helper()
	read := func(path string) string {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		return string(data)
	}
	interfaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	var links, addresses []string
	for _, iface := range interfaces {
		links = append(links, fmt.Sprintf("%d:%s:%d:%s", iface.Index, iface.Name, iface.MTU, iface.Flags))
		addrs, _ := iface.Addrs()
		for _, a := range addrs {
			addresses = append(addresses, iface.Name+"="+a.String())
		}
	}
	slices.Sort(addresses)
	rules := ""
	if out, err := exec.Command("ip", "rule", "show").Output(); err == nil {
		rules = string(out)
	}
	if out, err := exec.Command("ip", "-6", "rule", "show").Output(); err == nil {
		rules += string(out)
	}
	return hostNetwork{
		links:     strings.Join(links, "\n"),
		routes4:   read("/proc/net/route"),
		routes6:   read("/proc/net/ipv6_route"),
		addresses: strings.Join(addresses, "\n"),
		rules:     rules,
	}
}

func openRootless(t testing.TB, cfg Config) *Session {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	s, err := Open(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func runIn(t testing.TB, s *Session, script string) string {
	t.Helper()
	var out bytes.Buffer
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	p, err := s.Spawn(ctx, Config{Command: []string{"/bin/sh", "-c", script}, Stdout: &out, Stderr: &out})
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Wait(); err != nil {
		t.Fatalf("%q: %v\n%s", script, err, out.String())
	}
	return out.String()
}

func TestRootlessSessionNamespaces(t *testing.T) {
	requireRootless(t)
	before := snapshotHostNetwork(t)
	s := openRootless(t, Config{IPv6: true})
	if s.Mode() != ModeRootless {
		t.Fatalf("mode %q", s.Mode())
	}
	if err := s.Release(); err != nil {
		t.Fatal(err)
	}
	hostNS := map[string]string{}
	for _, kind := range []string{"user", "net", "mnt", "pid"} {
		link, err := os.Readlink("/proc/self/ns/" + kind)
		if err != nil {
			t.Fatal(err)
		}
		hostNS[kind] = link
	}
	out := runIn(t, s, `
		for ns in user net mnt pid; do echo "ns $ns $(readlink /proc/self/ns/$ns)"; done
		echo "uid $(id -u) gid $(id -g)"
		echo "pid $$"
		echo "procs $(ls /proc | grep -c '^[0-9]')"
		cat /proc/self/uid_map /proc/self/gid_map | awk '{print "map", $1, $2, $3}'
		cat /proc/net/route /proc/net/if_inet6 /etc/resolv.conf
		grep -E '^(Cap|NoNewPrivs)' /proc/self/status /proc/1/status
		cat /proc/1/cmdline | tr '\0' ' '; echo
		cat /sys/class/net/lo/operstate 2>/dev/null || true
	`)
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 3 && fields[0] == "ns" && fields[2] == hostNS[fields[1]] {
			t.Errorf("session shares the host %s namespace %s", fields[1], fields[2])
		}
	}
	// The session runs as the caller's host identity, mapped to the caller's
	// own UID/GID (an identity map in the initial namespace, "1009 0 1"
	// under `podman unshare`).
	cred := s.Credential()
	for _, want := range []string{
		fmt.Sprintf("uid %d gid %d", cred.UID, cred.GID),
		fmt.Sprintf("map %d %d 1", cred.UID, os.Geteuid()),
		fmt.Sprintf("map %d %d 1", cred.GID, os.Getegid()),
		"sessionnet0\t00000000", // IPv4 default route
		"fd427d2a9b3100000000000000000002",
		"nameserver " + GatewayIPv4, "nameserver " + GatewayIPv6,
		"sessionnet-supervisor",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("session output lacks %q:\n%s", want, out)
		}
	}
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "status:Cap") && !strings.HasSuffix(line, "0000000000000000") {
			t.Errorf("session or supervisor holds capabilities: %s", line)
		}
		if strings.Contains(line, "NoNewPrivs") && !strings.HasSuffix(line, "1") {
			t.Errorf("no_new_privs not set: %s", line)
		}
		if strings.HasPrefix(line, "procs ") {
			if n, _ := strconv.Atoi(strings.TrimPrefix(line, "procs ")); n > 6 {
				t.Errorf("session /proc shows host processes: %s", line)
			}
		}
	}
	if after := snapshotHostNetwork(t); after != before {
		t.Fatalf("host network changed:\nbefore %+v\nafter %+v", before, after)
	}
}

// TestRootlessTunHandoff verifies that traffic from the session reaches the
// TUN descriptor created inside the namespace and handed over SCM_RIGHTS.
func TestRootlessTunHandoff(t *testing.T) {
	requireRootless(t)
	s := openRootless(t, Config{})
	fd, err := s.DupTun()
	if err != nil {
		t.Fatal(err)
	}
	defer fd.Close()
	result := make(chan error, 1)
	go func() {
		packet := make([]byte, 65535)
		for {
			n, err := fd.Read(packet)
			if err != nil {
				result <- err
				return
			}
			if matchesUDPProbe(packet[:n]) {
				result <- nil
				return
			}
		}
	}()
	if err := s.Release(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	p, err := s.Spawn(ctx, Config{Command: []string{os.Args[0]}, Env: []string{"SESSIONNET_TEST_MODE=listen", "SESSIONNET_LISTEN=udp-probe"}})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	select {
	case err := <-result:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for the UDP probe on the handed-over TUN")
	}
}

// TestRootlessDiagnosticSocket proves the handed-over sock_diag socket
// queries the session namespace: it sees a session listener and none of the
// host's sockets, without the caller ever entering the namespace.
func TestRootlessDiagnosticSocket(t *testing.T) {
	requireRootless(t)
	host, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer host.Close()
	hostPort := uint16(host.Addr().(*net.TCPAddr).Port)
	s := openRootless(t, Config{})
	if err := s.Release(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	stdout, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer stdout.Close()
	p, err := s.Spawn(ctx, Config{Command: []string{os.Args[0]}, Env: []string{"SESSIONNET_TEST_MODE=listen", "SESSIONNET_LISTEN=tcp"}, Stdout: writer})
	_ = writer.Close()
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	line, err := bufio.NewReader(stdout).ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(strings.TrimSpace(line))
	if err != nil {
		t.Fatal(line)
	}
	diag, err := s.DupDiag()
	if err != nil {
		t.Fatal(err)
	}
	defer diag.Close()
	ports, uids, err := dumpTCPListeners(int(diag.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(ports, uint16(port)) {
		t.Fatalf("session listener %d not visible through sock_diag: %v", port, ports)
	}
	if slices.Contains(ports, hostPort) {
		t.Fatalf("sock_diag socket sees the host listener %d", hostPort)
	}
	for i, p := range ports {
		if p != uint16(port) {
			continue
		}
		// sock_diag reports the owner in the session's user namespace;
		// UIDToCaller makes it comparable with /proc owners.
		if uids[i] != s.Credential().UID {
			t.Fatalf("listener owner UID %d, want the session UID %d", uids[i], s.Credential().UID)
		}
		if caller, ok := s.UIDToCaller(uids[i]); !ok || caller != uint32(os.Geteuid()) {
			t.Fatalf("UIDToCaller(%d) = %d, %v; want %d", uids[i], caller, ok, os.Geteuid())
		}
		if _, ok := s.UIDToCaller(uids[i] + 1); ok {
			t.Fatal("UIDToCaller must refuse UIDs the session does not map")
		}
	}
	ns, err := s.DupNetNS()
	if err != nil {
		t.Fatal(err)
	}
	defer ns.Close()
	var nsStat, selfStat unix.Stat_t
	if err := unix.Fstat(int(ns.Fd()), &nsStat); err != nil {
		t.Fatal(err)
	}
	if err := unix.Stat("/proc/self/ns/net", &selfStat); err != nil {
		t.Fatal(err)
	}
	if nsStat.Ino == selfStat.Ino {
		t.Fatal("namespace handle refers to the host network namespace")
	}
}

// dumpTCPListeners performs an inet_diag dump of listening IPv4 TCP sockets.
func dumpTCPListeners(fd int) ([]uint16, []uint32, error) {
	req := make([]byte, 16+56)
	binary.NativeEndian.PutUint32(req[0:4], uint32(len(req)))
	binary.NativeEndian.PutUint16(req[4:6], 20) // SOCK_DIAG_BY_FAMILY
	binary.NativeEndian.PutUint16(req[6:8], unix.NLM_F_REQUEST|unix.NLM_F_DUMP)
	binary.NativeEndian.PutUint32(req[8:12], 1)
	req[16], req[17] = unix.AF_INET, unix.IPPROTO_TCP
	binary.NativeEndian.PutUint32(req[20:24], 1<<10) // TCP_LISTEN
	if err := unix.Sendto(fd, req, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return nil, nil, err
	}
	var ports []uint16
	var uids []uint32
	buf := make([]byte, 1<<16)
	for {
		n, _, err := unix.Recvfrom(fd, buf, 0)
		if err != nil {
			return nil, nil, err
		}
		msgs, err := syscall.ParseNetlinkMessage(buf[:n])
		if err != nil {
			return nil, nil, err
		}
		for _, m := range msgs {
			switch m.Header.Type {
			case unix.NLMSG_DONE:
				return ports, uids, nil
			case unix.NLMSG_ERROR:
				return nil, nil, errors.New("netlink error")
			}
			if len(m.Data) >= 72 {
				ports = append(ports, binary.BigEndian.Uint16(m.Data[4:6]))
				uids = append(uids, binary.NativeEndian.Uint32(m.Data[64:68]))
			}
		}
	}
}

// runListener is executed inside sessions by the tests.
func runListener() int {
	switch os.Getenv("SESSIONNET_LISTEN") {
	case "tcp":
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return 1
		}
		fmt.Println(l.Addr().(*net.TCPAddr).Port)
		time.Sleep(time.Minute)
	case "udp-probe":
		conn, err := net.Dial("udp", net.JoinHostPort(GatewayIPv4, "5353"))
		if err != nil {
			return 1
		}
		for range 50 {
			_, _ = conn.Write([]byte("probe"))
			time.Sleep(100 * time.Millisecond)
		}
	case "loopback":
		// Bind a fixed port on the session loopback; prints OK on success.
		l, err := net.Listen("tcp", "127.0.0.1:47123")
		if err != nil {
			fmt.Println("BUSY", err)
			return 1
		}
		fmt.Println("OK")
		time.Sleep(time.Minute)
		_ = l.Close()
	}
	return 0
}

// matchesUDPProbe rejects unrelated interface traffic and checks that the
// isolated command's exact UDP payload reaches the supervisor's TUN FD.
func matchesUDPProbe(packet []byte) bool {
	if len(packet) < 28 || packet[0]>>4 != 4 || packet[9] != 17 ||
		!bytes.Equal(packet[12:16], []byte{172, 31, 254, 2}) ||
		!bytes.Equal(packet[16:20], []byte{172, 31, 254, 1}) {
		return false
	}
	ipHeaderLength := int(packet[0]&0x0f) * 4
	if ipHeaderLength < 20 || len(packet) < ipHeaderLength+8 {
		return false
	}
	udp := packet[ipHeaderLength:]
	udpLength := int(binary.BigEndian.Uint16(udp[4:6]))
	if udpLength != 8+len("probe") || len(udp) < udpLength {
		return false
	}
	return binary.BigEndian.Uint16(udp[2:4]) == 5353 &&
		bytes.Equal(udp[8:udpLength], []byte("probe"))
}

func TestMatchesUDPProbe(t *testing.T) {
	probe := make([]byte, 20+8+len("probe"))
	probe[0] = 0x45
	probe[9] = 17
	copy(probe[12:16], []byte{172, 31, 254, 2})
	copy(probe[16:20], []byte{172, 31, 254, 1})
	binary.BigEndian.PutUint16(probe[22:24], 5353)
	binary.BigEndian.PutUint16(probe[24:26], uint16(8+len("probe")))
	copy(probe[28:], "probe")
	if !matchesUDPProbe(probe) {
		t.Fatal("expected UDP probe was not recognized")
	}
	if matchesUDPProbe([]byte{0x60, 0, 0, 0, 0, 8, 0x3a, 0xff}) || matchesUDPProbe(probe[:24]) {
		t.Fatal("unrelated packets must be ignored")
	}
}

// TestRootlessSessionsAreIndependent checks loopback, ports and resolver
// isolation between two sessions, and sharing within one session.
func TestRootlessSessionsAreIndependent(t *testing.T) {
	requireRootless(t)
	a := openRootless(t, Config{})
	b := openRootless(t, Config{})
	for _, s := range []*Session{a, b} {
		if err := s.Release(); err != nil {
			t.Fatal(err)
		}
	}
	listen := func(s *Session) (*Process, string) {
		stdout, writer, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		defer stdout.Close()
		p, err := s.Spawn(context.Background(), Config{Command: []string{os.Args[0]}, Env: []string{"SESSIONNET_TEST_MODE=listen", "SESSIONNET_LISTEN=loopback"}, Stdout: writer})
		_ = writer.Close()
		if err != nil {
			t.Fatal(err)
		}
		line, _ := bufio.NewReader(stdout).ReadString('\n')
		return p, strings.TrimSpace(line)
	}
	pa, ra := listen(a)
	defer pa.Close()
	pb, rb := listen(b)
	defer pb.Close()
	if ra != "OK" || rb != "OK" {
		t.Fatalf("the same loopback port must be free in each session: %q %q", ra, rb)
	}
	// A second command of the same session shares its loopback.
	pc, rc := listen(a)
	defer pc.Close()
	if !strings.HasPrefix(rc, "BUSY") {
		t.Fatalf("commands of one session must share loopback, got %q", rc)
	}
	netA, netB := runIn(t, a, "readlink /proc/self/ns/net"), runIn(t, b, "readlink /proc/self/ns/net")
	if netA == netB || netA != runIn(t, a, "readlink /proc/self/ns/net") {
		t.Fatalf("namespace sharing is wrong: %q %q", netA, netB)
	}
	mntA, mntB := runIn(t, a, "readlink /proc/self/ns/mnt"), runIn(t, b, "readlink /proc/self/ns/mnt")
	if mntA == mntB {
		t.Fatal("sessions share a resolver mount namespace")
	}
}

func TestRootlessDistinctResolverAddresses(t *testing.T) {
	requireRootless(t)
	// Compare contents: the test itself may run inside another session.
	original, _ := os.ReadFile("/etc/resolv.conf")
	custom := AddressConfig{GatewayIPv4: mustAddr("10.250.250.1"), SessionIPv4: mustPrefix("10.250.250.2/30")}
	a := openRootless(t, Config{Addresses: custom})
	b := openRootless(t, Config{})
	for _, s := range []*Session{a, b} {
		if err := s.Release(); err != nil {
			t.Fatal(err)
		}
	}
	if out := runIn(t, a, "cat /etc/resolv.conf"); !strings.Contains(out, "10.250.250.1") || strings.Contains(out, GatewayIPv4) {
		t.Fatalf("custom resolver: %q", out)
	}
	if out := runIn(t, b, "cat /etc/resolv.conf"); !strings.Contains(out, GatewayIPv4) || strings.Contains(out, "10.250.250.1") {
		t.Fatalf("default resolver leaked another session's settings: %q", out)
	}
	host, err := os.ReadFile("/etc/resolv.conf")
	if err == nil && !bytes.Equal(host, original) {
		t.Fatal("host resolver was modified")
	}
}

func TestRootlessIsolateDNS(t *testing.T) {
	requireRootless(t)
	var stat unix.Stat_t
	if err := unix.Stat("/etc/nsswitch.conf", &stat); err != nil {
		t.Skip("no /etc/nsswitch.conf on this host")
	}
	if stat.Nlink == 0 {
		// Nested inside an older sessionnet release, whose deleted bind mount
		// cannot be mounted over; that case is reported with a clear error.
		t.Skip("/etc/nsswitch.conf is a bind mount of a deleted file in this environment")
	}
	original, err := os.ReadFile("/etc/nsswitch.conf")
	if err != nil {
		t.Fatal(err)
	}
	s := openRootless(t, Config{IsolateDNS: true})
	if err := s.Release(); err != nil {
		t.Fatal(err)
	}
	out := runIn(t, s, "cat /etc/nsswitch.conf")
	if out != isolatedNSS(string(original)) {
		t.Fatalf("isolated NSS: %q", out)
	}
	if after, err := os.ReadFile("/etc/nsswitch.conf"); err != nil || !bytes.Equal(original, after) {
		t.Fatal("host NSS configuration changed")
	}
}

func mustAddr(s string) netip.Addr     { return netip.MustParseAddr(s) }
func mustPrefix(s string) netip.Prefix { return netip.MustParsePrefix(s) }

// sessionProcesses lists host PIDs whose PID namespace is pidns.
func sessionProcesses(pidns string) []int {
	entries, _ := os.ReadDir("/proc")
	var pids []int
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		if link, err := os.Readlink(filepath.Join("/proc", e.Name(), "ns/pid")); err == nil && link == pidns {
			pids = append(pids, pid)
		}
	}
	return pids
}

func waitNoProcesses(t testing.TB, pidns string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		left := sessionProcesses(pidns)
		if len(left) == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("processes of %s survived: %v", pidns, left)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// spawnProcessTree starts background, nested, setsid-detached and
// double-forked daemon processes that all outlive the spawning command.
const processTree = `
	sleep 300 &
	(sleep 300 &) &
	sh -c 'sh -c "sleep 300 & sleep 300" &' &
	setsid sleep 300 < /dev/null > /dev/null 2>&1 &
	nohup sh -c 'sleep 300' > /dev/null 2>&1 &
	sh -c 'setsid sh -c "sleep 300 &" &'
	sleep 0.3
	echo spawned
`

func TestRootlessLifecycleKillsAllDescendants(t *testing.T) {
	requireRootless(t)
	s := openRootless(t, Config{})
	if err := s.Release(); err != nil {
		t.Fatal(err)
	}
	pidns, err := os.Readlink(fmt.Sprintf("/proc/%d/ns/pid", s.PID()))
	if err != nil {
		t.Fatal(err)
	}
	if out := runIn(t, s, processTree); !strings.Contains(out, "spawned") {
		t.Fatal(out)
	}
	// The command returned; its detached descendants are still running.
	if n := len(sessionProcesses(pidns)); n < 8 {
		t.Fatalf("expected the detached process tree to be alive, found %d processes", n)
	}
	// Closing one command must not end the session.
	if out := runIn(t, s, "echo still-alive"); !strings.Contains(out, "still-alive") {
		t.Fatal(out)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	waitNoProcesses(t, pidns)
}

func TestRootlessProcessCloseKillsItsGroup(t *testing.T) {
	requireRootless(t)
	s := openRootless(t, Config{})
	if err := s.Release(); err != nil {
		t.Fatal(err)
	}
	p, err := s.Spawn(context.Background(), Config{Command: []string{"/bin/sh", "-c", "sleep 300 & sleep 300"}})
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	var exit *ExitError
	if err := p.Wait(); !errors.As(err, &exit) || exit.Signal() != int(syscall.SIGKILL) {
		t.Fatalf("closed process: %v", err)
	}
	if out := runIn(t, s, "pgrep -c sleep || true"); strings.TrimSpace(out) != "0" {
		t.Fatalf("process group survived Process.Close: %q", out)
	}
}

func TestRootlessExitStatusAndSignals(t *testing.T) {
	requireRootless(t)
	s := openRootless(t, Config{})
	if err := s.Release(); err != nil {
		t.Fatal(err)
	}
	p, err := s.Spawn(context.Background(), Config{Command: []string{"/bin/sh", "-c", "exit 7"}})
	if err != nil {
		t.Fatal(err)
	}
	var exit *ExitError
	if err := p.Wait(); !errors.As(err, &exit) || exit.ExitCode() != 7 {
		t.Fatalf("exit status: %v", err)
	}
	var out lockedBuffer
	p, err = s.Spawn(context.Background(), Config{Command: []string{"/bin/sh", "-c", "trap 'echo got-term; exit 0' TERM; echo ready; while :; do sleep 0.05; done"}, Stdout: &out})
	if err != nil {
		t.Fatal(err)
	}
	for !strings.Contains(out.String(), "ready") {
		time.Sleep(10 * time.Millisecond)
	}
	if err := p.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	if err := p.Wait(); err != nil || !strings.Contains(out.String(), "got-term") {
		t.Fatalf("signal forwarding: %v %q", err, out.String())
	}
	if _, err := s.Spawn(context.Background(), Config{Command: []string{"/nonexistent/binary"}}); err == nil {
		t.Fatal("spawning a missing executable must fail")
	}
	// Session processes cannot terminate their own PID 1 supervisor.
	runIn(t, s, "kill -TERM 1; kill -INT 1; kill -HUP 1; true")
	if out := runIn(t, s, "echo alive"); !strings.Contains(out, "alive") {
		t.Fatal(out)
	}
}

func TestRootlessSupervisorCrashKillsSession(t *testing.T) {
	requireRootless(t)
	s := openRootless(t, Config{})
	if err := s.Release(); err != nil {
		t.Fatal(err)
	}
	pidns, err := os.Readlink(fmt.Sprintf("/proc/%d/ns/pid", s.PID()))
	if err != nil {
		t.Fatal(err)
	}
	p, err := s.Spawn(context.Background(), Config{Command: []string{"/bin/sh", "-c", processTree + "\nsleep 300"}})
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(500 * time.Millisecond)
	if err := syscall.Kill(s.PID(), syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	if err := p.Wait(); !errors.Is(err, ErrSupervisorExited) {
		t.Fatalf("command of a crashed supervisor: %v", err)
	}
	<-s.Done()
	waitNoProcesses(t, pidns)
	if _, err := s.Spawn(context.Background(), Config{Command: []string{"/bin/true"}}); err == nil {
		t.Fatal("spawn after supervisor crash must fail")
	}
}

// runCrashParent plays the role of a Yuhaiin process that is killed with
// SIGKILL while a session with detached descendants is running.
func runCrashParent() int {
	s, err := Open(context.Background(), Config{})
	if err != nil {
		fmt.Println("ERROR", err)
		return 1
	}
	if err := s.Release(); err != nil {
		return 1
	}
	p, err := s.Spawn(context.Background(), Config{Command: []string{"/bin/sh", "-c", processTree + "\nsleep 300"}})
	if err != nil {
		return 1
	}
	_ = p
	time.Sleep(500 * time.Millisecond)
	pidns, _ := os.Readlink(fmt.Sprintf("/proc/%d/ns/pid", s.PID()))
	fmt.Printf("READY %d %s\n", s.PID(), pidns)
	time.Sleep(time.Minute)
	return 0
}

func TestRootlessParentCrashKillsSession(t *testing.T) {
	requireRootless(t)
	cmd := exec.Command(os.Args[0])
	cmd.Env = append(os.Environ(), "SESSIONNET_TEST_MODE=crash-parent")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	line, err := bufio.NewReader(stdout).ReadString('\n')
	fields := strings.Fields(line)
	if err != nil || len(fields) != 3 || fields[0] != "READY" {
		t.Fatalf("crash parent: %q %v", line, err)
	}
	pidns := fields[2]
	if n := len(sessionProcesses(pidns)); n < 8 {
		t.Fatalf("expected a live process tree, found %d", n)
	}
	if err := cmd.Process.Signal(syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	_ = cmd.Wait()
	waitNoProcesses(t, pidns)
}

func TestRootlessInitialCommandAndStdio(t *testing.T) {
	requireRootless(t)
	var out bytes.Buffer
	s := openRootless(t, Config{
		Command: []string{"/bin/sh", "-c", "read -r line; echo \"in=$line\"; echo err >&2; exit 4"},
		Stdin:   strings.NewReader("hello\n"), Stdout: &out, Stderr: &out,
	})
	if err := s.Release(); err != nil {
		t.Fatal(err)
	}
	if err := s.Release(); err == nil {
		t.Fatal("second release must fail")
	}
	var exit *ExitError
	if err := s.Wait(); !errors.As(err, &exit) || exit.ExitCode() != 4 {
		t.Fatalf("initial command: %v", err)
	}
	if !strings.Contains(out.String(), "in=hello") || !strings.Contains(out.String(), "err") {
		t.Fatalf("stdio: %q", out.String())
	}
}

// TestRootlessStartGate checks that nothing runs before Release.
func TestRootlessStartGate(t *testing.T) {
	requireRootless(t)
	dir := t.TempDir()
	marker := filepath.Join(dir, "started")
	s := openRootless(t, Config{Command: []string{"/bin/sh", "-c", "echo started > \"$1\"", "gate", marker}})
	time.Sleep(100 * time.Millisecond)
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("command ran before release: %v", err)
	}
	if _, err := s.Spawn(context.Background(), Config{Command: []string{"/bin/true"}}); err == nil {
		t.Fatal("spawn before release must fail")
	}
	if err := s.Release(); err != nil {
		t.Fatal(err)
	}
	if err := s.Wait(); err != nil {
		t.Fatal(err)
	}
	if content, err := os.ReadFile(marker); err != nil || string(content) != "started\n" {
		t.Fatalf("unexpected marker %q: %v", content, err)
	}
}

func TestRootlessCancellationLeaksNothing(t *testing.T) {
	requireRootless(t)
	before := countOpenFDs(t)
	for i := range 30 {
		ctx, cancel := context.WithTimeout(context.Background(), time.Duration(i%10)*300*time.Microsecond)
		s, err := Open(ctx, Config{IPv6: true})
		cancel()
		if err == nil {
			_ = s.Close()
		} else if !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, context.Canceled) {
			t.Fatalf("cancellation produced an unrelated error: %v", err)
		}
	}
	if children := childProcesses(t); len(children) != 0 {
		t.Fatalf("helpers left after canceled setup: %v", children)
	}
	if after := countOpenFDs(t); after > before+2 {
		t.Fatalf("descriptor leak: %d before, %d after", before, after)
	}
}

func countOpenFDs(t testing.TB) int {
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	return len(entries)
}

func childProcesses(t testing.TB) []string {
	t.Helper()
	tasks, _ := os.ReadDir("/proc/self/task")
	var children []string
	for _, task := range tasks {
		data, _ := os.ReadFile(filepath.Join("/proc/self/task", task.Name(), "children"))
		children = append(children, strings.Fields(string(data))...)
	}
	return children
}

// lockedBuffer is safe for a test to read while a session writes to it.
type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}
