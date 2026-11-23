//go:build linux

package sessionnet

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// Failure injection runs each scenario in a child of the test binary that
// lives in its own user and mount namespace. There it may lower namespace
// limits or hide /dev/net/tun without affecting the host, and then calls the
// real Open, exactly as Yuhaiin would.

type scenarioResult struct {
	OK      bool   `json:"ok"`
	Stage   Stage  `json:"stage"`
	Message string `json:"message"`
	Output  string `json:"output"`
}

type outerNamespace int

const (
	// outerIdentity maps only the caller's own IDs, like an unprivileged
	// user; ambient capabilities let the scenario inject faults.
	outerIdentity outerNamespace = iota
	// outerSubordinate maps root plus /etc/subuid ranges through newuidmap,
	// which emulates a root-owned Yuhaiin without host privileges.
	outerSubordinate
)

func runScenario(t *testing.T, name string, outer outerNamespace, caps ...uintptr) scenarioResult {
	t.Helper()
	requireRootless(t)
	cmd := exec.Command(os.Args[0], "-test.run=^$")
	cmd.Env = append(os.Environ(), "SESSIONNET_TEST_MODE=scenario:"+name, "SESSIONNET_SCENARIO_TMP="+t.TempDir())
	cmd.SysProcAttr = &syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWUSER | syscall.CLONE_NEWNS, AmbientCaps: caps}
	uid, gid := os.Geteuid(), os.Getegid()
	if outer == outerIdentity {
		cmd.SysProcAttr.UidMappings = []syscall.SysProcIDMap{{ContainerID: uid, HostID: uid, Size: 1}}
		cmd.SysProcAttr.GidMappings = []syscall.SysProcIDMap{{ContainerID: gid, HostID: gid, Size: 1}}
	}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stdout strings.Builder
	cmd.Stdout, cmd.Stderr = &stdout, &stdout
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	if outer == outerSubordinate {
		if err := mapSubordinate(cmd.Process.Pid); err != nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
			t.Skipf("subordinate ID mapping is unavailable: %v", err)
		}
	}
	_, _ = io.WriteString(stdin, "go\n")
	_ = stdin.Close()
	err = cmd.Wait()
	var result scenarioResult
	for _, line := range strings.Split(stdout.String(), "\n") {
		if strings.HasPrefix(line, "RESULT ") {
			if err := json.Unmarshal([]byte(strings.TrimPrefix(line, "RESULT ")), &result); err != nil {
				t.Fatal(err)
			}
			return result
		}
	}
	t.Fatalf("scenario %s produced no result (%v):\n%s", name, err, stdout.String())
	return result
}

func mapSubordinate(pid int) error {
	uid := os.Geteuid()
	subUID := readSubordinateIDs("/etc/subuid", currentIdentity().username, uint32(uid))
	subGID := readSubordinateIDs("/etc/subgid", currentIdentity().username, uint32(uid))
	if len(subUID) == 0 || len(subGID) == 0 || subUID[0].count < 2000 || subGID[0].count < 2000 {
		return errors.New("no /etc/subuid and /etc/subgid range of at least 2000 IDs")
	}
	for _, m := range []struct {
		tool  string
		own   int
		start uint64
	}{{"newuidmap", uid, subUID[0].start}, {"newgidmap", os.Getegid(), subGID[0].start}} {
		args := []string{strconv.Itoa(pid), "0", strconv.Itoa(m.own), "1", "1", strconv.FormatUint(m.start, 10), "1999"}
		if out, err := exec.Command(m.tool, args...).CombinedOutput(); err != nil {
			return fmt.Errorf("%s: %v: %s", m.tool, err, out)
		}
	}
	return nil
}

func report(err error, output string) int {
	r := scenarioResult{OK: err == nil, Output: output}
	var setup *SetupError
	if errors.As(err, &setup) {
		r.Stage, r.Message = setup.Stage, setup.Error()
	} else if err != nil {
		r.Message = err.Error()
	}
	data, _ := json.Marshal(r)
	fmt.Println("RESULT " + string(data))
	return 0
}

func runFailureScenario(name string) int {
	// Wait until the parent has installed the outer ID mappings.
	_, _ = bufio.NewReader(os.Stdin).ReadString('\n')
	tmp := os.Getenv("SESSIONNET_SCENARIO_TMP")
	// Scenarios that inject mounts run with CAP_SYS_ADMIN; keep their
	// mounts out of the host namespace.
	if strings.HasPrefix(name, "tun-") || name == "dangling-resolver" {
		if err := unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""); err != nil {
			return report(fmt.Errorf("scenario setup: %w", err), "")
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	limit := func(name string) error { return os.WriteFile("/proc/sys/user/"+name, []byte("0"), 0) }
	self := Credential{UID: uint32(os.Geteuid()), GID: uint32(os.Getegid())}
	switch name {
	case "userns-disabled":
		if err := limit("max_user_namespaces"); err != nil {
			return report(fmt.Errorf("scenario setup: %w", err), "")
		}
		return report(Probe(ctx, Config{}), "")
	case "pidns-disabled":
		if err := limit("max_pid_namespaces"); err != nil {
			return report(fmt.Errorf("scenario setup: %w", err), "")
		}
		return report(Probe(ctx, Config{}), "")
	case "netns-disabled":
		if err := limit("max_net_namespaces"); err != nil {
			return report(fmt.Errorf("scenario setup: %w", err), "")
		}
		return report(Probe(ctx, Config{}), "")
	case "tun-missing":
		if err := unix.Mount("tmpfs", "/dev/net", "tmpfs", 0, "size=4k"); err != nil {
			return report(fmt.Errorf("scenario setup: %w", err), "")
		}
		return report(Probe(ctx, Config{}), "")
	case "tun-inaccessible":
		blocked := filepath.Join(tmp, "tun")
		if err := os.WriteFile(blocked, nil, 0); err != nil {
			return report(fmt.Errorf("scenario setup: %w", err), "")
		}
		if err := unix.Mount(blocked, "/dev/net/tun", "", unix.MS_BIND, ""); err != nil {
			return report(fmt.Errorf("scenario setup: %w", err), "")
		}
		return report(Probe(ctx, Config{}), "")
	case "tun-not-device":
		if err := unix.Mount("/dev/null", "/dev/net/tun", "", unix.MS_BIND, ""); err != nil {
			return report(fmt.Errorf("scenario setup: %w", err), "")
		}
		return report(Probe(ctx, Config{}), "")
	case "uid-map-rejected":
		// CAP_SETUID makes the planner write the map itself; the kernel
		// rejects it because the UID is not mapped in this namespace.
		return report(Probe(ctx, Config{Credential: &Credential{UID: self.UID + 1000, GID: self.GID}}), "")
	case "gid-map-rejected":
		return report(Probe(ctx, Config{Credential: &Credential{UID: self.UID, GID: self.GID + 1000}}), "")
	case "dangling-resolver":
		// Point /etc/resolv.conf at a missing file in an existing directory.
		dir := filepath.Join(tmp, "resolve")
		if err := os.Mkdir(dir, 0o755); err != nil {
			return report(err, "")
		}
		link := filepath.Join(tmp, "resolv.conf")
		if err := os.Symlink(filepath.Join(dir, "stub-resolv.conf"), link); err != nil {
			return report(err, "")
		}
		if err := bindSymlinkOverResolver(link); err != nil {
			return report(fmt.Errorf("scenario setup: %w", err), "")
		}
		return sessionOutput(ctx, Config{}, "cat /etc/resolv.conf")
	case "privileged-rootless":
		// A root-owned Yuhaiin: the session must run as UID 1000 with its
		// supplementary groups replaced instead of inherited.
		return sessionOutput(ctx, Config{Credential: &Credential{UID: 1000, GID: 1000}}, "id -u; id -G; grep -E '^(CapEff|CapBnd)' /proc/self/status")
	case "rootful":
		return sessionOutput(ctx, Config{Mode: ModeRootful, IPv6: true, Credential: &Credential{UID: 1000, GID: 1000}},
			"id -u; id -G; grep -E '^(CapEff|CapBnd|NoNewPrivs)' /proc/self/status /proc/1/status; cat /proc/net/route; cat /etc/resolv.conf; echo pid=$$\n"+processTree)
	case "bench-modes":
		out, err := benchModes()
		return report(err, out)
	case "rootful-unprivileged":
		return report(Probe(ctx, Config{Mode: ModeRootful, Credential: &Credential{UID: self.UID, GID: self.GID}}), "")
	}
	return report(fmt.Errorf("unknown scenario %q", name), "")
}

// bindSymlinkOverResolver makes /etc/resolv.conf resolve through link. A
// symlink cannot be bind-mounted onto a file, so /etc is covered by a copy.
func bindSymlinkOverResolver(link string) error {
	tmp := filepath.Dir(link)
	etc := filepath.Join(tmp, "etc")
	if err := os.Mkdir(etc, 0o755); err != nil {
		return err
	}
	if err := unix.Mount("/etc", etc, "", unix.MS_BIND|unix.MS_REC, ""); err != nil {
		return err
	}
	if err := unix.Mount("tmpfs", "/etc", "tmpfs", 0, "size=64k"); err != nil {
		return err
	}
	if err := os.Symlink(filepath.Join(filepath.Dir(link), "resolve", "stub-resolv.conf"), "/etc/resolv.conf"); err != nil {
		return err
	}
	for _, name := range []string{"passwd", "group"} {
		data, err := os.ReadFile(filepath.Join(etc, name))
		if err == nil {
			_ = os.WriteFile("/etc/"+name, data, 0o644)
		}
	}
	return nil
}

func sessionOutput(ctx context.Context, cfg Config, script string) int {
	s, err := Open(ctx, cfg)
	if err != nil {
		return report(err, "")
	}
	defer s.Close()
	if err := s.Release(); err != nil {
		return report(err, "")
	}
	var out strings.Builder
	p, err := s.Spawn(ctx, Config{Command: []string{"/bin/sh", "-c", script}, Stdout: &out, Stderr: &out})
	if err != nil {
		return report(err, "")
	}
	err = p.Wait()
	pidns, _ := os.Readlink(fmt.Sprintf("/proc/%d/ns/pid", s.PID()))
	before := len(sessionProcesses(pidns))
	if closeErr := s.Close(); closeErr != nil && err == nil {
		err = closeErr
	}
	deadline := time.Now().Add(5 * time.Second)
	for len(sessionProcesses(pidns)) != 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	return report(err, fmt.Sprintf("%sprocesses-before-close=%d processes-after-close=%d\n", out.String(), before, len(sessionProcesses(pidns))))
}

func expectFailure(t *testing.T, r scenarioResult, stage Stage, message string) {
	t.Helper()
	if r.OK {
		t.Fatalf("session setup unexpectedly succeeded:\n%s", r.Output)
	}
	if r.Stage != stage || !strings.Contains(r.Message, message) {
		t.Fatalf("got stage %q message %q, want stage %q containing %q", r.Stage, r.Message, stage, message)
	}
	t.Logf("reported: %s", r.Message)
}

func TestFailureUserNamespaceDisabled(t *testing.T) {
	r := runScenario(t, "userns-disabled", outerIdentity, unix.CAP_SYS_ADMIN, unix.CAP_SYS_RESOURCE)
	expectFailure(t, r, StageUserNamespace, "User Namespace is disabled")
}

func TestFailurePIDNamespaceUnavailable(t *testing.T) {
	r := runScenario(t, "pidns-disabled", outerIdentity, unix.CAP_SYS_ADMIN, unix.CAP_SYS_RESOURCE)
	expectFailure(t, r, StagePIDNamespace, "PID Namespace initialization failed")
}

func TestFailureNetworkNamespaceUnavailable(t *testing.T) {
	r := runScenario(t, "netns-disabled", outerIdentity, unix.CAP_SYS_ADMIN, unix.CAP_SYS_RESOURCE)
	expectFailure(t, r, StageNamespaces, "Network Namespace initialization failed")
}

func TestFailureTUNMissing(t *testing.T) {
	r := runScenario(t, "tun-missing", outerIdentity, unix.CAP_SYS_ADMIN)
	expectFailure(t, r, StageTUN, "/dev/net/tun does not exist")
}

func TestFailureTUNInaccessible(t *testing.T) {
	r := runScenario(t, "tun-inaccessible", outerIdentity, unix.CAP_SYS_ADMIN)
	expectFailure(t, r, StageTUN, "/dev/net/tun is not accessible")
}

func TestFailureTUNNotADevice(t *testing.T) {
	r := runScenario(t, "tun-not-device", outerIdentity, unix.CAP_SYS_ADMIN)
	expectFailure(t, r, StageTUN, "not a usable TUN device")
}

func TestFailureUIDMappingRejected(t *testing.T) {
	r := runScenario(t, "uid-map-rejected", outerIdentity, unix.CAP_SETUID)
	expectFailure(t, r, StageUIDMap, "UID mapping failed")
}

func TestFailureGIDMappingRejected(t *testing.T) {
	r := runScenario(t, "gid-map-rejected", outerIdentity, unix.CAP_SETGID)
	expectFailure(t, r, StageGIDMap, "GID mapping failed")
}

func TestFailureUnmappableUID(t *testing.T) {
	requireRootless(t)
	self := currentIdentity()
	if self.canSetUID {
		t.Skip("the caller may map any UID")
	}
	uid := self.uid + 1
	for inRanges(self.subUIDs, uid) {
		uid++
	}
	err := Probe(context.Background(), Config{Credential: &Credential{UID: uid, GID: self.gid}})
	var setup *SetupError
	if !errors.As(err, &setup) || setup.Stage != StageUIDMap || !strings.Contains(setup.Message, "UID mapping failed") {
		t.Fatalf("unmappable UID: %v", err)
	}
	if children := childProcesses(t); len(children) != 0 {
		t.Fatalf("pre-validated failure started helpers: %v", children)
	}
}

func TestFailureRootfulWithoutPrivileges(t *testing.T) {
	r := runScenario(t, "rootful-unprivileged", outerIdentity)
	expectFailure(t, r, StageNamespaces, "Rootful mode requires root privileges")
}

func TestRootlessDanglingResolverSymlink(t *testing.T) {
	r := runScenario(t, "dangling-resolver", outerIdentity, unix.CAP_SYS_ADMIN)
	if !r.OK || !strings.Contains(r.Output, "nameserver "+GatewayIPv4) {
		t.Fatalf("dangling resolver symlink: %+v", r)
	}
}

func TestRootlessPrivilegedCallerReplacesGroups(t *testing.T) {
	r := runScenario(t, "privileged-rootless", outerSubordinate, allCaps()...)
	if !r.OK {
		t.Fatalf("%+v", r)
	}
	lines := strings.Split(r.Output, "\n")
	if len(lines) < 4 || lines[0] != "1000" || lines[1] != "1000" ||
		!strings.Contains(r.Output, "CapEff:\t0000000000000000") || !strings.Contains(r.Output, "CapBnd:\t0000000000000000") {
		t.Fatalf("privileged rootless session: %q", r.Output)
	}
}

// TestRootfulMode runs the rootful backend as root of a user namespace that
// owns the network, mount and PID namespaces, which is the same kernel path
// a root-owned Yuhaiin takes on the host.
func TestRootfulMode(t *testing.T) {
	var r scenarioResult
	if os.Geteuid() == 0 {
		// Real root (CI): the scenario mapping is not needed.
		t.Skip("covered by TestRootfulModeAsRoot")
	}
	r = runScenario(t, "rootful", outerSubordinate, allCaps()...)
	checkRootful(t, r)
}

func TestRootfulModeAsRoot(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root; TestRootfulMode covers rootful mode inside a user namespace")
	}
	_ = os.Setenv("SESSIONNET_SCENARIO_TMP", t.TempDir())
	cmd := exec.Command(os.Args[0], "-test.run=^$")
	cmd.Env = append(os.Environ(), "SESSIONNET_TEST_MODE=scenario:rootful")
	cmd.Stdin = strings.NewReader("go\n")
	cmd.SysProcAttr = &syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWNS}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	var r scenarioResult
	for _, line := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(line, "RESULT ") {
			_ = json.Unmarshal([]byte(strings.TrimPrefix(line, "RESULT ")), &r)
		}
	}
	checkRootful(t, r)
}

func checkRootful(t *testing.T, r scenarioResult) {
	t.Helper()
	if !r.OK {
		t.Fatalf("rootful session failed: %+v", r)
	}
	for _, want := range []string{"1000\n1000\n", "/proc/self/status:CapEff:\t0000000000000000", "/proc/1/status:CapEff:\t0000000000000000",
		"/proc/self/status:NoNewPrivs:\t1", "sessionnet0\t00000000", "nameserver " + GatewayIPv4, "spawned", "processes-after-close=0"} {
		if !strings.Contains(r.Output, want) {
			t.Fatalf("rootful output lacks %q:\n%s", want, r.Output)
		}
	}
}

func allCaps() []uintptr {
	return []uintptr{unix.CAP_SYS_ADMIN, unix.CAP_NET_ADMIN, unix.CAP_SETUID, unix.CAP_SETGID, unix.CAP_SETPCAP,
		unix.CAP_SYS_RESOURCE, unix.CAP_DAC_OVERRIDE, unix.CAP_CHOWN, unix.CAP_FOWNER, unix.CAP_KILL, unix.CAP_SYS_PTRACE}
}
