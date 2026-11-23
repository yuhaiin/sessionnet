//go:build linux

package sessionnet

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestCgroupRootValidation(t *testing.T) {
	for _, root := range []string{"relative", "/", filepath.Join(t.TempDir(), "regular")} {
		manager, err := NewCgroupManager(root)
		if err == nil {
			_ = manager.Close()
			t.Fatalf("root %q must be a trusted cgroup v2 directory", root)
		}
	}
}

func TestSafeGroupName(t *testing.T) {
	for _, tc := range []struct {
		name  string
		valid bool
	}{
		{"session-0123456789abcdef0123456789abcdef", true},
		{"session-../../etc/passwd", false},
		{"session-1234", false},
		{"session-0123456789abcdef0123456789abcdeg", false},
		{"other-0123456789abcdef0123456789abcdef", false},
	} {
		if safeGroupName(tc.name) != tc.valid {
			t.Errorf("unexpected validation for %q", tc.name)
		}
	}
}

func testCgroupRoot(t *testing.T) string {
	t.Helper()
	parent := os.Getenv("SESSIONNET_CGROUP_TEST_ROOT")
	if parent == "" {
		t.Skip("set SESSIONNET_CGROUP_TEST_ROOT to a writable, dedicated cgroup v2 parent")
	}
	root := filepath.Join(parent, "test-"+strconv.FormatInt(time.Now().UnixNano(), 16))
	t.Cleanup(func() { _ = os.Remove(root) })
	return root
}

func TestLinuxCgroupProcessContainment(t *testing.T) {
	root := testCgroupRoot(t)
	manager, err := NewCgroupManager(root)
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	owner, err := Open(ctx, cgroupTestConfig(manager))
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	if err := owner.Release(); err != nil {
		t.Fatal(err)
	}
	child, err := owner.Spawn(ctx, Config{Command: []string{"/bin/sh", "-c", processTree + "\nsleep 120"}})
	if err != nil {
		t.Fatal(err)
	}
	defer child.Close()
	time.Sleep(500 * time.Millisecond)
	names, err := managedGroupNames(root)
	if err != nil || len(names) != 1 {
		t.Fatalf("expected one session cgroup: %v %v", names, err)
	}
	processes, err := os.ReadFile(filepath.Join(root, names[0], "cgroup.procs"))
	if err != nil {
		t.Fatal(err)
	}
	members := strings.Fields(string(processes))
	if !slices.Contains(members, strconv.Itoa(owner.PID())) || len(members) < 8 {
		t.Fatalf("session helper and descendants must be in the managed cgroup: %q", processes)
	}
	if err := owner.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-child.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("cgroup.kill did not stop the spawned process")
	}
	names, err = managedGroupNames(root)
	if err != nil || len(names) != 0 {
		t.Fatalf("session cgroup was not removed: %v %v", names, err)
	}
}

// cgroupTestConfig uses rootless mode unless the test runs as root, which
// is how CI exercises cgroups on a root-owned hierarchy.
func cgroupTestConfig(manager *CgroupManager) Config {
	if os.Geteuid() == 0 {
		return Config{Mode: ModeRootful, Credential: unprivileged(), Cgroup: manager}
	}
	return Config{Cgroup: manager}
}

func TestCgroupReadOnlyRootFails(t *testing.T) {
	// The cgroup v2 mount point and service-manager owned directories are
	// not writable for a normal user; the manager must fail closed.
	if os.Geteuid() == 0 {
		t.Skip("root can write every cgroup")
	}
	var stat unix.Statfs_t
	if unix.Statfs("/sys/fs/cgroup", &stat) != nil || stat.Type != unix.CGROUP2_SUPER_MAGIC {
		t.Skip("cgroup v2 is not mounted")
	}
	for _, root := range []string{"/sys/fs/cgroup/sessionnet-readonly-test", "/sys/fs/cgroup/init.scope/sessionnet-test"} {
		if manager, err := NewCgroupManager(root); err == nil {
			_ = manager.Close()
			t.Fatalf("read-only cgroup %s was accepted", root)
		}
	}
}

func TestDelegatedCgroupRootRequiresMarker(t *testing.T) {
	root, err := DelegatedCgroupRoot("sessionnet-test")
	if err != nil {
		if !errors.Is(err, ErrNoDelegatedCgroup) {
			t.Fatal(err)
		}
		t.Logf("no delegation here, the PID namespace supervisor is used: %v", err)
		return
	}
	t.Logf("delegated cgroup available at %s", root)
	if _, err := DelegatedCgroupRoot("../escape"); err == nil {
		t.Fatal("cgroup names must not traverse")
	}
}

func TestLinuxCgroupOrphanRecovery(t *testing.T) {
	root := testCgroupRoot(t)
	first, err := NewCgroupManager(root)
	if err != nil {
		t.Fatal(err)
	}
	g, err := first.newGroup()
	if err != nil {
		_ = first.Close()
		t.Fatal(err)
	}
	defer g.fd.Close()
	cmd := exec.Command("/bin/sh", "-c", "exec sleep 120")
	cmd.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: int(g.fd.Fd())}
	if err := cmd.Start(); err != nil {
		_ = first.Close()
		t.Fatal(err)
	}
	waited := make(chan error, 1)
	go func() { waited <- cmd.Wait() }()
	// Simulate SIGKILL by dropping only the supervisor lock. The old
	// process and session cgroup remain populated.
	if err := first.root.Close(); err != nil {
		t.Fatal(err)
	}
	second, err := NewCgroupManager(root)
	if err != nil {
		_ = cmd.Process.Kill()
		t.Fatal(err)
	}
	defer second.Close()
	select {
	case err := <-waited:
		if err == nil {
			t.Fatal("orphan exited without a signal")
		}
	case <-time.After(5 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatal("orphan was not terminated during recovery")
	}
	names, err := managedGroupNames(root)
	if err != nil || len(names) != 0 {
		t.Fatalf("orphan cgroup remains: %v %v", names, err)
	}
}

func TestLinuxCgroupManagerExclusiveLock(t *testing.T) {
	root := testCgroupRoot(t)
	first, err := NewCgroupManager(root)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := NewCgroupManager(root)
	if err == nil {
		_ = second.Close()
		t.Fatal("second supervisor acquired an already-locked cgroup root")
	}
	if !errors.Is(err, unix.EWOULDBLOCK) && !errors.Is(err, unix.EAGAIN) {
		t.Fatalf("unexpected exclusive lock error: %v", err)
	}
}

func managedGroupNames(root string) ([]string, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, err
	}
	var names []string
	for _, entry := range entries {
		if entry.IsDir() && safeGroupName(entry.Name()) {
			names = append(names, entry.Name())
		}
	}
	return names, nil
}
