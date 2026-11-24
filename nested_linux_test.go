//go:build linux

package sessionnet

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// Nested user namespaces. A caller that runs inside a user namespace, such
// as Yuhaiin started by `podman unshare`, must give sessions the host
// identity its own namespace stands for: with uid_map "0 1009 1" the
// session maps host UID 1009 to the caller's UID 0.
//
// TestNestedNamespaceIdentity emulates that layout without Podman: the test
// binary re-executes itself as root of a user namespace whose UID/GID 0 is
// the test user, exactly like the first line of Podman's map, with setgroups
// denied (the stricter case). TestInheritedNamespaceInPlace runs the same
// checks when the test binary itself was started inside such a namespace,
// for example `podman unshare ./sessionnet.test -test.run InPlace`.
//
// Both verify file access through the kernel, not just the reported IDs.
// Environment for the in-place test (set by the runner, all optional):
//
//	SESSIONNET_EXPECT_HOST_UID/GID  expected host identity (required in place)
//	SESSIONNET_TEST_DIR             host directory owned by that identity
//	SESSIONNET_GROUP_DIR            directory only a supplementary group may use
//	SESSIONNET_DENIED_DIR           directory the identity must not read
//	SESSIONNET_REQUIRE_INHERITED=1  fail instead of skipping

// fileAccessScript reports the session identity and exercises dir, which
// holds "file" (content "hello") and "run.sh", both owned by the identity.
func fileAccessScript(dir, groupDir, denied string) string {
	return fmt.Sprintf(`echo "uid=$(id -u)"
echo "gid=$(id -g)"
echo "groups=$(id -G)"
echo "uidmap=$(tr -s ' ' < /proc/self/uid_map | sed 's/^ //')"
echo "gidmap=$(tr -s ' ' < /proc/self/gid_map | sed 's/^ //')"
echo "setgroups=$(cat /proc/self/setgroups)"
echo "owner=$(stat -c %%u:%%g %[1]s)"
echo "fileowner=$(stat -c %%u:%%g %[1]s/file)"
echo "ownername=$(stat -c %%U:%%G %[1]s)"
cd %[1]s && echo "traverse=ok"
echo "read=$(cat file)"
echo written > new && echo "write=$(cat new)"
echo "created=$(stat -c %%u:%%g new)"
rm new && test ! -e new && echo "deleted=yes"
echo "exec=$(./run.sh)"
if [ -n "%[2]s" ]; then
  if ls %[2]s >/dev/null 2>&1 && touch %[2]s/probe-$$ && rm %[2]s/probe-$$; then echo "groupaccess=yes"; else echo "groupaccess=no"; fi
fi
if [ -n "%[3]s" ]; then
  if ls %[3]s >/dev/null 2>&1; then echo "denied=no"; else echo "denied=yes"; fi
fi
grep -E '^(CapEff|CapBnd|NoNewPrivs)' /proc/self/status | tr -d '\t' | sed 's/:/=/'
`, dir, groupDir, denied)
}

func prepareAccessDir(t testing.TB, dir string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "file"), []byte("hello"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "run.sh"), []byte("#!/bin/sh\necho ok\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
}

func parseKeyValues(output string) map[string]string {
	values := map[string]string{}
	for _, line := range strings.Split(output, "\n") {
		if key, value, ok := strings.Cut(line, "="); ok {
			values[key] = value
		}
	}
	return values
}

// checkFileAccess verifies the output of fileAccessScript for a session
// that must run as host uid:gid.
func checkFileAccess(t testing.TB, label, output string, uid, gid uint32, groupDir, denied bool) {
	t.Helper()
	v := parseKeyValues(output)
	ids := fmt.Sprintf("%d:%d", uid, gid)
	want := map[string]string{
		"uid": strconv.FormatUint(uint64(uid), 10), "gid": strconv.FormatUint(uint64(gid), 10),
		"owner": ids, "fileowner": ids, "traverse": "ok", "read": "hello", "write": "written",
		"created": ids, "deleted": "yes", "exec": "ok",
		"CapEff": "0000000000000000", "CapBnd": "0000000000000000", "NoNewPrivs": "1",
	}
	if groupDir {
		want["groupaccess"] = "yes"
	}
	if denied {
		want["denied"] = "yes"
	}
	for key, expected := range want {
		if v[key] != expected {
			t.Errorf("%s: %s=%q, want %q\n%s", label, key, v[key], expected, output)
		}
	}
	t.Logf("%s:\n%s", label, output)
}

// inheritedScenario runs inside the emulated nested namespace. It opens a
// session with the default credential and one with the explicit host
// identity (the configuration that used to resolve to the wrong host UID),
// runs fileAccessScript in each and reports an Inspect summary.
func inheritedScenario(ctx context.Context) int {
	dir, groupDir, denied := os.Getenv("SESSIONNET_TEST_DIR"), os.Getenv("SESSIONNET_GROUP_DIR"), os.Getenv("SESSIONNET_DENIED_DIR")
	hostUID, err1 := strconv.ParseUint(os.Getenv("SESSIONNET_EXPECT_HOST_UID"), 10, 32)
	hostGID, err2 := strconv.ParseUint(os.Getenv("SESSIONNET_EXPECT_HOST_GID"), 10, 32)
	if err1 != nil || err2 != nil {
		return report(fmt.Errorf("scenario setup: expected host identity missing"), "")
	}
	var out strings.Builder
	for _, cred := range []*Credential{nil, {UID: uint32(hostUID), GID: uint32(hostGID)}} {
		text, err := runSessionScript(ctx, Config{Credential: cred, IPv6: true}, fileAccessScript(dir, groupDir, denied))
		if err != nil {
			return report(err, out.String())
		}
		out.WriteString("SESSION\n" + text)
	}
	r := Inspect(ctx, Config{IPv6: true})
	summary, _ := json.Marshal(r)
	out.WriteString("REPORT " + string(summary) + "\n")
	return report(nil, out.String())
}

func runSessionScript(ctx context.Context, cfg Config, script string) (string, error) {
	s, err := Open(ctx, cfg)
	if err != nil {
		return "", err
	}
	defer s.Close()
	if err := s.Release(); err != nil {
		return "", err
	}
	var out lockedBuffer
	p, err := s.Spawn(ctx, Config{Command: []string{"/bin/sh", "-c", script}, Stdout: &out, Stderr: &out})
	if err != nil {
		return "", err
	}
	if err := p.Wait(); err != nil {
		return out.String(), fmt.Errorf("session script: %w\n%s", err, out.String())
	}
	return out.String(), nil
}

func checkInheritedOutput(t *testing.T, output string, uid, gid uint32, groupDir, denied bool, wantSetgroups string) {
	t.Helper()
	sessions := strings.Split(output, "SESSION\n")
	if len(sessions) != 3 {
		t.Fatalf("expected two sessions:\n%s", output)
	}
	for i, label := range []string{"default credential", "explicit host credential"} {
		text := sessions[i+1]
		if before, _, ok := strings.Cut(text, "REPORT "); ok {
			text = before
		}
		checkFileAccess(t, label, text, uid, gid, groupDir, denied)
		v := parseKeyValues(text)
		// The caller is root of its namespace, which stands for the host
		// identity, so the session maps host UID to UID 0 ("1009 0 1").
		if want := fmt.Sprintf("%d %d 1", uid, 0); v["uidmap"] != want {
			t.Errorf("%s: uid_map %q", label, v["uidmap"])
		}
		if v["setgroups"] != wantSetgroups {
			t.Errorf("%s: setgroups=%q, want %q", label, v["setgroups"], wantSetgroups)
		}
	}
	_, reportJSON, ok := strings.Cut(output, "REPORT ")
	if !ok {
		t.Fatalf("no inspect report:\n%s", output)
	}
	var r Report
	if err := json.Unmarshal([]byte(strings.TrimSpace(reportJSON)), &r); err != nil {
		t.Fatal(err)
	}
	if r.Namespace == nil || r.Namespace.Initial || r.Namespace.Depth != 1 || r.HostUID == nil || *r.HostUID != uid ||
		r.HostGID == nil || *r.HostGID != gid || !r.IdentityVerified || !r.InheritsGroups ||
		r.Credential == nil || r.Credential.UID != uid || r.Features.Supervisor != FeatureAvailable || r.Features.IPv6 != FeatureAvailable {
		t.Fatalf("inspect report: %s", reportJSON)
	}
	t.Logf("inspect report: %s", reportJSON)
}

func TestNestedNamespaceIdentity(t *testing.T) {
	requireRootless(t)
	ns, err := CurrentUserNamespace()
	if err != nil || !ns.Initial {
		t.Skip("emulates a nested namespace from the initial one; see TestInheritedNamespaceInPlace")
	}
	uid, gid := uint32(os.Geteuid()), uint32(os.Getegid())
	dir := t.TempDir()
	prepareAccessDir(t, dir)
	groupDir, denied := os.Getenv("SESSIONNET_GROUP_DIR"), os.Getenv("SESSIONNET_DENIED_DIR")
	if denied == "" {
		if info, err := os.Stat("/root"); err == nil && info.Mode().Perm()&0o007 == 0 {
			denied = "/root"
		}
	}
	cmd := exec.Command(os.Args[0], "-test.run=^$")
	cmd.Env = append(os.Environ(), "SESSIONNET_TEST_MODE=scenario:inherited", "SESSIONNET_TEST_DIR="+dir,
		"SESSIONNET_DENIED_DIR="+denied, fmt.Sprintf("SESSIONNET_EXPECT_HOST_UID=%d", uid), fmt.Sprintf("SESSIONNET_EXPECT_HOST_GID=%d", gid))
	// Root of the namespace is the test user, as in `podman unshare`.
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags:  syscall.CLONE_NEWUSER,
		UidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: int(uid), Size: 1}},
		GidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: int(gid), Size: 1}},
	}
	cmd.Stdin = strings.NewReader("go\n")
	output, err := cmd.CombinedOutput()
	r := scenarioFromOutput(t, output, err)
	if !r.OK {
		t.Fatalf("nested session failed: %+v", r)
	}
	checkInheritedOutput(t, r.Output, uid, gid, groupDir != "", denied != "", "deny")
	// The host still sees the files as the test user's, and nothing leaked.
	checkHostOwnership(t, dir, uid, gid)
}

func scenarioFromOutput(t *testing.T, output []byte, err error) scenarioResult {
	t.Helper()
	for _, line := range strings.Split(string(output), "\n") {
		if strings.HasPrefix(line, "RESULT ") {
			var r scenarioResult
			if err := json.Unmarshal([]byte(strings.TrimPrefix(line, "RESULT ")), &r); err != nil {
				t.Fatal(err)
			}
			return r
		}
	}
	t.Fatalf("scenario produced no result (%v):\n%s", err, output)
	return scenarioResult{}
}

func checkHostOwnership(t *testing.T, dir string, uid, gid uint32) {
	t.Helper()
	for _, name := range []string{".", "file", "run.sh"} {
		var st syscall.Stat_t
		if err := syscall.Stat(filepath.Join(dir, name), &st); err != nil {
			t.Fatal(err)
		}
		if st.Uid != uid || st.Gid != gid {
			t.Errorf("host ownership of %s changed to %d:%d", name, st.Uid, st.Gid)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "new")); !os.IsNotExist(err) {
		t.Errorf("the session's file was not deleted: %v", err)
	}
}

func TestInheritedNamespaceInPlace(t *testing.T) {
	ns, err := CurrentUserNamespace()
	if err != nil {
		t.Fatal(err)
	}
	if ns.Initial {
		if os.Getenv("SESSIONNET_REQUIRE_INHERITED") == "1" {
			t.Fatal("the test must run inside an inherited user namespace")
		}
		t.Skip("not running inside an inherited user namespace")
	}
	requireRootless(t)
	uid, err1 := strconv.ParseUint(os.Getenv("SESSIONNET_EXPECT_HOST_UID"), 10, 32)
	gid, err2 := strconv.ParseUint(os.Getenv("SESSIONNET_EXPECT_HOST_GID"), 10, 32)
	if err1 != nil || err2 != nil {
		t.Fatal("set SESSIONNET_EXPECT_HOST_UID and SESSIONNET_EXPECT_HOST_GID to the host identity")
	}
	dir := os.Getenv("SESSIONNET_TEST_DIR")
	if dir == "" {
		dir = t.TempDir()
	}
	prepareAccessDir(t, dir)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	t.Logf("namespace: depth %d, uid_map %q, gid_map %q, setgroups allowed %v", ns.Depth, ns.UIDMap.String(), ns.GIDMap.String(), ns.SetgroupsAllowed)
	_ = os.Setenv("SESSIONNET_TEST_DIR", dir)
	var out strings.Builder
	code := captureStdout(t, &out, func() int { return inheritedScenario(ctx) })
	if code != 0 {
		t.Fatalf("scenario exited %d", code)
	}
	r := scenarioFromOutput(t, []byte(out.String()), nil)
	if !r.OK {
		t.Fatalf("inherited session failed: %+v", r)
	}
	setgroups := "deny"
	checkInheritedOutput(t, r.Output, uint32(uid), uint32(gid), os.Getenv("SESSIONNET_GROUP_DIR") != "", os.Getenv("SESSIONNET_DENIED_DIR") != "", setgroups)
	// Inside the namespace the files belong to the namespace UID that
	// stands for the host identity.
	nsUID, _ := ns.NamespaceUID(uint32(uid))
	nsGID, _ := ns.NamespaceGID(uint32(gid))
	checkHostOwnership(t, dir, nsUID, nsGID)
}

// captureStdout runs fn with os.Stdout redirected into out.
func captureStdout(t *testing.T, out *strings.Builder, fn func() int) int {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	saved := os.Stdout
	os.Stdout = w
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 32<<10)
		for {
			n, err := r.Read(buf)
			out.Write(buf[:n])
			if err != nil {
				return
			}
		}
	}()
	code := fn()
	os.Stdout = saved
	_ = w.Close()
	<-done
	_ = r.Close()
	return code
}
