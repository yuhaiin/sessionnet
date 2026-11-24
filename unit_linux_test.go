//go:build linux

package sessionnet

import (
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
)

func unprivileged() *Credential { return &Credential{UID: 65534, GID: 65534} }

func TestValidation(t *testing.T) {
	cred := Credential{UID: 65534, GID: 65534}
	tests := []struct {
		name     string
		mode     Mode
		cfg      Config
		cred     Credential
		contains string
	}{
		{"empty command", ModeRootless, Config{Command: []string{}}, cred, "command"},
		{"blank command", ModeRootless, Config{Command: []string{" "}}, cred, "command"},
		{"no command is an idle session", ModeRootless, Config{}, cred, ""},
		{"rootful root account", ModeRootful, Config{Command: []string{"/bin/true"}}, Credential{}, "unprivileged"},
		{"rootful root group", ModeRootful, Config{Command: []string{"/bin/true"}}, Credential{UID: 65534, GID: 65534, Groups: []uint32{0}}, "supplementary root group"},
		{"rootless root account", ModeRootless, Config{Command: []string{"/bin/true"}}, Credential{}, ""},
		{"rootless root group", ModeRootless, Config{Command: []string{"/bin/true"}}, Credential{UID: 65534, GID: 65534, Groups: []uint32{0}}, ""},
		{"bad mtu", ModeRootless, Config{Command: []string{"/bin/true"}, MTU: 9001}, cred, "MTU"},
		{"small mtu", ModeRootless, Config{Command: []string{"/bin/true"}, MTU: 1279}, cred, "MTU"},
		{"valid lower mtu", ModeRootless, Config{Command: []string{"/bin/true"}, MTU: 1280}, cred, ""},
		{"valid upper mtu", ModeRootless, Config{Command: []string{"/bin/true"}, MTU: 9000}, cred, ""},
		{"pty and stdin", ModeRootless, Config{Command: []string{"/bin/true"}, PTYSlave: os.Stdin, Stdin: os.Stdin}, cred, "PTYSlave"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validate(tt.cfg, tt.mode, tt.cred)
			if tt.contains == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.contains) {
				t.Fatalf("got %v, expected %q", err, tt.contains)
			}
		})
	}
}

func TestModeResolve(t *testing.T) {
	for in, want := range map[Mode]Mode{"": ModeRootless, ModeRootless: ModeRootless, ModeRootful: ModeRootful} {
		if got, err := in.Resolve(); err != nil || got != want {
			t.Fatalf("%q: %q %v", in, got, err)
		}
	}
	if _, err := Mode("auto").Resolve(); err == nil {
		t.Fatal("unknown modes must be rejected")
	}
}

func TestResolveCredential(t *testing.T) {
	self := identity{Caller: Caller{UID: 0, GID: 0}, ns: podmanNamespace()}
	got, err := resolveCredential(ModeRootless, nil, self)
	if err != nil || got.UID != 1009 || got.GID != 1009 {
		t.Fatalf("rootless default credential must be the caller's host identity: %+v %v", got, err)
	}
	if _, err := resolveCredential(ModeRootful, nil, self); err == nil {
		t.Fatal("rootful mode requires an explicit credential")
	}
	explicit := &Credential{UID: 5, GID: 6, Groups: []uint32{7}}
	got, err = resolveCredential(ModeRootless, explicit, self)
	if err != nil || got.UID != 5 || got.GID != 6 || len(got.Groups) != 1 {
		t.Fatalf("explicit credential: %+v %v", got, err)
	}
	got.Groups[0] = 8
	if explicit.Groups[0] != 7 {
		t.Fatal("the resolved credential must not alias the caller's slice")
	}
}

func initialNamespace() UserNamespace {
	return UserNamespace{Initial: true, UIDMap: IdentityIDMap(), GIDMap: IdentityIDMap(), SetgroupsAllowed: true}
}

// podmanNamespace is the namespace `podman unshare` creates for host user
// 1009 with /etc/subuid and /etc/subgid "example-user:689824:65536".
func podmanNamespace() UserNamespace {
	m := IDMap{{0, 1009, 1}, {1, 689824, 65536}}
	return UserNamespace{Depth: 1, UIDMap: m, GIDMap: m, SetgroupsAllowed: true}
}

func allCapsCaller(uid, gid uint32) Caller {
	return Caller{UID: uid, GID: gid, CapSetUID: true, CapSetGID: true, CapSetFCAP: true, CapSysAdm: true, CapNetAdm: true}
}

func TestPlanIDMaps(t *testing.T) {
	user := identity{Caller: Caller{UID: 1000, GID: 1000}, ns: initialNamespace(), username: "alice"}
	withSub := user
	withSub.subUIDs, withSub.subGIDs = []idRange{{100000, 65536}}, []idRange{{100000, 65536}}
	withSub.newuidmap, withSub.newgidm = "/usr/bin/newuidmap", "/usr/bin/newgidmap"
	root := identity{Caller: allCapsCaller(0, 0), ns: initialNamespace()}
	podman := identity{Caller: allCapsCaller(0, 0), ns: podmanNamespace()}
	podmanNoFCAP := podman
	podmanNoFCAP.CapSetFCAP = false
	podmanDenied := podman
	podmanDenied.ns.SetgroupsAllowed = false
	// Rootless podman with its subordinate range, but Yuhaiin running as a
	// non-root user of it without capabilities.
	podmanUser := identity{Caller: Caller{UID: 1000, GID: 1000}, ns: podmanNamespace()}
	nested := identity{Caller: allCapsCaller(0, 0), ns: podmanNamespace()}
	nested.ns.Depth = 2
	unknown := nested
	unknown.ns.Depth, unknown.ns.DepthError = -1, "probe failed"
	cases := []struct {
		name      string
		self      identity
		cred      Credential
		stage     Stage
		uidLine   string
		gidLines  []string
		uidTool   bool
		gidTool   bool
		setGroups bool
		message   string
	}{
		{name: "native own IDs keep groups", self: user, cred: Credential{UID: 1000, GID: 1000}, uidLine: "1000 1000 1", gidLines: []string{"1000 1000 1"}},
		{name: "native other UID without newuidmap", self: user, cred: Credential{UID: 1001, GID: 1000}, stage: StageUIDMap, message: "Yuhaiin user (UID 1000) only"},
		{name: "native other GID without newgidmap", self: user, cred: Credential{UID: 1000, GID: 1001}, stage: StageGIDMap},
		{name: "native groups need setgroups", self: user, cred: Credential{UID: 1000, GID: 1000, Groups: []uint32{27}}, stage: StageGIDMap},
		{name: "native subordinate UID uses newuidmap", self: withSub, cred: Credential{UID: 100005, GID: 1000}, uidLine: "100005 100005 1", gidLines: []string{"1000 1000 1"}, uidTool: true},
		{name: "native subordinate GID uses newgidmap", self: withSub, cred: Credential{UID: 1000, GID: 100005}, uidLine: "1000 1000 1", gidLines: []string{"100005 100005 1"}, gidTool: true, setGroups: true},
		{name: "native subordinate UID outside range", self: withSub, cred: Credential{UID: 200000, GID: 1000}, stage: StageUIDMap},
		{name: "native root maps any ID and replaces groups", self: root, cred: Credential{UID: 65534, GID: 65534, Groups: []uint32{100, 65534}}, uidLine: "65534 65534 1", gidLines: []string{"65534 65534 1", "100 100 1"}, setGroups: true},
		{name: "native root keeps its own groups", self: root, cred: Credential{UID: 0, GID: 0}, uidLine: "0 0 1", gidLines: []string{"0 0 1"}},

		// The reported bug: host UID 1009 is namespace UID 0, not 1009.
		{name: "podman host identity maps to namespace root", self: podman, cred: Credential{UID: 1009, GID: 1009}, uidLine: "1009 0 1", gidLines: []string{"1009 0 1"}},
		{name: "podman subordinate host ID", self: podman, cred: Credential{UID: 689824, GID: 689824}, uidLine: "689824 1 1", gidLines: []string{"689824 1 1"}, setGroups: true},
		{name: "podman supplementary groups translated", self: podman, cred: Credential{UID: 1009, GID: 1009, Groups: []uint32{689900}}, uidLine: "1009 0 1", gidLines: []string{"1009 0 1", "689900 77 1"}, setGroups: true},
		{name: "podman unmapped host UID", self: podman, cred: Credential{UID: 1000, GID: 1009}, stage: StageUIDMap, message: "host UID 1000 is not mapped"},
		{name: "podman unmapped host GID", self: podman, cred: Credential{UID: 1009, GID: 100}, stage: StageGIDMap, message: "host GID 100 is not mapped"},
		{name: "podman unmapped supplementary group", self: podman, cred: Credential{UID: 1009, GID: 1009, Groups: []uint32{100}}, stage: StageGIDMap, message: "host GID 100"},
		{name: "podman host root is unmapped", self: podman, cred: Credential{UID: 0, GID: 0}, stage: StageUIDMap, message: "host UID 0 is not mapped"},
		{name: "podman root without CAP_SETFCAP", self: podmanNoFCAP, cred: Credential{UID: 1009, GID: 1009}, stage: StageUIDMap, message: "CAP_SETFCAP"},
		{name: "podman subordinate without CAP_SETFCAP", self: podmanNoFCAP, cred: Credential{UID: 689824, GID: 1009}, uidLine: "689824 1 1", gidLines: []string{"1009 0 1"}, setGroups: true},
		{name: "podman setgroups denied keeps own groups", self: podmanDenied, cred: Credential{UID: 1009, GID: 1009}, uidLine: "1009 0 1", gidLines: []string{"1009 0 1"}},
		{name: "podman setgroups denied rejects groups", self: podmanDenied, cred: Credential{UID: 1009, GID: 1009, Groups: []uint32{689900}}, stage: StageGIDMap, message: "setgroups"},
		{name: "podman setgroups denied rejects other GID", self: podmanDenied, cred: Credential{UID: 1009, GID: 689900}, stage: StageGIDMap, message: "setgroups"},
		{name: "podman unprivileged user own identity", self: podmanUser, cred: Credential{UID: 690823, GID: 690823}, uidLine: "690823 1000 1", gidLines: []string{"690823 1000 1"}},
		{name: "podman unprivileged user other UID", self: podmanUser, cred: Credential{UID: 1009, GID: 690823}, stage: StageUIDMap, message: "CAP_SETUID"},

		{name: "nested twice own identity", self: nested, cred: Credential{UID: 0, GID: 0}, uidLine: "0 0 1", gidLines: []string{"0 0 1"}},
		{name: "nested twice rejects host IDs", self: nested, cred: Credential{UID: 1009, GID: 1009}, stage: StageUIDMap, message: "nesting depth 2"},
		{name: "unknown depth rejects other IDs", self: unknown, cred: Credential{UID: 0, GID: 5}, stage: StageGIDMap, message: "probe failed"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			plan, err := planIDMaps(tc.self, tc.cred)
			if tc.stage != "" {
				var setup *SetupError
				if !errors.As(err, &setup) || setup.Stage != tc.stage || !strings.Contains(setup.Message, tc.message) {
					t.Fatalf("expected %s failure containing %q, got %v", tc.stage, tc.message, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if (plan.uidTool != "") != tc.uidTool || (plan.gidTool != "") != tc.gidTool || plan.setGroups != tc.setGroups ||
				len(plan.uidLines) != 1 || plan.uidLines[0] != tc.uidLine || !slices.Equal(plan.gidLines, tc.gidLines) {
				t.Fatalf("plan %+v", plan)
			}
			if inside, _ := plan.uidMap.FromParent(mustParseLine(t, tc.uidLine)); inside != tc.cred.UID {
				t.Fatalf("uidMap %v does not translate back to %d", plan.uidMap, tc.cred.UID)
			}
		})
	}
}

func mustParseLine(t *testing.T, line string) uint32 {
	t.Helper()
	m := mustParse(t, line)
	return m[0].ParentID
}

func TestRootfulCredential(t *testing.T) {
	podman := identity{Caller: allCapsCaller(0, 0), ns: podmanNamespace()}
	got, err := rootfulCredential(podman, Credential{UID: 690823, GID: 690823, Groups: []uint32{689900}})
	if err != nil || got.UID != 1000 || got.GID != 1000 || !slices.Equal(got.Groups, []uint32{77}) {
		t.Fatalf("rootful credential in podman: %+v %v", got, err)
	}
	// Host 1009 is the namespace root: rootful sessions must not run as it.
	if _, err := rootfulCredential(podman, Credential{UID: 1009, GID: 1009}); err == nil || !strings.Contains(err.Error(), "root of the user namespace") {
		t.Fatalf("namespace root must be refused: %v", err)
	}
	if _, err := rootfulCredential(podman, Credential{UID: 1000, GID: 1000}); err == nil {
		t.Fatal("unmapped host IDs must be refused")
	}
	native := identity{Caller: allCapsCaller(0, 0), ns: initialNamespace()}
	if got, err := rootfulCredential(native, Credential{UID: 1000, GID: 1000}); err != nil || got.UID != 1000 {
		t.Fatalf("native rootful credential: %+v %v", got, err)
	}
}

func TestReadSubordinateIDs(t *testing.T) {
	path := filepath.Join(t.TempDir(), "subuid")
	if err := os.WriteFile(path, []byte("alice:100000:65536\nbob:200000:10\n1000:300000:5\nbroken\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	got := readSubordinateIDs(path, "alice", 1000)
	if len(got) != 2 || !got[0].contains(165535) || got[0].contains(165536) || !got[1].contains(300004) {
		t.Fatalf("%+v", got)
	}
}

func TestExitError(t *testing.T) {
	exited := &ExitError{Status: 3 << 8}
	if !exited.Exited() || exited.ExitCode() != 3 || exited.Signal() != 0 {
		t.Fatalf("%+v", exited)
	}
	killed := &ExitError{Status: uint32(syscall.SIGKILL)}
	if killed.Exited() || killed.ExitCode() != -1 || killed.Signal() != int(syscall.SIGKILL) {
		t.Fatalf("%+v", killed)
	}
}

func TestWireErrorKeepsErrno(t *testing.T) {
	w := newWireError(StageTUN, "cannot open", syscall.ENOENT)
	err := w.toError()
	var setup *SetupError
	if !errors.As(err, &setup) || setup.Stage != StageTUN || !errors.Is(err, syscall.ENOENT) {
		t.Fatalf("%v", err)
	}
}

func TestControlMessagesCarryDescriptors(t *testing.T) {
	parent, child, err := newSocketPair()
	if err != nil {
		t.Fatal(err)
	}
	defer parent.Close()
	peer, err := fileControlConn(child)
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	if err := parent.send(&message{Op: opSpawn, ID: 7}, r, w); err != nil {
		t.Fatal(err)
	}
	m, files, err := peer.receive()
	if err != nil {
		t.Fatal(err)
	}
	defer closeFiles(files)
	if m.Op != opSpawn || m.ID != 7 || len(files) != 2 {
		t.Fatalf("%+v %d", m, len(files))
	}
	if _, err := files[1].WriteString("x"); err != nil {
		t.Fatal(err)
	}
	var b [1]byte
	if _, err := r.Read(b[:]); err != nil || b[0] != 'x' {
		t.Fatal("received descriptor does not refer to the sent pipe")
	}
	// A peer closing its end is reported, not mistaken for a message.
	_ = parent.Close()
	if _, _, err := peer.receive(); err == nil {
		t.Fatal("closed peer must fail receive")
	}
}

func TestResolverTarget(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "real.conf")
	if err := os.WriteFile(file, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(file, link); err != nil {
		t.Fatal(err)
	}
	if target, parent, err := resolverTarget(link); err != nil || target != file || parent {
		t.Fatalf("%s %v %v", target, parent, err)
	}
	missing := filepath.Join(dir, "sub", "stub.conf")
	if err := os.Mkdir(filepath.Join(dir, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	dangling := filepath.Join(dir, "dangling")
	if err := os.Symlink(missing, dangling); err != nil {
		t.Fatal(err)
	}
	if target, parent, err := resolverTarget(dangling); err != nil || target != missing || !parent {
		t.Fatalf("%s %v %v", target, parent, err)
	}
	broken := filepath.Join(dir, "broken")
	if err := os.Symlink(filepath.Join(dir, "absent", "x"), broken); err != nil {
		t.Fatal(err)
	}
	if _, _, err := resolverTarget(broken); err == nil {
		t.Fatal("a resolver whose directory is missing must fail")
	}
}

var _ = netip.Addr{}

func TestAddressConfig(t *testing.T) {
	defaults, err := (AddressConfig{}).Resolve(true)
	if err != nil {
		t.Fatal(err)
	}
	if defaults.GatewayIPv4.String() != GatewayIPv4 || defaults.GatewayIPv6.String() != GatewayIPv6 {
		t.Fatalf("unexpected defaults: %+v", defaults)
	}
	if netip.MustParsePrefix("198.18.0.0/15").Overlaps(defaults.SessionIPv4.Masked()) ||
		netip.MustParsePrefix("2001:2::/48").Overlaps(defaults.SessionIPv6.Masked()) ||
		netip.MustParsePrefix("fd7a:115c:a1e0::/48").Overlaps(defaults.SessionIPv6.Masked()) {
		t.Fatal("session defaults must not overlap Yuhaiin FakeIP or Tailscale ranges")
	}
	custom := AddressConfig{
		GatewayIPv4: netip.MustParseAddr("10.250.250.1"),
		SessionIPv4: netip.MustParsePrefix("10.250.250.2/30"),
		GatewayIPv6: netip.MustParseAddr("fd22:3456:789a::1"),
		SessionIPv6: netip.MustParsePrefix("fd22:3456:789a::2/64"),
	}
	actual, err := custom.Resolve(true)
	if err != nil || actual != custom {
		t.Fatalf("custom addresses: %+v, %v", actual, err)
	}
	cases := []struct {
		name   string
		config AddressConfig
		ipv6   bool
	}{
		{"partial IPv4", AddressConfig{GatewayIPv4: custom.GatewayIPv4}, false},
		{"outside subnet", AddressConfig{GatewayIPv4: netip.MustParseAddr("10.250.250.5"), SessionIPv4: custom.SessionIPv4}, false},
		{"same endpoint", AddressConfig{GatewayIPv4: custom.SessionIPv4.Addr(), SessionIPv4: custom.SessionIPv4}, false},
		{"network address", AddressConfig{GatewayIPv4: netip.MustParseAddr("10.250.250.0"), SessionIPv4: custom.SessionIPv4}, false},
		{"IPv6 disabled", AddressConfig{GatewayIPv6: custom.GatewayIPv6, SessionIPv6: custom.SessionIPv6}, false},
		{"invalid v6", AddressConfig{GatewayIPv6: netip.MustParseAddr("fd22:3456:789a::3"), SessionIPv6: netip.MustParsePrefix("fd22:3456:789b::2/64")}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := tc.config.Resolve(tc.ipv6); err == nil {
				t.Fatal("expected address validation failure")
			}
		})
	}
}

func TestAppArmorUsernsMessageNamesExecutable(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}
	msg := appArmorUsernsMessage()
	if !strings.Contains(msg, "apparmor_restrict_unprivileged_userns=1") || !strings.Contains(msg, "userns,") || !strings.Contains(msg, exe) {
		t.Fatalf("AppArmor message lacks the remedy: %s", msg)
	}
}

// TestUsableIDsMatchPlanner checks that the advertised ranges agree with
// what planIDMaps accepts, for every probed ID.
func TestUsableIDsMatchPlanner(t *testing.T) {
	podman := identity{Caller: allCapsCaller(0, 0), ns: podmanNamespace()}
	podmanNoFCAP := podman
	podmanNoFCAP.CapSetFCAP = false
	podmanDenied := podman
	podmanDenied.ns.SetgroupsAllowed = false
	user := identity{Caller: Caller{UID: 1000, GID: 1000}, ns: initialNamespace(), username: "alice",
		subUIDs: []idRange{{100000, 10}}, subGIDs: []idRange{{200000, 10}}, newuidmap: "/x", newgidm: "/x"}
	nested := podman
	nested.ns.Depth = 2
	probes := []uint32{0, 1, 99, 100, 999, 1000, 1001, 1008, 1009, 1010, 99999, 100000, 100009, 100010, 199999, 200000,
		200009, 200010, 689823, 689824, 690000, 755359, 755360, 4294967294}
	for name, self := range map[string]identity{"podman": podman, "podman without CAP_SETFCAP": podmanNoFCAP,
		"podman setgroups denied": podmanDenied, "native user": user, "nested twice": nested} {
		uids, gids := self.usableUIDs(), self.usableGIDs()
		inRange := func(ranges []IDRange, id uint32) bool {
			return slices.ContainsFunc(ranges, func(r IDRange) bool { return r.Contains(id) })
		}
		own := self.defaultCredential()
		for _, id := range probes {
			_, err := planIDMaps(self, Credential{UID: id, GID: own.GID})
			if (err == nil) != inRange(uids, id) {
				t.Errorf("%s: UID %d: planner error %v, advertised %v", name, id, err, uids)
			}
			_, err = planIDMaps(self, Credential{UID: uids[0].Start, GID: id})
			if (err == nil) != inRange(gids, id) {
				t.Errorf("%s: GID %d: planner error %v, advertised %v", name, id, err, gids)
			}
		}
	}
	if got := podman.usableUIDs(); !slices.Equal(got, []IDRange{{1009, 1}, {689824, 65536}}) {
		t.Fatalf("podman UIDs %v", got)
	}
}
