//go:build linux

package sessionnet

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
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
	got, err := resolveCredential(ModeRootless, nil)
	if err != nil || got.UID != uint32(os.Geteuid()) || got.GID != uint32(os.Getegid()) {
		t.Fatalf("rootless default credential: %+v %v", got, err)
	}
	if _, err := resolveCredential(ModeRootful, nil); err == nil {
		t.Fatal("rootful mode requires an explicit credential")
	}
}

func TestPlanIDMaps(t *testing.T) {
	user := identity{uid: 1000, gid: 1000, username: "alice"}
	withSub := user
	withSub.subUIDs, withSub.subGIDs = []idRange{{100000, 65536}}, []idRange{{100000, 65536}}
	withSub.newuidmap, withSub.newgidm = "/usr/bin/newuidmap", "/usr/bin/newgidmap"
	root := identity{canSetUID: true, canSetGID: true}
	cases := []struct {
		name      string
		self      identity
		cred      Credential
		stage     Stage
		uidTool   bool
		gidTool   bool
		setGroups bool
		gidLines  int
	}{
		{"own IDs map directly and keep groups", user, Credential{UID: 1000, GID: 1000}, "", false, false, false, 1},
		{"other UID without newuidmap", user, Credential{UID: 1001, GID: 1000}, StageUIDMap, false, false, false, 0},
		{"other GID without newgidmap", user, Credential{UID: 1000, GID: 1001}, StageGIDMap, false, false, false, 0},
		{"groups need setgroups", user, Credential{UID: 1000, GID: 1000, Groups: []uint32{27}}, StageGIDMap, false, false, false, 0},
		{"subordinate UID uses newuidmap", withSub, Credential{UID: 100005, GID: 1000}, "", true, false, false, 1},
		{"subordinate GID uses newgidmap", withSub, Credential{UID: 1000, GID: 100005}, "", false, true, true, 1},
		{"subordinate UID outside range", withSub, Credential{UID: 200000, GID: 1000}, StageUIDMap, false, false, false, 0},
		{"privileged caller maps any ID and groups", root, Credential{UID: 65534, GID: 65534, Groups: []uint32{100, 65534}}, "", false, false, true, 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			plan, err := planIDMaps(tc.self, tc.cred)
			if tc.stage != "" {
				var setup *SetupError
				if !errors.As(err, &setup) || setup.Stage != tc.stage {
					t.Fatalf("expected %s failure, got %v", tc.stage, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if (plan.uidTool != "") != tc.uidTool || (plan.gidTool != "") != tc.gidTool || plan.setGroups != tc.setGroups || len(plan.gidLines) != tc.gidLines {
				t.Fatalf("plan %+v", plan)
			}
			if want := fmt.Sprintf("%d %d 1", tc.cred.UID, tc.cred.UID); plan.uidLines[0] != want {
				t.Fatalf("mappings must be identity mappings: %v", plan.uidLines)
			}
		})
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
