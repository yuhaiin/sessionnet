package sessionnet

import (
	"strconv"
	"strings"
	"testing"
)

// podmanMap is the map `podman unshare` installs for a user with UID 1009
// and /etc/subuid "689824:65536".
const podmanMap = "         0       1009          1\n         1     689824      65536\n"

func mustParse(t testing.TB, text string) IDMap {
	t.Helper()
	m, err := ParseIDMap([]byte(text))
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestParseIDMap(t *testing.T) {
	m := mustParse(t, podmanMap)
	want := IDMap{{0, 1009, 1}, {1, 689824, 65536}}
	if len(m) != 2 || m[0] != want[0] || m[1] != want[1] {
		t.Fatalf("got %+v", m)
	}
	if m.String() != "0 1009 1\n1 689824 65536\n" {
		t.Fatalf("String: %q", m.String())
	}
	if !mustParse(t, "0 0 4294967295\n").IsIdentity() || m.IsIdentity() {
		t.Fatal("identity detection")
	}
	for name, text := range map[string]string{
		"empty":                 "",
		"short line":            "0 1009\n",
		"long line":             "0 1009 1 2\n",
		"negative":              "0 -1 1\n",
		"too large":             "0 4294967296 1\n",
		"zero count":            "0 1009 0\n",
		"inside overflow":       "4294967295 0 2\n",
		"parent overflow":       "0 4294967295 2\n",
		"inside overlap":        "0 1000 10\n5 2000 10\n",
		"parent overlap":        "0 1000 10\n100 1005 10\n",
		"duplicate":             "0 1009 1\n0 1009 1\n",
		"inside overlap at end": "0 0 4294967295\n4294967294 4294967295 1\n",
	} {
		if _, err := ParseIDMap([]byte(text)); err == nil {
			t.Errorf("%s: %q was accepted", name, text)
		}
	}
	var many strings.Builder
	for i := range maxIDMapExtents + 1 {
		many.WriteString(strings.Repeat(" ", i%3))
		many.WriteString(strconv.Itoa(i) + " " + strconv.Itoa(i+100000) + " 1\n")
	}
	if _, err := ParseIDMap([]byte(many.String())); err == nil {
		t.Error("more than 340 ranges were accepted")
	}
}

func TestIDMapTranslation(t *testing.T) {
	cases := []struct {
		name   string
		m      IDMap
		inside uint32
		parent uint32
		ok     bool
	}{
		{"identity", IdentityIDMap(), 1009, 1009, true},
		{"identity top", IdentityIDMap(), 4294967294, 4294967294, true},
		{"identity excludes -1", IdentityIDMap(), 4294967295, 0, false},
		{"single range", IDMap{{1009, 0, 1}}, 1009, 0, true},
		{"single range miss", IDMap{{1009, 0, 1}}, 1010, 0, false},
		{"podman root", mustParse(t, podmanMap), 0, 1009, true},
		{"podman first subordinate", mustParse(t, podmanMap), 1, 689824, true},
		{"podman 1009", mustParse(t, podmanMap), 1009, 690832, true},
		{"podman last", mustParse(t, podmanMap), 65536, 755359, true},
		{"podman past end", mustParse(t, podmanMap), 65537, 0, false},
		{"non-contiguous gap", IDMap{{0, 100, 10}, {20, 300, 10}}, 15, 0, false},
		{"non-contiguous second", IDMap{{0, 100, 10}, {20, 300, 10}}, 29, 309, true},
		{"range boundary start", IDMap{{10, 500, 5}}, 10, 500, true},
		{"range boundary end", IDMap{{10, 500, 5}}, 14, 504, true},
		{"range boundary past", IDMap{{10, 500, 5}}, 15, 0, false},
		{"range boundary before", IDMap{{10, 500, 5}}, 9, 0, false},
		{"max range no wrap", IDMap{{4294967290, 10, 5}}, 4294967294, 14, true},
	}
	for _, tc := range cases {
		got, ok := tc.m.ToParent(tc.inside)
		if ok != tc.ok || (ok && got != tc.parent) {
			t.Errorf("%s: ToParent(%d) = %d, %v; want %d, %v", tc.name, tc.inside, got, ok, tc.parent, tc.ok)
		}
		if !tc.ok {
			continue
		}
		back, ok := tc.m.FromParent(tc.parent)
		if !ok || back != tc.inside {
			t.Errorf("%s: FromParent(%d) = %d, %v; want %d", tc.name, tc.parent, back, ok, tc.inside)
		}
	}
	// Host IDs that the podman namespace does not map.
	for _, host := range []uint32{0, 100, 1000, 1008, 1010, 689823, 755360} {
		if id, ok := mustParse(t, podmanMap).FromParent(host); ok {
			t.Errorf("host ID %d must be unmapped, got %d", host, id)
		}
	}
}

func TestIDMapNestedChain(t *testing.T) {
	// A toolbox-like container keeps the user's ID (1009 -> 1009) and maps
	// subordinate IDs; `podman unshare` inside it maps 0 -> 1009 again.
	outer := IDMap{{0, 100000, 1009}, {1009, 1009, 1}, {1010, 101009, 700000}}
	inner := mustParse(t, podmanMap)
	// Innermost namespace UID 0 is host UID 1009.
	if host, ok := ResolveIDChain(0, inner, outer); !ok || host != 1009 {
		t.Fatalf("ResolveIDChain(0) = %d, %v", host, ok)
	}
	// Innermost UID 1 -> outer 689824 -> host 689824-1010+101009.
	if host, ok := ResolveIDChain(1, inner, outer); !ok || host != 689824-1010+101009 {
		t.Fatalf("ResolveIDChain(1) = %d, %v", host, ok)
	}
	if id, ok := LookupIDChain(1009, inner, outer); !ok || id != 0 {
		t.Fatalf("LookupIDChain(1009) = %d, %v", id, ok)
	}
	// Host UID 100500 is mapped by the outer level only.
	if _, ok := LookupIDChain(100500, inner, outer); ok {
		t.Fatal("an ID unmapped at one level must not resolve")
	}
	if _, ok := ResolveIDChain(70000, inner, outer); ok {
		t.Fatal("an ID unmapped at the innermost level must not resolve")
	}
	if id, ok := ResolveIDChain(42); !ok || id != 42 {
		t.Fatal("an empty chain is the identity")
	}
}

func TestUserNamespaceHostTranslation(t *testing.T) {
	podman := UserNamespace{Depth: 1, UIDMap: mustParse(t, podmanMap), GIDMap: IDMap{{0, 1009, 1}, {1, 700000, 10}}}
	if id, ok := podman.NamespaceUID(1009); !ok || id != 0 {
		t.Fatalf("NamespaceUID(1009) = %d, %v", id, ok)
	}
	if id, ok := podman.HostUID(0); !ok || id != 1009 {
		t.Fatalf("HostUID(0) = %d, %v", id, ok)
	}
	// UID and GID maps are independent.
	if id, ok := podman.HostGID(1); !ok || id != 700000 {
		t.Fatalf("HostGID(1) = %d, %v", id, ok)
	}
	if id, ok := podman.HostUID(1); !ok || id != 689824 {
		t.Fatalf("HostUID(1) = %d, %v", id, ok)
	}
	if _, ok := podman.NamespaceGID(100); ok {
		t.Fatal("host GID 100 (users) is not mapped by podman")
	}
	deeper := podman
	deeper.Depth = 2
	if _, ok := deeper.HostUID(0); ok || deeper.HostIDs() {
		t.Fatal("a namespace nested twice must not claim host IDs")
	}
	unknown := podman
	unknown.Depth = -1
	if _, ok := unknown.NamespaceUID(1009); ok {
		t.Fatal("an unmeasured depth must not resolve host IDs")
	}
	initial := UserNamespace{Initial: true, UIDMap: IdentityIDMap(), GIDMap: IdentityIDMap()}
	if id, ok := initial.NamespaceUID(1009); !ok || id != 1009 || !initial.HostIDs() {
		t.Fatal("the initial namespace uses host IDs")
	}
}

func BenchmarkIDMapToParent(b *testing.B) {
	podman := mustParse(b, podmanMap)
	var wide IDMap
	for i := range uint32(maxIDMapExtents) {
		wide = append(wide, IDMapping{NamespaceID: i * 10, ParentID: 1_000_000 + i*10, Count: 10})
	}
	b.Run("podman", func(b *testing.B) {
		for i := 0; b.Loop(); i++ {
			_, _ = podman.ToParent(uint32(i) & 0xffff)
		}
	})
	b.Run("340-ranges-last", func(b *testing.B) {
		for b.Loop() {
			_, _ = wide.ToParent(3395)
		}
	})
	b.Run("340-ranges-miss", func(b *testing.B) {
		for b.Loop() {
			_, _ = wide.FromParent(1)
		}
	})
}

func BenchmarkParseIDMap(b *testing.B) {
	data := []byte(podmanMap)
	for b.Loop() {
		if _, err := ParseIDMap(data); err != nil {
			b.Fatal(err)
		}
	}
}
