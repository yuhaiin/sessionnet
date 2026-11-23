//go:build linux

package sessionnet

import (
	"strings"
	"testing"
)

func TestIsolatedNSSPreservesAccountDatabases(t *testing.T) {
	input := "# configuration\npasswd: files systemd\ngroup: files [SUCCESS=merge] systemd\nhosts: resolve [!UNAVAIL=return] files dns\n hosts : mdns\n"
	got := isolatedNSS(input)
	for _, preserved := range []string{"# configuration\n", "passwd: files systemd\n", "group: files [SUCCESS=merge] systemd\n"} {
		if !strings.Contains(got, preserved) {
			t.Fatalf("missing %q in %q", preserved, got)
		}
	}
	if strings.Contains(got, "resolve") || strings.Contains(got, "mdns") || strings.Count(got, "hosts:") != 1 {
		t.Fatalf("host resolver bypass remains: %q", got)
	}
	if !strings.HasSuffix(got, "hosts: files dns\n") || isolatedNSS(got) != got {
		t.Fatalf("invalid or non-idempotent NSS configuration: %q", got)
	}
}

func TestIsolatedNSSWithoutExistingConfiguration(t *testing.T) {
	if got := isolatedNSS(""); got != "hosts: files dns\n" {
		t.Fatal(got)
	}
}

func BenchmarkIsolatedNSS(b *testing.B) {
	input := "passwd: files systemd\ngroup: files systemd\nhosts: resolve files dns\nnetworks: files\n"
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = isolatedNSS(input)
	}
}
