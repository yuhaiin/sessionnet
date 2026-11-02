//go:build linux

package sessionnet

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"
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

func TestLinuxDNSIsolation(t *testing.T) {
	if os.Getenv("SESSIONNET_INTEGRATION") != "1" {
		t.Skip("set SESSIONNET_INTEGRATION=1 on a namespace-capable Linux host")
	}
	original, err := os.ReadFile("/etc/nsswitch.conf")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var output bytes.Buffer
	s, err := Open(ctx, Config{Command: []string{"/bin/sh", "-c", "cat /etc/nsswitch.conf; cat /etc/resolv.conf"}, Credential: unprivileged(), IsolateDNS: true, Stdout: &output})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.Release(); err != nil {
		t.Fatal(err)
	}
	if err := s.Wait(); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(output.String(), isolatedNSS(string(original))) || !strings.Contains(output.String(), "nameserver "+GatewayIPv4) {
		t.Fatalf("isolated DNS configuration: %s", output.String())
	}
	after, err := os.ReadFile("/etc/nsswitch.conf")
	if err != nil || !bytes.Equal(original, after) {
		t.Fatal("host NSS configuration changed")
	}
}

func TestLinuxSessionSignal(t *testing.T) {
	if os.Getenv("SESSIONNET_INTEGRATION") != "1" {
		t.Skip("set SESSIONNET_INTEGRATION=1 on a namespace-capable Linux host")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	s, err := Open(ctx, Config{Command: []string{"/bin/sleep", "30"}, Credential: unprivileged()})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.Release(); err != nil {
		t.Fatal(err)
	}
	if err := s.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	var exit *exec.ExitError
	if err := s.Wait(); !errors.As(err, &exit) || exit.Sys().(syscall.WaitStatus).Signal() != syscall.SIGTERM {
		t.Fatalf("signal exit: %v", err)
	}
	if err := s.Signal(syscall.SIGTERM); !errors.Is(err, os.ErrProcessDone) {
		t.Fatalf("signaling a reaped process: %v", err)
	}
}

func BenchmarkLinuxSessionLifecycle(b *testing.B) {
	if os.Getenv("SESSIONNET_INTEGRATION") != "1" {
		b.Skip("set SESSIONNET_INTEGRATION=1 on a namespace-capable Linux host")
	}
	for _, isolate := range []bool{false, true} {
		name := "ResolverOnly"
		if isolate {
			name = "IsolatedNSS"
		}
		b.Run(name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				s, err := Open(context.Background(), Config{Command: []string{"/bin/true"}, Credential: unprivileged(), IsolateDNS: isolate})
				if err != nil {
					b.Fatal(err)
				}
				if err := s.Release(); err != nil {
					_ = s.Close()
					b.Fatal(err)
				}
				if err := s.Wait(); err != nil {
					_ = s.Close()
					b.Fatal(err)
				}
				if err := s.Close(); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
