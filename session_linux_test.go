//go:build linux

package sessionnet

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

func unprivileged() *Credential {
	return &Credential{UID: 65534, GID: 65534}
}

func TestValidation(t *testing.T) {
	tests := []struct {
		name     string
		cfg      Config
		contains string
	}{
		{"missing command", Config{Credential: unprivileged()}, "command"},
		{"missing account", Config{Command: []string{"/bin/true"}}, "unprivileged"},
		{"root account", Config{Command: []string{"/bin/true"}, Credential: &Credential{UID: 0, GID: 0}}, "unprivileged"},
		{"privileged group", Config{Command: []string{"/bin/true"}, Credential: &Credential{UID: 65534, GID: 65534, Groups: []uint32{0}}}, "supplementary root group"},
		{"bad mtu", Config{Command: []string{"/bin/true"}, Credential: unprivileged(), MTU: 9001}, "MTU"},
		{"small mtu", Config{Command: []string{"/bin/true"}, Credential: unprivileged(), MTU: 1279}, "MTU"},
		{"valid lower mtu", Config{Command: []string{"/bin/true"}, Credential: unprivileged(), MTU: 1280}, ""},
		{"valid upper mtu", Config{Command: []string{"/bin/true"}, Credential: unprivileged(), MTU: 9000}, ""},
		{"pty and stdin", Config{Command: []string{"/bin/true"}, Credential: unprivileged(), PTYSlave: os.Stdin, Stdin: os.Stdin}, "PTYSlave"},
		{"valid", Config{Command: []string{"/bin/true"}, Credential: unprivileged()}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validate(tt.cfg)
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

func TestInterfaceName(t *testing.T) {
	a, err := randomInterfaceName()
	if err != nil {
		t.Fatal(err)
	}
	b, err := randomInterfaceName()
	if err != nil {
		t.Fatal(err)
	}
	if len(a) > 15 || len(a) == 0 || a == b {
		t.Fatalf("interface names invalid %q %q", a, b)
	}
}

// Integration requires Linux with CAP_SYS_ADMIN, CAP_NET_ADMIN, /dev/net/tun,
// iproute2, util-linux and mount permissions. CI without privileges skips.
func TestLinuxSessionIntegration(t *testing.T) {
	if testing.Short() || os.Getenv("SESSIONNET_INTEGRATION") != "1" {
		t.Skip("set SESSIONNET_INTEGRATION=1 on an appropriately privileged Linux host")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var out strings.Builder
	s, err := Open(ctx, Config{Command: []string{"/bin/sh", "-c", "ip route; cat /etc/resolv.conf"}, Credential: unprivileged(), Stdout: &out})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	fd, err := s.DupTun()
	if err != nil {
		t.Fatal(err)
	}
	defer fd.Close()
	if err := s.Release(); err != nil {
		t.Fatal(err)
	}
	if err := s.Release(); err == nil {
		t.Fatal("second release must fail")
	}
	if err := s.Wait(); err != nil && !errors.Is(err, os.ErrClosed) {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "default dev ") || !strings.Contains(out.String(), GatewayIPv4) {
		t.Fatalf("bad isolated output: %q", out.String())
	}
}

// The start gate must prevent command execution before the application's packet
// processing stack has been initialized. This integration test is opt-in.
func TestLinuxStartGate(t *testing.T) {
	if testing.Short() || os.Getenv("SESSIONNET_INTEGRATION") != "1" {
		t.Skip("set SESSIONNET_INTEGRATION=1 on an appropriately privileged Linux host")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	dir, err := os.MkdirTemp("", "sessionnet-gate-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	if err := os.Chmod(dir, 0777); err != nil {
		t.Fatal(err)
	}
	marker := dir + "/started"
	s, err := Open(ctx, Config{
		Command:    []string{"/bin/sh", "-c", "echo started > \"$1\"", "gate", marker},
		Credential: unprivileged(),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("command ran before release: %v", err)
	}
	if err := s.Release(); err != nil {
		t.Fatal(err)
	}
	if err := s.Wait(); err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(marker)
	if err != nil || string(content) != "started\n" {
		t.Fatalf("unexpected command output %q: %v", string(content), err)
	}
}
