//go:build linux

package sessionnet

import (
	"bytes"
	"context"
	"encoding/binary"
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
// and mount permissions. CI without privileges skips.
func TestLinuxSessionIntegration(t *testing.T) {
	if testing.Short() || os.Getenv("SESSIONNET_INTEGRATION") != "1" {
		t.Skip("set SESSIONNET_INTEGRATION=1 on an appropriately privileged Linux host")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var out strings.Builder
	s, err := Open(ctx, Config{Command: []string{"/bin/sh", "-c", "cat /proc/net/route; cat /etc/resolv.conf"}, Credential: unprivileged(), Stdout: &out})
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
	if !strings.Contains(out.String(), "00000000") || !strings.Contains(out.String(), GatewayIPv4) {
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

// This verifies that application traffic reaches the supervisor's TUN FD.
func TestLinuxTunPacketHandoff(t *testing.T) {
	if testing.Short() || os.Getenv("SESSIONNET_INTEGRATION") != "1" {
		t.Skip("set SESSIONNET_INTEGRATION=1 on an appropriately privileged Linux host")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	s, err := Open(ctx, Config{
		Command:    []string{"/bin/bash", "-c", "printf probe >/dev/udp/198.18.0.1/5353"},
		Credential: unprivileged(),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	fd, err := s.DupTun()
	if err != nil {
		t.Fatal(err)
	}
	defer fd.Close()
	// The kernel may emit unrelated packets, such as IPv6 neighbor
	// discovery traffic, immediately after the interface comes up.
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
	select {
	case err := <-result:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for the expected IPv4 UDP probe on TUN")
	}
	if err := s.Wait(); err != nil {
		t.Fatal(err)
	}
}

// matchesUDPProbe rejects unrelated interface traffic and checks that the
// isolated command's exact UDP payload reaches the supervisor's TUN FD.
func matchesUDPProbe(packet []byte) bool {
	if len(packet) < 28 || packet[0]>>4 != 4 || packet[9] != 17 ||
		!bytes.Equal(packet[12:16], []byte{198, 18, 0, 2}) ||
		!bytes.Equal(packet[16:20], []byte{198, 18, 0, 1}) {
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
	copy(probe[12:16], []byte{198, 18, 0, 2})
	copy(probe[16:20], []byte{198, 18, 0, 1})
	binary.BigEndian.PutUint16(probe[22:24], 5353)
	binary.BigEndian.PutUint16(probe[24:26], uint16(8+len("probe")))
	copy(probe[28:], "probe")
	if !matchesUDPProbe(probe) {
		t.Fatal("expected UDP probe was not recognized")
	}
	ipv6NeighborDiscovery := []byte{0x60, 0, 0, 0, 0, 8, 0x3a, 0xff}
	if matchesUDPProbe(ipv6NeighborDiscovery) {
		t.Fatal("IPv6 neighbor discovery packet must be ignored")
	}
	if matchesUDPProbe(probe[:24]) {
		t.Fatal("truncated UDP probe must be ignored")
	}
	otherDestination := append([]byte(nil), probe...)
	otherDestination[19] = 3
	if matchesUDPProbe(otherDestination) {
		t.Fatal("unrelated destination must be ignored")
	}
}
