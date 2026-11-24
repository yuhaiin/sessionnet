//go:build linux

package sessionnet

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"
)

var (
	lo4 = netip.MustParseAddr("127.0.0.1")
	lo6 = netip.IPv6Loopback()
)

func TestValidateLoopbackForwards(t *testing.T) {
	ok := []LoopbackForward{
		{"tcp", netip.AddrPortFrom(lo4, 5432)}, {"tcp", netip.AddrPortFrom(lo6, 5432)},
		{"udp", netip.AddrPortFrom(lo4, 5432)}, {"udp", netip.AddrPortFrom(lo6, 1)}, {"tcp", netip.AddrPortFrom(lo4, 65535)},
	}
	if err := validateLoopbackForwards(ok); err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct {
		f LoopbackForward
	}{
		"network":         {LoopbackForward{"sctp", netip.AddrPortFrom(lo4, 1)}},
		"empty network":   {LoopbackForward{"", netip.AddrPortFrom(lo4, 1)}},
		"other loopback":  {LoopbackForward{"tcp", netip.MustParseAddrPort("127.0.0.2:80")}},
		"unspecified":     {LoopbackForward{"tcp", netip.MustParseAddrPort("0.0.0.0:80")}},
		"unspecified v6":  {LoopbackForward{"tcp", netip.MustParseAddrPort("[::]:80")}},
		"lan":             {LoopbackForward{"tcp", netip.MustParseAddrPort("192.168.1.2:80")}},
		"mapped loopback": {LoopbackForward{"tcp", netip.MustParseAddrPort("[::ffff:127.0.0.1]:80")}},
		"zero port":       {LoopbackForward{"tcp", netip.AddrPortFrom(lo4, 0)}},
		"invalid address": {LoopbackForward{"tcp", netip.AddrPort{}}},
	} {
		if err := validateLoopbackForwards([]LoopbackForward{tc.f}); err == nil {
			t.Errorf("%s: %v was accepted", name, tc.f)
		}
	}
	dup := []LoopbackForward{{"tcp", netip.AddrPortFrom(lo4, 80)}, {"tcp", netip.AddrPortFrom(lo4, 80)}}
	if err := validateLoopbackForwards(dup); err == nil {
		t.Error("duplicates were accepted")
	}
	// The same port on both protocols and both families is four forwards.
	both := []LoopbackForward{{"tcp", netip.AddrPortFrom(lo4, 53)}, {"udp", netip.AddrPortFrom(lo4, 53)}, {"tcp", netip.AddrPortFrom(lo6, 53)}, {"udp", netip.AddrPortFrom(lo6, 53)}}
	if err := validateLoopbackForwards(both); err != nil {
		t.Fatal(err)
	}
	many := make([]LoopbackForward, MaxLoopbackForwards+1)
	for i := range many {
		many[i] = LoopbackForward{"tcp", netip.AddrPortFrom(lo4, uint16(1000+i))}
	}
	if err := validateLoopbackForwards(many); err == nil {
		t.Error("too many forwards were accepted")
	}
}

// runLoopbackClient runs inside a session: it sends one UDP datagram or opens
// one TCP connection to SESSIONNET_LOOPBACK_TARGET and reports the outcome.
func runLoopbackClient() int {
	network, target := os.Getenv("SESSIONNET_LOOPBACK_NETWORK"), os.Getenv("SESSIONNET_LOOPBACK_TARGET")
	if network == "tcp" {
		c, err := net.DialTimeout("tcp", target, 2*time.Second)
		if err != nil {
			fmt.Println("tcp-error", err)
			return 0
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(3 * time.Second))
		if _, err := fmt.Fprint(c, "hello"); err != nil {
			fmt.Println("tcp-error", err)
			return 0
		}
		_ = c.(*net.TCPConn).CloseWrite()
		reply, err := io.ReadAll(c)
		fmt.Printf("tcp-reply %s from %s local %s err %v\n", reply, c.RemoteAddr(), c.LocalAddr(), err)
		return 0
	}
	c, err := net.Dial("udp", target)
	if err != nil {
		fmt.Println("udp-error", err)
		return 0
	}
	defer c.Close()
	for i := range 3 {
		if _, err := fmt.Fprintf(c, "ping-%d", i); err != nil {
			fmt.Println("udp-error", err)
			return 0
		}
		_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
		buf := make([]byte, 128)
		n, err := c.Read(buf)
		if err != nil {
			fmt.Println("udp-error", err)
			return 0
		}
		// A connected socket only accepts replies from target, so the reply
		// address is the loopback target the process asked for.
		fmt.Printf("udp-reply %s from %s\n", buf[:n], c.RemoteAddr())
	}
	return 0
}

func spawnLoopbackClient(t *testing.T, s *Session, network, target string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	var out lockedBuffer
	p, err := s.Spawn(ctx, Config{Command: []string{os.Args[0]}, Stdout: &out, Stderr: &out,
		Env: []string{"SESSIONNET_TEST_MODE=loopback-client", "SESSIONNET_LOOPBACK_NETWORK=" + network, "SESSIONNET_LOOPBACK_TARGET=" + target}})
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Wait(); err != nil {
		t.Fatalf("%s %s: %v\n%s", network, target, err, out.String())
	}
	return out.String()
}

// serveLoopbackSockets echoes on every handed-over socket and reports the
// peer addresses it saw. It stops when the sockets are closed.
func serveLoopbackSockets(t *testing.T, sockets []LoopbackSocket, peers chan<- string) {
	t.Helper()
	for _, sock := range sockets {
		switch sock.Forward.Network {
		case "tcp":
			l, err := net.FileListener(sock.File)
			_ = sock.File.Close()
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = l.Close() })
			go func() {
				for {
					c, err := l.Accept()
					if err != nil {
						return
					}
					peers <- "tcp " + c.RemoteAddr().String() + " -> " + c.LocalAddr().String()
					go func() {
						defer c.Close()
						data, _ := io.ReadAll(c)
						_, _ = c.Write(append([]byte("echo-"), data...))
					}()
				}
			}()
		case "udp":
			pc, err := net.FilePacketConn(sock.File)
			_ = sock.File.Close()
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = pc.Close() })
			go func() {
				buf := make([]byte, 2048)
				for {
					n, from, err := pc.ReadFrom(buf)
					if err != nil {
						return
					}
					peers <- "udp " + from.String() + " -> " + pc.LocalAddr().String()
					_, _ = pc.WriteTo(append([]byte("echo-"), buf[:n]...), from)
				}
			}()
		}
	}
}

// TestRootlessLoopbackForwardRoundTrip verifies that session processes reach
// the caller through forwarded loopback endpoints of both families and both
// protocols, see the address they used, and that unforwarded ports and the
// other family of a forwarded port stay ordinary session loopback.
func TestRootlessLoopbackForwardRoundTrip(t *testing.T) {
	requireRootless(t)
	forwards := []LoopbackForward{
		{"udp", netip.AddrPortFrom(lo4, 15353)}, {"udp", netip.AddrPortFrom(lo6, 15353)},
		{"tcp", netip.AddrPortFrom(lo4, 15432)}, {"tcp", netip.AddrPortFrom(lo6, 15433)},
		{"tcp", netip.AddrPortFrom(lo4, 80)}, // a privileged port
	}
	s := openRootless(t, Config{IPv6: true, LoopbackForwards: forwards})
	sockets, err := s.LoopbackSockets()
	if err != nil {
		t.Fatal(err)
	}
	if len(sockets) != len(forwards) {
		t.Fatalf("%d sockets for %d forwards", len(sockets), len(forwards))
	}
	for i, sock := range sockets {
		if sock.Forward != forwards[i] {
			t.Fatalf("socket %d is %v, want %v", i, sock.Forward, forwards[i])
		}
	}
	peers := make(chan string, 64)
	serveLoopbackSockets(t, sockets, peers)
	if err := s.Release(); err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{"127.0.0.1:15353", "[::1]:15353"} {
		out := spawnLoopbackClient(t, s, "udp", target)
		for i := range 3 {
			if want := fmt.Sprintf("udp-reply echo-ping-%d from %s", i, target); !strings.Contains(out, want) {
				t.Errorf("%s: output lacks %q:\n%s", target, want, out)
			}
		}
	}
	for _, target := range []string{"127.0.0.1:15432", "[::1]:15433", "127.0.0.1:80"} {
		out := spawnLoopbackClient(t, s, "tcp", target)
		if want := "tcp-reply echo-hello from " + target; !strings.Contains(out, want) {
			t.Errorf("%s: output lacks %q:\n%s", target, want, out)
		}
	}
	// The caller sees the real loopback peers of the session processes.
	// The echo goroutines may still report, so drain without closing.
	for drained := false; !drained; {
		select {
		case peer := <-peers:
			if !strings.Contains(peer, "127.0.0.1:") && !strings.Contains(peer, "[::1]:") {
				t.Errorf("unexpected peer %s", peer)
			}
		default:
			drained = true
		}
	}
	for _, target := range []string{"127.0.0.1:15434", "[::1]:15432", "127.0.0.1:15433"} {
		if out := spawnLoopbackClient(t, s, "tcp", target); !strings.Contains(out, "connection refused") {
			t.Errorf("%s must stay on the session loopback: %s", target, out)
		}
	}
}

func TestLoopbackSocketsClosedWithSession(t *testing.T) {
	requireRootless(t)
	before := countOpenFDs(t)
	s := openRootless(t, Config{IPv6: true, LoopbackForwards: []LoopbackForward{{"tcp", netip.AddrPortFrom(lo4, 15600)}, {"udp", netip.AddrPortFrom(lo6, 15600)}}})
	sockets, err := s.LoopbackSockets()
	if err != nil {
		t.Fatal(err)
	}
	for _, sock := range sockets {
		_ = sock.File.Close()
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := s.LoopbackSockets(); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("LoopbackSockets after Close: %v", err)
	}
	if after := countOpenFDs(t); after > before {
		t.Fatalf("leaked %d descriptors", after-before)
	}
}

func TestRootlessLoopbackForwardFailures(t *testing.T) {
	requireRootless(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	// Invalid forwards fail before anything starts.
	_, err := Open(ctx, Config{LoopbackForwards: []LoopbackForward{{"tcp", netip.MustParseAddrPort("10.0.0.1:80")}}})
	var setup *SetupError
	if !errors.As(err, &setup) || setup.Stage != StageLoopbackForward {
		t.Fatalf("invalid forward: %v", err)
	}
	if children := childProcesses(t); len(children) != 0 {
		t.Fatalf("a pre-validated failure started helpers: %v", children)
	}
}

// TestRootlessLoopbackForwardsStayInSession checks that sessions do not share
// rules and that nothing is installed in the caller's namespace.
func TestRootlessLoopbackForwardsStayInSession(t *testing.T) {
	requireRootless(t)
	before := snapshotHostNetwork(t)
	a := openRootless(t, Config{LoopbackForwards: []LoopbackForward{{"tcp", netip.AddrPortFrom(lo4, 15500)}}})
	b := openRootless(t, Config{})
	if err := errors.Join(a.Release(), b.Release()); err != nil {
		t.Fatal(err)
	}
	// The session without forwards keeps a plain loopback: an unbound port
	// is refused locally even though session A forwards it.
	out := spawnLoopbackClient(t, b, "tcp", "127.0.0.1:15500")
	if !strings.Contains(out, "connection refused") {
		t.Fatalf("session B is affected by session A's forward: %s", out)
	}
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	if after := snapshotHostNetwork(t); after != before {
		t.Fatalf("host network changed:\nbefore %+v\nafter %+v", before, after)
	}
}
