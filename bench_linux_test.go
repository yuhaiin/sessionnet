//go:build linux

package sessionnet

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// reportTimings adds the mean of every setup phase as custom metrics.
func reportTimings(b *testing.B, total []SetupTimings) {
	var sum SetupTimings
	for _, t := range total {
		sum.Spawn += t.Spawn
		sum.IDMap += t.IDMap
		sum.Handshake += t.Handshake
		sum.Mounts += t.Mounts
		sum.TUN += t.TUN
		sum.Network += t.Network
		sum.Diagnostics += t.Diagnostics
		sum.Supervisor += t.Supervisor
	}
	n := float64(len(total))
	if n == 0 {
		return
	}
	for name, d := range map[string]time.Duration{
		"spawn-µs": sum.Spawn, "idmap-µs": sum.IDMap, "handshake-µs": sum.Handshake, "mounts-µs": sum.Mounts,
		"tun-µs": sum.TUN, "network-µs": sum.Network, "diag-µs": sum.Diagnostics, "supervisor-µs": sum.Supervisor,
	} {
		b.ReportMetric(float64(d.Microseconds())/n, name)
	}
}

func benchmarkOpen(b *testing.B, cfg Config) {
	b.ReportAllocs()
	timings := make([]SetupTimings, 0, b.N)
	fds, goroutines := countFDs(), runtime.NumGoroutine()
	for b.Loop() {
		s, err := Open(context.Background(), cfg)
		if err != nil {
			b.Fatal(err)
		}
		timings = append(timings, s.SetupTimings())
		if err := s.Close(); err != nil {
			b.Fatal(err)
		}
	}
	reportTimings(b, timings)
	b.ReportMetric(float64(countFDs()-fds), "leaked-fds")
	b.ReportMetric(float64(runtime.NumGoroutine()-goroutines), "leaked-goroutines")
}

func countFDs() int {
	entries, _ := os.ReadDir("/proc/self/fd")
	return len(entries)
}

// BenchmarkSessionOpen measures a new namespace set: user namespace and ID
// maps (rootless), network/mount/PID namespaces, TUN, routes, resolver,
// descriptor handoff and the privilege drop, followed by Close.
func BenchmarkSessionOpen(b *testing.B) {
	requireRootless(b)
	b.Run("rootless", func(b *testing.B) { benchmarkOpen(b, Config{}) })
	b.Run("rootless-ipv6", func(b *testing.B) { benchmarkOpen(b, Config{IPv6: true}) })
	b.Run("rootless-isolated-dns", func(b *testing.B) {
		if !nssUsable() {
			b.Skip("/etc/nsswitch.conf cannot be overmounted here")
		}
		benchmarkOpen(b, Config{IsolateDNS: true})
	})
	if os.Geteuid() == 0 {
		b.Run("rootful", func(b *testing.B) { benchmarkOpen(b, Config{Mode: ModeRootful, Credential: unprivileged()}) })
	}
}

// BenchmarkSessionSpawn is the extra cost of a command that reuses an
// existing session (an additional SSH channel on the same transport).
func BenchmarkSessionSpawn(b *testing.B) {
	requireRootless(b)
	s, err := Open(context.Background(), Config{})
	if err != nil {
		b.Fatal(err)
	}
	defer s.Close()
	if err := s.Release(); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for b.Loop() {
		p, err := s.Spawn(context.Background(), Config{Command: []string{"/bin/true"}})
		if err != nil {
			b.Fatal(err)
		}
		if err := p.Wait(); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkSessionOpenParallel creates sessions concurrently, as several
// SSH transports connecting at once would.
func BenchmarkSessionOpenParallel(b *testing.B) {
	requireRootless(b)
	for _, n := range []int{4, 16} {
		b.Run(fmt.Sprint(n), func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				var wg sync.WaitGroup
				errs := make(chan error, n)
				for range n {
					wg.Go(func() {
						s, err := Open(context.Background(), Config{})
						if err != nil {
							errs <- err
							return
						}
						errs <- s.Close()
					})
				}
				wg.Wait()
				close(errs)
				for err := range errs {
					if err != nil {
						b.Fatal(err)
					}
				}
			}
			b.ReportMetric(float64(b.Elapsed().Microseconds())/float64(b.N*n), "µs/session")
		})
	}
}

// TestBenchmarkModesSameEnvironment compares rootless and rootful in one
// environment without host root: both run as root of a user namespace that
// newuidmap set up. It only runs when SESSIONNET_BENCH_MODES=1.
func TestBenchmarkModesSameEnvironment(t *testing.T) {
	if os.Getenv("SESSIONNET_BENCH_MODES") != "1" {
		t.Skip("set SESSIONNET_BENCH_MODES=1 to compare rootless and rootful setup cost")
	}
	r := runScenario(t, "bench-modes", outerSubordinate, allCaps()...)
	if !r.OK {
		t.Fatalf("%+v", r)
	}
	t.Log("\n" + r.Output)
}

func benchModes() (string, error) {
	var out strings.Builder
	for _, mode := range []Mode{ModeRootless, ModeRootful} {
		cfg := Config{Mode: mode, Credential: &Credential{UID: 1000, GID: 1000}}
		var failure error
		result := testing.Benchmark(func(b *testing.B) {
			timings := make([]SetupTimings, 0, b.N)
			for b.Loop() {
				s, err := Open(context.Background(), cfg)
				if err != nil {
					failure = err
					b.SkipNow()
				}
				timings = append(timings, s.SetupTimings())
				_ = s.Close()
			}
			reportTimings(b, timings)
		})
		if failure != nil {
			return "", failure
		}
		fmt.Fprintf(&out, "%-9s %s %s\n", mode, result.String(), result.MemString())
	}
	return out.String(), nil
}

func nssUsable() bool {
	var stat unix.Stat_t
	return unix.Stat("/etc/nsswitch.conf", &stat) == nil && stat.Nlink != 0
}

// BenchmarkInspectUserNamespace measures the uncached namespace inspection.
// In the initial namespace it only reads /proc; nested (for example under
// `podman unshare`) it includes the depth probe, which CurrentUserNamespace
// runs once per process.
func BenchmarkInspectUserNamespace(b *testing.B) {
	for b.Loop() {
		if _, err := inspectUserNamespace("/proc/self/exe"); err != nil {
			b.Fatal(err)
		}
	}
}
