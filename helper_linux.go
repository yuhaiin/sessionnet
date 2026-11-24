//go:build linux

package sessionnet

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// The helper is the integrating binary re-executed with these arguments.
// Stage one runs with capabilities inside the session's namespaces and
// performs all setup. It then drops every capability and executes stage two,
// the supervisor, which runs as PID 1 of the session's PID namespace.
const (
	helperArg       = "__sessionnet_helper__"
	helperSupervise = "supervise"
	helperArgv0     = "sessionnet-helper"
	supervisorArgv0 = "sessionnet-supervisor"
	controlFD       = 3
)

func init() {
	if len(os.Args) >= 2 && os.Args[1] == helperArg {
		os.Exit(helperMain(os.Args[2:]))
	}
	if len(os.Args) == 2 && os.Args[0] == helperArgv0 && os.Args[1] == helperLevelArg {
		os.Exit(nestingLevelMain())
	}
}

func helperMain(args []string) int {
	// Never let an accidental invocation read an unrelated descriptor.
	var stat unix.Stat_t
	if unix.Fstat(controlFD, &stat) != nil || stat.Mode&unix.S_IFMT != unix.S_IFSOCK {
		fmt.Fprintln(os.Stderr, "sessionnet: the session helper is started by sessionnet only")
		return 2
	}
	if t, err := unix.GetsockoptInt(controlFD, unix.SOL_SOCKET, unix.SO_TYPE); err != nil || t != unix.SOCK_SEQPACKET {
		fmt.Fprintln(os.Stderr, "sessionnet: invalid helper control socket")
		return 2
	}
	unix.CloseOnExec(controlFD)
	conn, err := fileControlConn(os.NewFile(controlFD, "sessionnet-control"))
	if err != nil {
		return 2
	}
	defer conn.Close()
	if len(args) == 1 && args[0] == helperSupervise {
		return supervise(conn)
	}
	if len(args) != 0 {
		return 2
	}
	return setupStage(conn)
}

// helperFailure is a classified setup failure produced inside the helper.
type helperFailure struct{ wire *wireError }

func (f *helperFailure) Error() string { return f.wire.Message }

func fail(stage Stage, message string, err error) error {
	return &helperFailure{wire: newWireError(stage, message, err)}
}

func setupStage(conn *controlConn) int {
	m, files, err := conn.receive()
	closeFiles(files)
	if err != nil || m.Op != opInit || m.Init == nil {
		return 2
	}
	if err := setupSession(conn, m.Init); err != nil {
		var failure *helperFailure
		if !errors.As(err, &failure) {
			failure = &helperFailure{wire: newWireError(StageHelper, "session helper failed", err)}
		}
		_ = conn.send(&message{Op: opFailed, Error: failure.wire})
		return 1
	}
	return 0 // unreachable: setupSession executes the supervisor
}

func setupSession(conn *controlConn, req *initRequest) error {
	reply := &readyReply{Interface: req.Interface}
	phase := time.Now()
	elapsed := func(into *int64) { now := time.Now(); *into = int64(now.Sub(phase)); phase = now }
	if req.Mode == ModeRootless {
		// The parent has mapped exactly the session IDs. Adopt them on every
		// thread first, so files created during setup are owned by mapped IDs.
		if err := adoptCredentials(req); err != nil {
			return err
		}
	}
	// Session processes run as the same user. A non-dumpable helper cannot be
	// ptraced by them while it still holds namespace capabilities.
	if err := unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0); err != nil {
		return fail(StagePrivileges, "cannot protect the session helper", err)
	}
	elapsed(&reply.Credentials)
	if err := setupMounts(req); err != nil {
		return err
	}
	elapsed(&reply.Mounts)
	h, err := netlink.NewHandle(unix.NETLINK_ROUTE)
	if err != nil {
		return fail(StageNetwork, "cannot open a netlink socket in the session network namespace", err)
	}
	defer h.Close()
	if err := enableLoopback(h); err != nil {
		return err
	}
	tun, err := createTun(req.Interface)
	if err != nil {
		return err
	}
	defer tun.Close()
	elapsed(&reply.TUN)
	if err := configureTun(h, req); err != nil {
		return err
	}
	elapsed(&reply.Network)
	diagFD, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_INET_DIAG)
	if err != nil {
		return fail(StageDiagnostics, "cannot open the socket diagnostics channel used for process lookup", err)
	}
	diag := os.NewFile(uintptr(diagFD), "sock_diag")
	defer diag.Close()
	netns, err := os.OpenFile("/proc/self/ns/net", os.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return fail(StageDiagnostics, "cannot open the session network namespace handle", err)
	}
	defer netns.Close()
	elapsed(&reply.Diagnostics)
	if err := conn.send(&message{Op: opReady, Ready: reply}, tun, diag, netns); err != nil {
		return fail(StageHandshake, "cannot hand the TUN descriptor to the supervisor", err)
	}
	_ = tun.Close()
	_ = diag.Close()
	_ = netns.Close()
	return dropPrivilegesAndSupervise(conn, req)
}

func adoptCredentials(req *initRequest) error {
	if req.SetGroups {
		if err := syscall.Setgroups(toInts(req.Groups)); err != nil {
			return fail(StageCredentials, "cannot set supplementary groups in the user namespace", err)
		}
	}
	if uint32(os.Getgid()) != req.GID || uint32(os.Getegid()) != req.GID {
		if err := syscall.Setresgid(int(req.GID), int(req.GID), int(req.GID)); err != nil {
			return fail(StageGIDMap, fmt.Sprintf("GID %d is not usable inside the user namespace", req.GID), err)
		}
	}
	if uint32(os.Getuid()) != req.UID || uint32(os.Geteuid()) != req.UID {
		if err := syscall.Setresuid(int(req.UID), int(req.UID), int(req.UID)); err != nil {
			return fail(StageUIDMap, fmt.Sprintf("UID %d is not usable inside the user namespace", req.UID), err)
		}
	}
	return nil
}

func toInts(values []uint32) []int {
	result := make([]int, len(values))
	for i, v := range values {
		result[i] = int(v)
	}
	return result
}

const (
	prSetSecurebits       = 28
	secbitNoroot          = 1 << 0
	secbitNorootLocked    = 1 << 1
	secbitNoSetuidFixup   = 1 << 2
	secbitNoSetuidLocked  = 1 << 3
	secbitKeepCapsLocked  = 1 << 5
	secbitNoAmbientRaise  = 1 << 6
	secbitNoAmbientLocked = 1 << 7
	lockedSecurebits      = secbitNoroot | secbitNorootLocked | secbitNoSetuidFixup | secbitNoSetuidLocked |
		secbitKeepCapsLocked | secbitNoAmbientRaise | secbitNoAmbientLocked
)

// dropPrivilegesAndSupervise executes the supervisor from one locked OS
// thread whose credentials have been reduced to nothing. Credentials are a
// per-thread attribute in Linux, but execve keeps only the calling thread,
// so the supervisor image starts with exactly this thread's state: no
// capabilities in any set, an empty bounding set, locked securebits and
// no_new_privs. The thread is never returned to the Go scheduler.
func dropPrivilegesAndSupervise(conn *controlConn, req *initRequest) error {
	runtime.LockOSThread()
	last := lastCapability()
	for c := 0; c <= last; c++ {
		if err := unix.Prctl(unix.PR_CAPBSET_DROP, uintptr(c), 0, 0, 0); err != nil && !errors.Is(err, unix.EINVAL) {
			return fail(StagePrivileges, "cannot clear the capability bounding set", err)
		}
	}
	if err := unix.Prctl(prSetSecurebits, lockedSecurebits, 0, 0, 0); err != nil {
		return fail(StagePrivileges, "cannot lock the session securebits", err)
	}
	if req.Mode == ModeRootful {
		// Go applies these to every thread. NO_SETUID_FIXUP keeps this
		// thread's capabilities until they are cleared explicitly below.
		if err := syscall.Setgroups(toInts(req.Groups)); err != nil {
			return fail(StageCredentials, "cannot set supplementary groups", err)
		}
		if err := syscall.Setresgid(int(req.GID), int(req.GID), int(req.GID)); err != nil {
			return fail(StageCredentials, fmt.Sprintf("cannot switch to GID %d", req.GID), err)
		}
		if err := syscall.Setresuid(int(req.UID), int(req.UID), int(req.UID)); err != nil {
			return fail(StageCredentials, fmt.Sprintf("cannot switch to UID %d", req.UID), err)
		}
	}
	if err := unix.Prctl(unix.PR_CAP_AMBIENT, unix.PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0); err != nil {
		return fail(StagePrivileges, "cannot clear ambient capabilities", err)
	}
	header := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	var data [2]unix.CapUserData
	if err := unix.Capset(&header, &data[0]); err != nil {
		return fail(StagePrivileges, "cannot clear capabilities", err)
	}
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return fail(StagePrivileges, "cannot set no_new_privs", err)
	}
	// Hand the live control socket to the supervisor as descriptor 3,
	// without close-on-exec. Every other descriptor is close-on-exec.
	raw, err := conn.conn.SyscallConn()
	if err != nil {
		return fail(StageHelper, "cannot keep the control socket for the supervisor", err)
	}
	var dupErr error
	if err := raw.Control(func(fd uintptr) { dupErr = unix.Dup3(int(fd), controlFD, 0) }); err != nil || dupErr != nil {
		return fail(StageHelper, "cannot keep the control socket for the supervisor", errors.Join(err, dupErr))
	}
	err = unix.Exec("/proc/self/exe", []string{supervisorArgv0, helperArg, helperSupervise}, helperEnvironment())
	_ = unix.Close(controlFD)
	return fail(StageHelper, "cannot start the session supervisor", err)
}

func helperEnvironment() []string {
	// The helper performs no Go-intensive work; keep its footprint small.
	return []string{"GOMAXPROCS=1", "GOTRACEBACK=none"}
}

func lastCapability() int {
	data, err := os.ReadFile("/proc/sys/kernel/cap_last_cap")
	if err == nil {
		if n, err := strconv.Atoi(strings.TrimSpace(string(data))); err == nil && n >= 0 && n < 64 {
			return n
		}
	}
	return 63
}

// verifyNoPrivileges confirms the supervisor kept no capability. It reads
// the kernel's view instead of trusting the setup code that dropped them.
func verifyNoPrivileges() error {
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return err
	}
	want := map[string]string{
		"CapInh:": "0000000000000000", "CapPrm:": "0000000000000000", "CapEff:": "0000000000000000",
		"CapBnd:": "0000000000000000", "CapAmb:": "0000000000000000", "NoNewPrivs:": "1",
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 {
			if expected, ok := want[fields[0]]; ok {
				if fields[1] != expected {
					return fmt.Errorf("%s %s", fields[0], fields[1])
				}
				delete(want, fields[0])
			}
		}
	}
	if len(want) != 0 {
		return errors.New("incomplete process status")
	}
	return nil
}
