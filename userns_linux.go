//go:build linux

package sessionnet

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"
)

// initialUserNamespaceInode is PROC_USER_INIT_INO, the fixed nsfs inode of
// the initial user namespace.
const initialUserNamespaceInode = 0xEFFFFFFD

// maxUserNamespaceLevel is the deepest nesting level the kernel allows:
// create_user_ns refuses a child of a namespace whose level exceeds 32, so
// namespaces exist at levels 0 (initial) through 33. This has been fixed
// since Linux 3.11.
const maxUserNamespaceLevel = 33

// helperLevelArg re-executes the binary as one link of the nesting probe.
const helperLevelArg = "__sessionnet_userns_level__"

var (
	userNamespaceOnce   sync.Once
	userNamespaceResult UserNamespace
	userNamespaceErr    error
)

// CurrentUserNamespace inspects the caller's user namespace. A process
// cannot change its user namespace without setns(2), which sessionnet never
// does, so the result is computed once. Inside a nested namespace the depth
// probe briefly starts one helper process per remaining nesting level
// (about 32 for a depth of 1); they create user namespaces only, nothing
// else, and all have exited when this returns.
func CurrentUserNamespace() (UserNamespace, error) {
	userNamespaceOnce.Do(func() { userNamespaceResult, userNamespaceErr = inspectUserNamespace("/proc/self/exe") })
	return userNamespaceResult, userNamespaceErr
}

func inspectUserNamespace(helperPath string) (UserNamespace, error) {
	var u UserNamespace
	var stat unix.Stat_t
	if err := unix.Stat("/proc/self/ns/user", &stat); err != nil {
		return u, fmt.Errorf("sessionnet: cannot identify the user namespace: %w", err)
	}
	u.Inode = stat.Ino
	var err error
	if u.UIDMap, err = readIDMap("/proc/self/uid_map"); err != nil {
		return u, err
	}
	if u.GIDMap, err = readIDMap("/proc/self/gid_map"); err != nil {
		return u, err
	}
	setgroups, err := os.ReadFile("/proc/self/setgroups")
	u.SetgroupsAllowed = err != nil || strings.TrimSpace(string(setgroups)) != "deny"
	u.Initial = stat.Ino == initialUserNamespaceInode && u.UIDMap.IsIdentity() && u.GIDMap.IsIdentity()
	if u.Initial {
		return u, nil
	}
	remaining, err := probeNestingLevels(helperPath)
	if err != nil {
		u.Depth, u.DepthError = -1, err.Error()
		return u, nil
	}
	u.Depth = maxUserNamespaceLevel - remaining
	if u.Depth < 1 {
		u.Depth, u.DepthError = -1, fmt.Sprintf("the kernel allowed %d nested user namespaces, more than expected", remaining)
	}
	return u, nil
}

func readIDMap(path string) (IDMap, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("sessionnet: cannot read %s: %w", path, err)
	}
	m, err := ParseIDMap(data)
	if err != nil {
		return nil, fmt.Errorf("sessionnet: %s: %w", path, err)
	}
	return m, nil
}

// probeNestingLevels counts how many user namespaces can still be nested
// below the caller. Each link of the chain is a helper process in a new user
// namespace that maps only the caller's own UID and GID (the unprivileged
// form the kernel always permits) and starts the next link. A limit such as
// user.max_user_namespaces or a security policy can only stop the chain
// early, which makes the measured depth larger, never smaller: a namespace
// is never mistaken for a direct child of the host.
func probeNestingLevels(helperPath string) (int, error) {
	uid, gid := os.Geteuid(), os.Getegid()
	attr := &syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWUSER}
	if uid == 0 && !currentCaller().CapSetFCAP {
		// Mapping UID 0 needs CAP_SETFCAP (Linux 5.12+). Holding CAP_SETUID,
		// the chain can continue as another UID of this namespace instead.
		other, ok := nonRootUID()
		if !ok || !currentCaller().CapSetUID {
			return 0, errors.New("cannot measure the user namespace nesting depth: mapping UID 0 needs CAP_SETFCAP")
		}
		uid = int(other)
		attr.Credential = &syscall.Credential{Uid: other, Gid: uint32(gid), NoSetGroups: true}
	}
	attr.UidMappings = []syscall.SysProcIDMap{{ContainerID: uid, HostID: uid, Size: 1}}
	attr.GidMappings = []syscall.SysProcIDMap{{ContainerID: gid, HostID: gid, Size: 1}}
	cmd := &exec.Cmd{
		Path:        helperPath,
		Args:        []string{helperArgv0, helperLevelArg},
		Env:         helperEnvironment(),
		Dir:         "/",
		SysProcAttr: attr,
	}
	err := cmd.Run()
	if errno := syscall.Errno(0); errors.As(err, &errno) && errno == syscall.ENOSPC && cmd.Process == nil {
		// The kernel refused a deeper namespace: the caller's level is the
		// last one, or a namespace limit was reached first.
		return 0, nil
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		if code := exitErr.ExitCode(); code >= 0 && code < maxUserNamespaceLevel {
			return code + 1, nil
		}
		return 0, errors.New("cannot measure the user namespace nesting depth: a nested user namespace could not be created")
	}
	if err != nil {
		return 0, fmt.Errorf("cannot measure the user namespace nesting depth: %w", err)
	}
	return 1, nil
}

// nonRootUID returns a UID other than 0 that this namespace maps.
func nonRootUID() (uint32, bool) {
	m, err := readIDMap("/proc/self/uid_map")
	if err != nil {
		return 0, false
	}
	for _, r := range m {
		if r.NamespaceID != 0 {
			return r.NamespaceID, true
		}
		if r.Count > 1 {
			return 1, true
		}
	}
	return 0, false
}

// nestingLevelMain is one link of probeNestingLevels. Its exit status is
// the number of levels below it, or maxUserNamespaceLevel+1 on failure.
func nestingLevelMain() int {
	remaining, err := probeNestingLevels("/proc/self/exe")
	if err != nil {
		return maxUserNamespaceLevel + 1
	}
	return remaining
}

func currentCaller() Caller {
	c := Caller{UID: uint32(os.Geteuid()), GID: uint32(os.Getegid())}
	if groups, err := unix.Getgroups(); err == nil {
		for _, g := range groups {
			c.Groups = append(c.Groups, uint32(g))
		}
	}
	header := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	var data [2]unix.CapUserData
	if unix.Capget(&header, &data[0]) == nil {
		effective := uint64(data[1].Effective)<<32 | uint64(data[0].Effective)
		has := func(c int) bool { return effective&(1<<uint(c)) != 0 }
		c.CapSetUID, c.CapSetGID, c.CapSetFCAP = has(unix.CAP_SETUID), has(unix.CAP_SETGID), has(unix.CAP_SETFCAP)
		c.CapSysAdm, c.CapNetAdm = has(unix.CAP_SYS_ADMIN), has(unix.CAP_NET_ADMIN)
	}
	return c
}

// overflowGID is the GID the kernel reports for groups the namespace does
// not map (kernel.overflowgid, normally 65534).
func overflowGID() uint32 {
	if v, err := strconv.ParseUint(readSysctl("kernel/overflowgid"), 10, 32); err == nil {
		return uint32(v)
	}
	return 65534
}
