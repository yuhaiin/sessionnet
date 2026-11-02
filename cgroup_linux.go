//go:build linux

package sessionnet

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

const groupPrefix = "session-"

// CgroupManager owns a private cgroup v2 subtree and an exclusive lifetime
// lock. It reaps leftover session cgroups before admitting new sessions.
//
// A stable, dedicated root path is required across restarts. The caller must
// provide a writable, trusted cgroup v2 subtree; a regular directory is not
// accepted. Only entries created with the session- prefix are ever reaped.
type CgroupManager struct {
	root   *os.File
	path   string
	mu     sync.Mutex
	groups map[*sessionCgroup]struct{}
	closed bool
}

type sessionCgroup struct {
	manager   *CgroupManager
	name      string
	fd        *os.File
	closeOnce sync.Once
	closeErr  error
}

// NewCgroupManager acquires an exclusive lock and kills orphaned sessions
// left by an earlier crashed supervisor. If the lock is already held, cgroup
// v2 is unavailable, or any orphan cannot be reaped, it fails closed.
func NewCgroupManager(root string) (_ *CgroupManager, err error) {
	if !filepath.IsAbs(root) || root == "/" || filepath.Clean(root) != root {
		return nil, errors.New("sessionnet: cgroup root must be a clean absolute path")
	}
	if err := os.MkdirAll(root, 0700); err != nil {
		return nil, fmt.Errorf("sessionnet: create cgroup root: %w", err)
	}
	fd, err := unix.Open(root, unix.O_DIRECTORY|unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("sessionnet: open cgroup root: %w", err)
	}
	file := os.NewFile(uintptr(fd), root)
	defer func() {
		if err != nil {
			_ = file.Close()
		}
	}()
	var stat unix.Statfs_t
	if err = unix.Fstatfs(fd, &stat); err != nil {
		return nil, err
	}
	if stat.Type != unix.CGROUP2_SUPER_MAGIC {
		return nil, errors.New("sessionnet: cgroup root must be on a cgroup v2 filesystem")
	}
	var parentStat unix.Statfs_t
	if err = unix.Statfs(filepath.Dir(root), &parentStat); err != nil {
		return nil, err
	}
	if parentStat.Type != unix.CGROUP2_SUPER_MAGIC {
		return nil, errors.New("sessionnet: cgroup root must be a dedicated subtree, not the cgroup mount point")
	}
	if err = unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return nil, fmt.Errorf("sessionnet: cgroup root is locked by another supervisor: %w", err)
	}
	manager := &CgroupManager{root: file, path: root, groups: make(map[*sessionCgroup]struct{})}
	if err = manager.cleanupOrphans(); err != nil {
		return nil, fmt.Errorf("sessionnet: recover orphaned cgroups: %w", err)
	}
	return manager, nil
}

func (m *CgroupManager) cleanupOrphans() error {
	entries, err := os.ReadDir(m.path)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasPrefix(name, groupPrefix) || !safeGroupName(name) {
			continue
		}
		fd, err := openGroup(m.root, name)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return fmt.Errorf("open orphan %s: %w", name, err)
		}
		if err := terminateGroup(m.root, name, fd); err != nil {
			return fmt.Errorf("terminate orphan %s: %w", name, err)
		}
	}
	return nil
}

func safeGroupName(name string) bool {
	if !strings.HasPrefix(name, groupPrefix) || len(name) != len(groupPrefix)+32 {
		return false
	}
	_, err := hex.DecodeString(name[len(groupPrefix):])
	return err == nil
}

func (m *CgroupManager) newGroup() (*sessionCgroup, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return nil, os.ErrClosed
	}
	var entropy [16]byte
	if _, err := rand.Read(entropy[:]); err != nil {
		return nil, err
	}
	name := groupPrefix + hex.EncodeToString(entropy[:])
	if err := unix.Mkdirat(int(m.root.Fd()), name, 0700); err != nil {
		return nil, fmt.Errorf("sessionnet: create session cgroup: %w", err)
	}
	fd, err := openGroup(m.root, name)
	if err != nil {
		_ = unix.Unlinkat(int(m.root.Fd()), name, unix.AT_REMOVEDIR)
		return nil, err
	}
	if err := verifyCgroupKill(fd); err != nil {
		_ = fd.Close()
		_ = unix.Unlinkat(int(m.root.Fd()), name, unix.AT_REMOVEDIR)
		return nil, fmt.Errorf("sessionnet: cgroup.kill unavailable: %w", err)
	}
	group := &sessionCgroup{manager: m, name: name, fd: fd}
	m.groups[group] = struct{}{}
	return group, nil
}

func openGroup(root *os.File, name string) (*os.File, error) {
	if !safeGroupName(name) {
		return nil, errors.New("sessionnet: invalid session cgroup name")
	}
	fd, err := unix.Openat(int(root.Fd()), name, unix.O_DIRECTORY|unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), name), nil
}

func verifyCgroupKill(group *os.File) error {
	fd, err := unix.Openat(int(group.Fd()), "cgroup.kill", unix.O_WRONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	return unix.Close(fd)
}

func killCgroup(group *os.File) error {
	fd, err := unix.Openat(int(group.Fd()), "cgroup.kill", unix.O_WRONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), "cgroup.kill")
	_, writeErr := io.WriteString(file, "1")
	return errors.Join(writeErr, file.Close())
}

func cgroupPopulated(group *os.File) (bool, error) {
	fd, err := unix.Openat(int(group.Fd()), "cgroup.events", unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return false, err
	}
	file := os.NewFile(uintptr(fd), "cgroup.events")
	content, readErr := io.ReadAll(io.LimitReader(file, 4096))
	closeErr := file.Close()
	if err := errors.Join(readErr, closeErr); err != nil {
		return false, err
	}
	for _, line := range strings.Split(string(content), "\n") {
		if line == "populated 1" {
			return true, nil
		}
		if line == "populated 0" {
			return false, nil
		}
	}
	return false, errors.New("sessionnet: no populated field in cgroup.events")
}

// terminateGroup always uses cgroup.kill rather than enumerating PIDs.
// A process cannot escape by creating a new process group or daemonizing.
func terminateGroup(root *os.File, name string, group *os.File) error {
	defer group.Close()
	if err := killCgroup(group); err != nil {
		return err
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		populated, err := cgroupPopulated(group)
		if err != nil {
			return err
		}
		if !populated {
			break
		}
		if time.Now().After(deadline) {
			return errors.New("sessionnet: timed out waiting for cgroup to empty")
		}
		time.Sleep(20 * time.Millisecond)
	}
	for {
		err := unix.Unlinkat(int(root.Fd()), name, unix.AT_REMOVEDIR)
		if err == nil || errors.Is(err, unix.ENOENT) {
			return nil
		}
		if !errors.Is(err, unix.EBUSY) || time.Now().After(deadline) {
			return err
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func (g *sessionCgroup) Close() error {
	g.closeOnce.Do(func() {
		m := g.manager
		g.closeErr = terminateGroup(m.root, g.name, g.fd)
		m.mu.Lock()
		delete(m.groups, g)
		m.mu.Unlock()
	})
	return g.closeErr
}

// Close kills and reaps any remaining managed sessions before releasing the
// exclusive lock. It is safe to call repeatedly after all Open calls finish.
func (m *CgroupManager) Close() error {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return nil
	}
	m.closed = true
	groups := make([]*sessionCgroup, 0, len(m.groups))
	for g := range m.groups {
		groups = append(groups, g)
	}
	m.mu.Unlock()
	var err error
	for _, g := range groups {
		err = errors.Join(err, g.Close())
	}
	return errors.Join(err, m.root.Close())
}
