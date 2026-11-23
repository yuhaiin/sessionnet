//go:build linux

package sessionnet

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// idMapPlan describes how the parent maps the session IDs into a new user
// namespace. Every mapping is an identity mapping: an ID inside the session
// equals the same ID on the host, so file ownership keeps its host meaning.
type idMapPlan struct {
	uidLines  []string // "inside outside count"
	gidLines  []string
	uidTool   string // newuidmap path when a subordinate UID is mapped
	gidTool   string // newgidmap path when a subordinate GID is mapped
	setGroups bool   // whether setgroups(2) is allowed in the namespace
}

// identity is the caller's view of itself needed for mapping decisions.
type identity struct {
	uid, gid           uint32
	canSetUID          bool // CAP_SETUID in the caller's user namespace
	canSetGID          bool // CAP_SETGID in the caller's user namespace
	username           string
	subUIDs, subGIDs   []idRange
	newuidmap, newgidm string
}

type idRange struct{ start, count uint64 }

func (r idRange) contains(id uint32) bool {
	return uint64(id) >= r.start && uint64(id) < r.start+r.count
}

func currentIdentity() identity {
	id := identity{uid: uint32(os.Geteuid()), gid: uint32(os.Getegid())}
	header := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	var data [2]unix.CapUserData
	if unix.Capget(&header, &data[0]) == nil {
		id.canSetUID = data[0].Effective&(1<<unix.CAP_SETUID) != 0
		id.canSetGID = data[0].Effective&(1<<unix.CAP_SETGID) != 0
	}
	if account, err := user.LookupId(strconv.FormatUint(uint64(id.uid), 10)); err == nil {
		id.username = account.Username
	}
	id.subUIDs = readSubordinateIDs("/etc/subuid", id.username, id.uid)
	id.subGIDs = readSubordinateIDs("/etc/subgid", id.username, id.uid)
	id.newuidmap, _ = exec.LookPath("newuidmap")
	id.newgidm, _ = exec.LookPath("newgidmap")
	return id
}

func readSubordinateIDs(path, username string, uid uint32) []idRange {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var ranges []idRange
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		fields := strings.Split(strings.TrimSpace(scanner.Text()), ":")
		if len(fields) != 3 || (fields[0] != username && fields[0] != strconv.FormatUint(uint64(uid), 10)) {
			continue
		}
		start, err1 := strconv.ParseUint(fields[1], 10, 32)
		count, err2 := strconv.ParseUint(fields[2], 10, 32)
		if err1 == nil && err2 == nil && count > 0 {
			ranges = append(ranges, idRange{start, count})
		}
	}
	return ranges
}

func inRanges(ranges []idRange, id uint32) bool {
	for _, r := range ranges {
		if r.contains(id) {
			return true
		}
	}
	return false
}

// planIDMaps decides, before anything is started, whether the requested
// credential can be represented in a rootless session and how.
func planIDMaps(self identity, cred Credential) (idMapPlan, error) {
	var plan idMapPlan
	uidLine := fmt.Sprintf("%d %d 1", cred.UID, cred.UID)
	switch {
	case self.canSetUID, cred.UID == self.uid:
		plan.uidLines = []string{uidLine}
	case self.newuidmap != "" && inRanges(self.subUIDs, cred.UID):
		plan.uidLines, plan.uidTool = []string{uidLine}, self.newuidmap
	default:
		reason := "newuidmap is not installed"
		if self.newuidmap != "" {
			reason = fmt.Sprintf("/etc/subuid does not delegate UID %d to %s", cred.UID, describeUser(self))
		}
		return plan, &SetupError{Stage: StageUIDMap, Message: fmt.Sprintf(
			"UID mapping failed: rootless mode can run the session as the Yuhaiin user (UID %d) only; UID %d would need a subordinate UID mapping, but %s",
			self.uid, cred.UID, reason)}
	}
	gids := []uint32{cred.GID}
	for _, group := range cred.Groups {
		if group != cred.GID && !containsID(gids, group) {
			gids = append(gids, group)
		}
	}
	switch {
	case self.canSetGID:
		for _, gid := range gids {
			plan.gidLines = append(plan.gidLines, fmt.Sprintf("%d %d 1", gid, gid))
		}
		plan.setGroups = true
	case cred.GID == self.gid && len(cred.Groups) == 0:
		// Unprivileged gid_map writes require setgroups to be denied, so the
		// session keeps the caller's supplementary groups.
		plan.gidLines = []string{fmt.Sprintf("%d %d 1", cred.GID, cred.GID)}
	case self.newgidm != "" && allInRanges(self.subGIDs, self.gid, gids):
		for _, gid := range gids {
			plan.gidLines = append(plan.gidLines, fmt.Sprintf("%d %d 1", gid, gid))
		}
		plan.gidTool, plan.setGroups = self.newgidm, true
	case cred.GID == self.gid:
		return plan, &SetupError{Stage: StageGIDMap, Message: "GID mapping failed: supplementary groups cannot be changed in an unprivileged user namespace without newgidmap and /etc/subgid; leave them empty (the session then keeps the groups of the Yuhaiin process)"}
	default:
		reason := "newgidmap is not installed"
		if self.newgidm != "" {
			reason = fmt.Sprintf("/etc/subgid does not delegate GID %d to %s", cred.GID, describeUser(self))
		}
		return plan, &SetupError{Stage: StageGIDMap, Message: fmt.Sprintf(
			"GID mapping failed: rootless mode can run the session with the Yuhaiin group (GID %d) only; GID %d would need a subordinate GID mapping, but %s",
			self.gid, cred.GID, reason)}
	}
	return plan, nil
}

func containsID(ids []uint32, id uint32) bool {
	for _, v := range ids {
		if v == id {
			return true
		}
	}
	return false
}

// allInRanges reports whether newgidmap may map every ID: each must be the
// caller's own GID or delegated through /etc/subgid.
func allInRanges(ranges []idRange, own uint32, ids []uint32) bool {
	for _, id := range ids {
		if id != own && !inRanges(ranges, id) {
			return false
		}
	}
	return true
}

func describeUser(self identity) string {
	if self.username != "" {
		return fmt.Sprintf("%s (UID %d)", self.username, self.uid)
	}
	return fmt.Sprintf("UID %d", self.uid)
}

// writeIDMaps installs the plan for the helper process pid. The helper is
// blocked on its control socket until the parent reports completion.
func writeIDMaps(pid int, plan idMapPlan) error {
	if err := writeMap(pid, "uid_map", plan.uidTool, plan.uidLines); err != nil {
		return &SetupError{Stage: StageUIDMap, Message: "UID mapping failed: the kernel rejected the user namespace UID map" + userNamespacePolicyHint(), Err: err}
	}
	if !plan.setGroups {
		if err := os.WriteFile(fmt.Sprintf("/proc/%d/setgroups", pid), []byte("deny"), 0); err != nil {
			return &SetupError{Stage: StageGIDMap, Message: "GID mapping failed: cannot deny setgroups in the user namespace", Err: err}
		}
	}
	if err := writeMap(pid, "gid_map", plan.gidTool, plan.gidLines); err != nil {
		return &SetupError{Stage: StageGIDMap, Message: "GID mapping failed: the kernel rejected the user namespace GID map" + userNamespacePolicyHint(), Err: err}
	}
	return nil
}

func writeMap(pid int, file, tool string, lines []string) error {
	if tool == "" {
		return os.WriteFile(fmt.Sprintf("/proc/%d/%s", pid, file), []byte(strings.Join(lines, "\n")+"\n"), 0)
	}
	args := []string{strconv.Itoa(pid)}
	for _, line := range lines {
		args = append(args, strings.Fields(line)...)
	}
	output, err := exec.Command(tool, args...).CombinedOutput()
	if err != nil {
		if message := strings.TrimSpace(string(output)); message != "" {
			return fmt.Errorf("%s: %w: %s", tool, err, message)
		}
		return fmt.Errorf("%s: %w", tool, err)
	}
	return nil
}
