//go:build linux

package sessionnet

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// Session IDs.
//
// A Credential names IDs as the session sees them. Whenever the caller's
// user namespace can be resolved to the host (it is the initial namespace,
// or a direct child of it such as `podman unshare`), session IDs are host
// IDs: a rootless session maps host UID H to the caller-namespace UID that
// the caller's own uid_map assigns to H, so files keep their host owners
// and the session shows them under their host IDs. Otherwise session IDs
// are the caller's namespace IDs and only the caller's own identity can be
// used, because nothing beyond the parent namespace can be verified.

// idMapPlan describes how the parent maps the session IDs into a new user
// namespace, and the IDs the helper then adopts in its namespace.
type idMapPlan struct {
	uidLines  []string // "inside outside count"
	gidLines  []string
	uidTool   string // newuidmap path when a subordinate UID is mapped
	gidTool   string // newgidmap path when a subordinate GID is mapped
	setGroups bool   // whether the helper calls setgroups(2)
	// uidMap and gidMap translate session IDs into the caller's namespace.
	uidMap, gidMap IDMap
}

// identity is the caller's view of itself needed for mapping decisions.
type identity struct {
	Caller
	ns                 UserNamespace
	username           string
	subUIDs, subGIDs   []idRange
	newuidmap, newgidm string
}

type idRange struct{ start, count uint64 }

func (r idRange) contains(id uint32) bool {
	return uint64(id) >= r.start && uint64(id) < r.start+r.count
}

func currentIdentity() (identity, error) {
	ns, err := CurrentUserNamespace()
	if err != nil {
		return identity{}, &SetupError{Stage: StageUserNamespace, Message: "cannot inspect the user namespace Yuhaiin runs in", Err: err}
	}
	id := identity{Caller: currentCaller(), ns: ns}
	// /etc/subuid, /etc/subgid and the setuid newuidmap/newgidmap tools
	// describe host IDs and only work for processes of the initial namespace.
	if ns.Initial {
		if account, err := user.LookupId(strconv.FormatUint(uint64(id.UID), 10)); err == nil {
			id.username = account.Username
		}
		id.subUIDs = readSubordinateIDs("/etc/subuid", id.username, id.UID)
		id.subGIDs = readSubordinateIDs("/etc/subgid", id.username, id.UID)
		id.newuidmap, _ = exec.LookPath("newuidmap")
		id.newgidm, _ = exec.LookPath("newgidmap")
	}
	return id, nil
}

// DefaultCredential returns the rootless default: the caller's own UID and
// GID as session IDs (host IDs when the namespace is resolvable).
func DefaultCredential() (Credential, error) {
	self, err := currentIdentity()
	if err != nil {
		return Credential{}, err
	}
	return self.defaultCredential(), nil
}

func (id identity) defaultCredential() Credential {
	uid, _ := id.sessionUID(id.UID)
	gid, _ := id.sessionGID(id.GID)
	return Credential{UID: uid, GID: gid}
}

// sessionUID translates a caller-namespace UID into a session UID.
func (id identity) sessionUID(caller uint32) (uint32, bool) {
	if id.ns.HostIDs() {
		return id.ns.HostUID(caller)
	}
	return caller, true
}

func (id identity) sessionGID(caller uint32) (uint32, bool) {
	if id.ns.HostIDs() {
		return id.ns.HostGID(caller)
	}
	return caller, true
}

// callerUID translates a session UID into the caller's namespace. Without a
// resolvable host mapping only the caller's own UID is accepted.
func (id identity) callerUID(session uint32) (uint32, bool) {
	if id.ns.HostIDs() {
		return id.ns.NamespaceUID(session)
	}
	return session, session == id.UID
}

func (id identity) callerGID(session uint32) (uint32, bool) {
	if id.ns.HostIDs() {
		return id.ns.NamespaceGID(session)
	}
	return session, session == id.GID
}

// usableUIDs lists the session UIDs planIDMaps accepts, following the same
// rules: the caller's own UID, any UID of the caller's namespace with
// CAP_SETUID, or delegated subordinate UIDs in the initial namespace. With
// CAP_SETFCAP missing, the caller namespace's UID 0 cannot be mapped.
func (id identity) usableUIDs() []IDRange {
	return id.toSessionRanges(id.usableParentUIDs(), id.ns.UIDMap, id.UID)
}

// usableParentUIDs lists the caller-namespace UIDs a session UID may map to,
// which is what a manual ParentUID may name.
func (id identity) usableParentUIDs() []IDRange {
	callerRanges := []IDRange{{Start: id.UID, Count: 1}}
	if id.CapSetUID {
		callerRanges = namespaceRanges(id.ns.UIDMap)
	} else if id.newuidmap != "" {
		callerRanges = append(callerRanges, subordinateRanges(id.subUIDs)...)
	}
	if !id.CapSetFCAP {
		callerRanges = withoutID(callerRanges, 0)
	}
	return callerRanges
}

// usableGIDs lists the session GIDs planIDMaps accepts as the primary group
// of a credential without supplementary groups.
func (id identity) usableGIDs() []IDRange {
	return id.toSessionRanges(id.usableParentGIDs(), id.ns.GIDMap, id.GID)
}

// usableParentGIDs lists the caller-namespace GIDs a primary session GID may
// map to.
func (id identity) usableParentGIDs() []IDRange {
	callerRanges := []IDRange{{Start: id.GID, Count: 1}}
	if id.CapSetGID && id.ns.SetgroupsAllowed {
		callerRanges = namespaceRanges(id.ns.GIDMap)
	} else if id.newgidm != "" {
		callerRanges = append(callerRanges, subordinateRanges(id.subGIDs)...)
	}
	return callerRanges
}

func namespaceRanges(m IDMap) []IDRange {
	ranges := make([]IDRange, 0, len(m))
	for _, r := range m {
		ranges = append(ranges, IDRange{Start: r.NamespaceID, Count: r.Count})
	}
	return ranges
}

func subordinateRanges(sub []idRange) []IDRange {
	var ranges []IDRange
	for _, r := range sub {
		ranges = append(ranges, IDRange{Start: uint32(r.start), Count: uint32(r.count)})
	}
	return ranges
}

func withoutID(ranges []IDRange, id uint32) []IDRange {
	var out []IDRange
	for _, r := range ranges {
		if !r.Contains(id) {
			out = append(out, r)
			continue
		}
		if id > r.Start {
			out = append(out, IDRange{Start: r.Start, Count: id - r.Start})
		}
		if end := uint64(r.Start) + uint64(r.Count); uint64(id)+1 < end {
			out = append(out, IDRange{Start: id + 1, Count: uint32(end - uint64(id) - 1)})
		}
	}
	return out
}

// toSessionRanges translates caller-namespace ranges into session IDs.
func (id identity) toSessionRanges(callerRanges []IDRange, m IDMap, own uint32) []IDRange {
	switch {
	case id.ns.Initial:
		return callerRanges
	case !id.ns.HostIDs():
		// Only the caller's own identity is verifiable.
		for _, r := range callerRanges {
			if r.Contains(own) {
				return []IDRange{{Start: own, Count: 1}}
			}
		}
		return nil
	}
	var out []IDRange
	for _, r := range callerRanges {
		for _, e := range m {
			lo := max(uint64(r.Start), uint64(e.NamespaceID))
			hi := min(uint64(r.Start)+uint64(r.Count), uint64(e.NamespaceID)+uint64(e.Count))
			if lo < hi {
				out = append(out, IDRange{Start: e.ParentID + uint32(lo-uint64(e.NamespaceID)), Count: uint32(hi - lo)})
			}
		}
	}
	return out
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

// unmappedIDError explains a session ID that has no counterpart in the
// caller's namespace. Such an ID is rejected, never substituted.
func unmappedIDError(self identity, stage Stage, kind string, id uint32) error {
	m, own := self.ns.UIDMap, self.UID
	if kind == "GID" {
		m, own = self.ns.GIDMap, self.GID
	}
	if !self.ns.HostIDs() {
		return &SetupError{Stage: stage, Message: fmt.Sprintf(
			"%s mapping failed: Yuhaiin runs in a nested user namespace whose host IDs cannot be resolved (%s), so only its own identity (%s %d of its namespace) can be used automatically; %s %d cannot be verified. Leave the %s empty to use Yuhaiin's identity, or name the parent namespace %s it maps to explicitly",
			kind, describeDepth(self.ns), kind, own, kind, id, kind, kind)}
	}
	return &SetupError{Stage: stage, Message: fmt.Sprintf(
		"%s mapping failed: host %s %d is not mapped into the user namespace Yuhaiin runs in, which maps only host %ss %s",
		kind, kind, id, kind, describeParentRanges(m))}
}

func describeDepth(ns UserNamespace) string {
	if ns.Depth < 0 {
		return "nesting depth unknown: " + ns.DepthError
	}
	return fmt.Sprintf("nesting depth %d", ns.Depth)
}

func describeParentRanges(m IDMap) string {
	parts := make([]string, 0, len(m))
	for _, r := range m {
		if r.Count == 1 {
			parts = append(parts, strconv.FormatUint(uint64(r.ParentID), 10))
		} else {
			parts = append(parts, fmt.Sprintf("%d-%d", r.ParentID, uint64(r.ParentID)+uint64(r.Count)-1))
		}
	}
	return strings.Join(parts, ", ")
}

// planIDMaps decides, before anything is started, whether the requested
// credential can be represented in a rootless session and how. The new
// namespace maps each session ID to the caller-namespace ID it stands for:
// for `podman unshare` (uid_map "0 1009 1") host UID 1009 becomes the line
// "1009 0 1", so the session runs as host UID 1009 and sees it as 1009.
func planIDMaps(self identity, cred Credential) (idMapPlan, error) {
	var plan idMapPlan
	outUID, err := self.parentID(StageUIDMap, "UID", cred.UID, cred.ParentUID)
	if err != nil {
		return plan, err
	}
	uidLine := fmt.Sprintf("%d %d 1", cred.UID, outUID)
	switch {
	case self.CapSetUID, outUID == self.UID:
		plan.uidLines = []string{uidLine}
	case self.newuidmap != "" && inRanges(self.subUIDs, outUID):
		plan.uidLines, plan.uidTool = []string{uidLine}, self.newuidmap
	default:
		reason := "newuidmap is not installed"
		switch {
		case !self.ns.Initial:
			reason = "Yuhaiin lacks CAP_SETUID in its user namespace (subordinate IDs only apply to host processes)"
		case self.newuidmap != "":
			reason = fmt.Sprintf("/etc/subuid does not delegate UID %d to %s", outUID, describeUser(self))
		}
		own, _ := self.sessionUID(self.UID)
		return plan, &SetupError{Stage: StageUIDMap, Message: fmt.Sprintf(
			"UID mapping failed: rootless mode can run the session as the Yuhaiin user (UID %d) only; UID %d would need a subordinate UID mapping, but %s",
			own, cred.UID, reason)}
	}
	if outUID == 0 && !self.CapSetFCAP {
		// Linux 5.12+ (verify_root_map) only lets a writer that holds
		// CAP_SETFCAP over the parent map the parent's UID 0.
		return plan, &SetupError{Stage: StageUIDMap, Message: fmt.Sprintf(
			"UID mapping failed: session UID %d is UID 0 of the user namespace Yuhaiin runs in, and the kernel maps it into a new user namespace only for a process holding CAP_SETFCAP, which Yuhaiin lacks", cred.UID)}
	}
	plan.uidMap = IDMap{{NamespaceID: cred.UID, ParentID: outUID, Count: 1}}

	gids := []uint32{cred.GID}
	for _, group := range cred.Groups {
		if !containsID(gids, group) {
			gids = append(gids, group)
		}
	}
	outGIDs := make([]uint32, len(gids))
	if outGIDs[0], err = self.parentID(StageGIDMap, "GID", cred.GID, cred.ParentGID); err != nil {
		return plan, err
	}
	for i := 1; i < len(gids); i++ {
		var ok bool
		if outGIDs[i], ok = self.callerGID(gids[i]); !ok {
			return plan, unmappedIDError(self, StageGIDMap, "GID", gids[i])
		}
		if outGIDs[i] == outGIDs[0] {
			return plan, &SetupError{Stage: StageGIDMap, Message: fmt.Sprintf(
				"GID mapping failed: supplementary group %d and the primary group %d would both be parent GID %d", gids[i], cred.GID, outGIDs[0])}
		}
	}
	gidLines := func() []string {
		lines := make([]string, len(gids))
		for i := range gids {
			lines[i] = fmt.Sprintf("%d %d 1", gids[i], outGIDs[i])
			plan.gidMap = append(plan.gidMap, IDMapping{NamespaceID: gids[i], ParentID: outGIDs[i], Count: 1})
		}
		return lines
	}
	sameIdentity := outUID == self.UID && outGIDs[0] == self.GID
	switch {
	case sameIdentity && len(cred.Groups) == 0:
		// The caller's own identity keeps the caller's supplementary groups,
		// including groups this namespace does not map (shown as nogroup):
		// setgroups is denied, so the kernel keeps them unchanged.
		plan.gidLines = gidLines()
	case self.CapSetGID && self.ns.SetgroupsAllowed:
		plan.gidLines = gidLines()
		plan.setGroups = true
	case outGIDs[0] == self.GID && len(cred.Groups) == 0:
		// Unprivileged gid_map writes require setgroups to be denied, so the
		// session keeps the caller's supplementary groups.
		plan.gidLines = gidLines()
	case self.newgidm != "" && allInRanges(self.subGIDs, self.GID, outGIDs):
		plan.gidLines = gidLines()
		plan.gidTool, plan.setGroups = self.newgidm, true
	case outGIDs[0] == self.GID:
		message := "GID mapping failed: supplementary groups cannot be changed in an unprivileged user namespace without newgidmap and /etc/subgid; leave them empty (the session then keeps the groups of the Yuhaiin process)"
		if self.CapSetGID {
			message = "GID mapping failed: setgroups(2) is denied in the user namespace Yuhaiin runs in (/proc/self/setgroups is \"deny\"), so supplementary groups cannot be set; leave them empty (the session then keeps the groups of the Yuhaiin process)"
		}
		return plan, &SetupError{Stage: StageGIDMap, Message: message}
	default:
		reason := "newgidmap is not installed"
		switch {
		case self.CapSetGID:
			reason = "setgroups(2) is denied in the user namespace Yuhaiin runs in, so the Yuhaiin process's supplementary groups could not be dropped"
		case !self.ns.Initial:
			reason = "Yuhaiin lacks CAP_SETGID in its user namespace (subordinate IDs only apply to host processes)"
		case self.newgidm != "":
			reason = fmt.Sprintf("/etc/subgid does not delegate GID %d to %s", outGIDs[0], describeUser(self))
		}
		own, _ := self.sessionGID(self.GID)
		return plan, &SetupError{Stage: StageGIDMap, Message: fmt.Sprintf(
			"GID mapping failed: rootless mode can run the session with the Yuhaiin group (GID %d) only; GID %d would need a subordinate GID mapping, but %s",
			own, cred.GID, reason)}
	}
	return plan, nil
}

// parentID selects the caller-namespace ID a session ID maps to: the
// automatic translation, or a manual override of the session's immediate
// parent ID. An override is accepted only for an ID the caller's namespace
// really maps, and, where the automatic translation can resolve host IDs,
// only if it agrees with it: otherwise the session would show one host ID
// while acting as another. Whether the caller may map the ID at all is
// checked by planIDMaps and finally by the kernel.
func (id identity) parentID(stage Stage, kind string, session uint32, override *uint32) (uint32, error) {
	m, callerID := id.ns.UIDMap, id.callerUID
	if kind == "GID" {
		m, callerID = id.ns.GIDMap, id.callerGID
	}
	auto, autoOK := callerID(session)
	if override == nil {
		if !autoOK {
			return 0, unmappedIDError(id, stage, kind, session)
		}
		return auto, nil
	}
	parent := *override
	if _, mapped := m.ToParent(parent); !mapped {
		return 0, &SetupError{Stage: stage, Message: fmt.Sprintf(
			"%s mapping failed: the manual parent namespace %s %d does not exist in the user namespace Yuhaiin runs in, which maps only %ss %s",
			kind, kind, parent, kind, describeNamespaceRanges(m))}
	}
	if id.ns.HostIDs() {
		host, _ := id.ns.toHost(m, parent)
		if !autoOK || auto != parent {
			return 0, &SetupError{Stage: stage, Message: fmt.Sprintf(
				"%s mapping failed: the manual parent namespace %s %d is host %s %d, not the session %s %d; Yuhaiin resolves host IDs automatically here, so remove the override",
				kind, kind, parent, kind, host, kind, session)}
		}
	}
	return parent, nil
}

func describeNamespaceRanges(m IDMap) string {
	return describeParentRanges(namespaceAsParent(m))
}

func namespaceAsParent(m IDMap) IDMap {
	out := make(IDMap, len(m))
	for i, r := range m {
		out[i] = IDMapping{ParentID: r.NamespaceID, Count: r.Count}
	}
	return out
}

// rootfulCredential translates session IDs into the caller's namespace, in
// which rootful sessions run. Neither the session IDs nor the IDs they stand
// for may be root.
func rootfulCredential(self identity, cred Credential) (Credential, error) {
	var out Credential
	var ok bool
	if cred.ParentUID != nil || cred.ParentGID != nil {
		return out, errors.New("sessionnet: parent namespace IDs only apply to rootless sessions; rootful sessions run in the caller's user namespace")
	}
	if out.UID, ok = self.callerUID(cred.UID); !ok {
		return out, unmappedIDError(self, StageCredentials, "UID", cred.UID)
	}
	if out.GID, ok = self.callerGID(cred.GID); !ok {
		return out, unmappedIDError(self, StageCredentials, "GID", cred.GID)
	}
	out.Groups = make([]uint32, 0, len(cred.Groups))
	for _, group := range cred.Groups {
		g, ok := self.callerGID(group)
		if !ok {
			return out, unmappedIDError(self, StageCredentials, "GID", group)
		}
		if g == 0 {
			return out, errors.New("sessionnet: supplementary root group is forbidden in rootful mode")
		}
		out.Groups = append(out.Groups, g)
	}
	if out.UID == 0 || out.GID == 0 {
		return out, fmt.Errorf("sessionnet: rootful mode requires an unprivileged uid/gid, but %d:%d is %d:%d, root of the user namespace Yuhaiin runs in", cred.UID, cred.GID, out.UID, out.GID)
	}
	return out, nil
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
		return fmt.Sprintf("%s (UID %d)", self.username, self.UID)
	}
	return fmt.Sprintf("UID %d", self.UID)
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
		// One write(2): the kernel accepts a map only once and as a whole.
		fd, err := unix.Open(fmt.Sprintf("/proc/%d/%s", pid, file), unix.O_WRONLY|unix.O_CLOEXEC, 0)
		if err != nil {
			return err
		}
		defer unix.Close(fd)
		_, err = unix.Write(fd, []byte(strings.Join(lines, "\n")+"\n"))
		return err
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

// verifyInsideIdentity compares what the helper read inside the session
// (its /proc/self/uid_map, gid_map and IDs) with the plan. A difference
// means the session is not the identity it claims, and it is refused.
func verifyInsideIdentity(r *readyReply, cred Credential, plan idMapPlan) error {
	if r == nil {
		return &SetupError{Stage: StageHandshake, Message: "the session helper did not report its identity"}
	}
	uidMap, err1 := ParseIDMap([]byte(r.UIDMap))
	gidMap, err2 := ParseIDMap([]byte(r.GIDMap))
	if err := errors.Join(err1, err2); err != nil {
		return &SetupError{Stage: StageUIDMap, Message: "the session reported unreadable ID maps", Err: err}
	}
	same := func(ids []uint32, want uint32) bool {
		return len(ids) == 3 && ids[0] == want && ids[1] == want && ids[2] == want
	}
	if !equalMaps(uidMap, plan.uidMap) || !same(r.UIDs, cred.UID) {
		return &SetupError{Stage: StageUIDMap, Message: fmt.Sprintf(
			"UID mapping failed: inside the session uid_map is %q and the UIDs are %v, but %q and UID %d were planned",
			strings.TrimSpace(uidMap.String()), r.UIDs, strings.TrimSpace(plan.uidMap.String()), cred.UID)}
	}
	if !equalMaps(gidMap, plan.gidMap) || !same(r.GIDs, cred.GID) {
		return &SetupError{Stage: StageGIDMap, Message: fmt.Sprintf(
			"GID mapping failed: inside the session gid_map is %q and the GIDs are %v, but %q and GID %d were planned",
			strings.TrimSpace(gidMap.String()), r.GIDs, strings.TrimSpace(plan.gidMap.String()), cred.GID)}
	}
	return nil
}

// equalMaps compares maps as sets of lines; the kernel may reorder them.
func equalMaps(a, b IDMap) bool {
	if len(a) != len(b) {
		return false
	}
	for _, r := range a {
		found := false
		for _, o := range b {
			found = found || r == o
		}
		if !found {
			return false
		}
	}
	return true
}
