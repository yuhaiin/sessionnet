package sessionnet

// This file holds the platform-neutral description of the caller's user
// namespace and of what a host offers for sessions; Inspect fills it in on
// Linux.

// UserNamespace describes the user namespace the calling process runs in.
//
// The kernel only exposes one level of ID mapping to a process: the second
// column of /proc/self/uid_map is an ID of the parent user namespace, which
// is the initial (host) namespace only when the caller is nested exactly one
// level deep. Depth is therefore measured, not assumed; see HostIDs.
type UserNamespace struct {
	// Inode identifies the namespace (/proc/self/ns/user).
	Inode uint64 `json:"inode"`
	// Initial reports whether this is the initial user namespace.
	Initial bool `json:"initial"`
	// Depth is the nesting level: 0 for the initial namespace, 1 for a
	// namespace created directly by a host process (for example by
	// `podman unshare` or `unshare -U`). -1 means it could not be measured.
	Depth int `json:"depth"`
	// UIDMap and GIDMap translate this namespace's IDs into its parent.
	UIDMap IDMap `json:"uidMap"`
	GIDMap IDMap `json:"gidMap"`
	// SetgroupsAllowed mirrors /proc/self/setgroups. When it is "deny",
	// no descendant namespace can ever call setgroups(2).
	SetgroupsAllowed bool `json:"setgroupsAllowed"`
	// DepthError explains why Depth is -1.
	DepthError string `json:"depthError,omitempty"`
}

// HostIDs reports whether IDs of this namespace can be translated into
// host (initial user namespace) IDs exactly.
func (u UserNamespace) HostIDs() bool { return u.Initial || u.Depth == 1 }

// HostUID translates a UID of this namespace into the host UID.
func (u UserNamespace) HostUID(id uint32) (uint32, bool) { return u.toHost(u.UIDMap, id) }

// HostGID translates a GID of this namespace into the host GID.
func (u UserNamespace) HostGID(id uint32) (uint32, bool) { return u.toHost(u.GIDMap, id) }

// NamespaceUID translates a host UID into this namespace.
func (u UserNamespace) NamespaceUID(id uint32) (uint32, bool) { return u.fromHost(u.UIDMap, id) }

// NamespaceGID translates a host GID into this namespace.
func (u UserNamespace) NamespaceGID(id uint32) (uint32, bool) { return u.fromHost(u.GIDMap, id) }

func (u UserNamespace) toHost(m IDMap, id uint32) (uint32, bool) {
	switch {
	case u.Initial:
		return id, id != noID
	case u.Depth == 1:
		return m.ToParent(id)
	}
	return 0, false
}

func (u UserNamespace) fromHost(m IDMap, id uint32) (uint32, bool) {
	switch {
	case u.Initial:
		return id, id != noID
	case u.Depth == 1:
		return m.FromParent(id)
	}
	return 0, false
}

// Caller describes the identity the calling process holds in its own user
// namespace, the starting point of every session credential.
type Caller struct {
	UID    uint32   `json:"uid"`
	GID    uint32   `json:"gid"`
	Groups []uint32 `json:"groups"`
	// Effective capabilities in the caller's user namespace.
	CapSetUID  bool `json:"capSetUID"`
	CapSetGID  bool `json:"capSetGID"`
	CapSetFCAP bool `json:"capSetFCAP"`
	CapSysAdm  bool `json:"capSysAdmin"`
	CapNetAdm  bool `json:"capNetAdmin"`
}

// IDRange is Count consecutive IDs starting at Start.
type IDRange struct {
	Start uint32 `json:"start"`
	Count uint32 `json:"count"`
}

// Contains reports whether id is in the range.
func (r IDRange) Contains(id uint32) bool {
	return id >= r.Start && uint64(id) < uint64(r.Start)+uint64(r.Count)
}

// GroupID is a supplementary group of the caller.
type GroupID struct {
	// ID is the group as the caller's namespace sees it. Groups the
	// namespace does not map are shown as the overflow GID (65534).
	ID uint32 `json:"id"`
	// HostID is valid when HostMapped is set.
	HostID     uint32 `json:"hostID"`
	HostMapped bool   `json:"hostMapped"`
}

// SessionIdentity is the identity of a running session as the kernel
// reports it, read from the session supervisor (PID 1 of the session).
type SessionIdentity struct {
	// Credential holds the session IDs, as processes inside see them.
	Credential Credential `json:"credential"`
	// CallerUID, CallerGID and CallerGroups are the same identity in the
	// caller's user namespace, which decides file access exactly like the
	// caller's own IDs do.
	CallerUID    uint32   `json:"callerUID"`
	CallerGID    uint32   `json:"callerGID"`
	CallerGroups []uint32 `json:"callerGroups"`
	// UIDMap and GIDMap are the session user namespace maps into the
	// caller's namespace (rootless mode only).
	UIDMap IDMap `json:"uidMap,omitempty"`
	GIDMap IDMap `json:"gidMap,omitempty"`
	// SetgroupsAllowed reports whether setgroups(2) is permitted inside.
	SetgroupsAllowed bool `json:"setgroupsAllowed"`
}

// FeatureStatus is the outcome of one check of a Report.
type FeatureStatus string

const (
	FeatureAvailable   FeatureStatus = "available"
	FeatureUnavailable FeatureStatus = "unavailable"
	// FeatureUnknown means the check did not run, for example because an
	// earlier setup stage failed.
	FeatureUnknown FeatureStatus = "unknown"
)

// Features lists what a probe session could set up.
type Features struct {
	UserNamespace    FeatureStatus `json:"userNamespace"`
	NetworkNamespace FeatureStatus `json:"networkNamespace"`
	MountNamespace   FeatureStatus `json:"mountNamespace"`
	PIDNamespace     FeatureStatus `json:"pidNamespace"`
	IDMapping        FeatureStatus `json:"idMapping"`
	TUN              FeatureStatus `json:"tun"`
	IPv4             FeatureStatus `json:"ipv4"`
	IPv6             FeatureStatus `json:"ipv6"`
	Supervisor       FeatureStatus `json:"supervisor"`
}

// Report describes the caller's identity and namespace, the session
// credential a configuration resolves to, and the result of creating a
// short-lived probe session with it.
type Report struct {
	Mode Mode `json:"mode"`
	// Namespace is nil when the caller's user namespace could not be read.
	Namespace      *UserNamespace `json:"namespace,omitempty"`
	NamespaceError string         `json:"namespaceError,omitempty"`
	Caller         Caller         `json:"caller"`
	// HostUID and HostGID are the caller's own IDs on the host, when the
	// namespace can be resolved.
	HostUID *uint32   `json:"hostUID,omitempty"`
	HostGID *uint32   `json:"hostGID,omitempty"`
	Groups  []GroupID `json:"groups"`
	// UIDRanges and GIDRanges list the session IDs a rootless credential
	// may use; anything else is refused with a mapping error.
	UIDRanges []IDRange `json:"uidRanges"`
	GIDRanges []IDRange `json:"gidRanges"`
	// ParentUIDRanges and ParentGIDRanges list the IDs of the caller's own
	// namespace a session ID may map to: what Credential.ParentUID and
	// ParentGID may name.
	ParentUIDRanges []IDRange `json:"parentUIDRanges"`
	ParentGIDRanges []IDRange `json:"parentGIDRanges"`
	// Credential is the session credential cfg resolves to.
	Credential *Credential `json:"credential,omitempty"`
	// InheritsGroups reports that the session keeps the caller's
	// supplementary groups unchanged (setgroups is denied inside).
	InheritsGroups bool `json:"inheritsGroups"`
	// Session is what the kernel reports for the probe session.
	Session *SessionIdentity `json:"session,omitempty"`
	// IdentityVerified reports that the probe session runs as exactly the
	// caller-namespace IDs the credential stands for, so files are accessed
	// with the permissions of those host IDs.
	IdentityVerified bool `json:"identityVerified"`
	// Error explains why the credential or the probe session failed.
	Error    *SetupError `json:"-"`
	Features Features    `json:"features"`
}
