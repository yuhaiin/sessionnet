//go:build linux

package sessionnet

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"slices"
	"strconv"
	"strings"
)

// Identity reads the identity the session runs as from the kernel. The
// supervisor runs with the session credential, so its /proc entries, which
// the kernel renders in the reader's user namespace, show what the session's
// processes are to the caller and therefore to the filesystem.
func (s *Session) Identity() (SessionIdentity, error) {
	id := SessionIdentity{Credential: s.Credential()}
	pid := s.helper.Process.Pid
	status, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return id, fmt.Errorf("sessionnet: read session identity: %w", err)
	}
	if id.CallerUID, id.CallerGID, id.CallerGroups, err = parseStatusIDs(status); err != nil {
		return id, err
	}
	if s.mode == ModeRootless {
		if id.UIDMap, err = readIDMap(fmt.Sprintf("/proc/%d/uid_map", pid)); err != nil {
			return id, err
		}
		if id.GIDMap, err = readIDMap(fmt.Sprintf("/proc/%d/gid_map", pid)); err != nil {
			return id, err
		}
	}
	setgroups, err := os.ReadFile(fmt.Sprintf("/proc/%d/setgroups", pid))
	id.SetgroupsAllowed = err == nil && strings.TrimSpace(string(setgroups)) == "allow"
	// The helper must still be the session supervisor: a PID that exited and
	// was recycled would describe an unrelated process.
	select {
	case <-s.helperDone:
		return id, ErrSupervisorExited
	default:
	}
	return id, nil
}

// parseStatusIDs extracts the effective UID, GID and supplementary groups
// from /proc/PID/status.
func parseStatusIDs(status []byte) (uid, gid uint32, groups []uint32, err error) {
	var haveUID, haveGID bool
	scanner := bufio.NewScanner(bytes.NewReader(status))
	for scanner.Scan() {
		key, value, ok := strings.Cut(scanner.Text(), ":")
		if !ok {
			continue
		}
		fields := strings.Fields(value)
		switch key {
		case "Uid", "Gid":
			if len(fields) < 2 {
				return 0, 0, nil, fmt.Errorf("sessionnet: malformed %s line in process status", key)
			}
			v, perr := strconv.ParseUint(fields[1], 10, 32)
			if perr != nil {
				return 0, 0, nil, fmt.Errorf("sessionnet: malformed %s line in process status: %w", key, perr)
			}
			if key == "Uid" {
				uid, haveUID = uint32(v), true
			} else {
				gid, haveGID = uint32(v), true
			}
		case "Groups":
			groups = make([]uint32, 0, len(fields))
			for _, field := range fields {
				v, perr := strconv.ParseUint(field, 10, 32)
				if perr != nil {
					return 0, 0, nil, fmt.Errorf("sessionnet: malformed Groups line in process status: %w", perr)
				}
				groups = append(groups, uint32(v))
			}
		}
	}
	if !haveUID || !haveGID {
		return 0, 0, nil, errors.New("sessionnet: process status lacks Uid or Gid")
	}
	return uid, gid, groups, nil
}

// Inspect reports the caller's user namespace and identity, resolves the
// session credential of cfg and verifies it by creating a probe session,
// which is closed again before Inspect returns. Like Probe, it changes
// nothing outside the probe session's own namespaces. Errors are part of the
// report; a canceled ctx yields a report whose probe failed.
func Inspect(ctx context.Context, cfg Config) Report {
	cfg.Command, cfg.Stdin, cfg.Stdout, cfg.Stderr, cfg.PTYSlave = nil, nil, nil, nil, nil
	r := Report{Caller: currentCaller()}
	r.Features = Features{
		UserNamespace: FeatureUnknown, NetworkNamespace: FeatureUnknown, MountNamespace: FeatureUnknown,
		PIDNamespace: FeatureUnknown, IDMapping: FeatureUnknown, TUN: FeatureUnknown,
		IPv4: FeatureUnknown, IPv6: FeatureUnknown, Supervisor: FeatureUnknown,
	}
	mode, err := cfg.Mode.Resolve()
	if err != nil {
		r.Error = &SetupError{Stage: StageHelper, Message: err.Error()}
		return r
	}
	r.Mode = mode
	self, err := currentIdentity()
	if err != nil {
		r.NamespaceError = err.Error()
		r.Error = asSetupError(StageUserNamespace, err)
		return r
	}
	r.Namespace = &self.ns
	if uid, ok := self.ns.HostUID(self.UID); ok {
		r.HostUID = &uid
	}
	if gid, ok := self.ns.HostGID(self.GID); ok {
		r.HostGID = &gid
	}
	overflow := overflowGID()
	for _, g := range self.Groups {
		host, ok := self.ns.HostGID(g)
		// A group the namespace does not map is shown as the overflow GID,
		// which may also be a mapped GID: never claim a host ID for it.
		if !self.ns.Initial && g == overflow {
			host, ok = 0, false
		}
		r.Groups = append(r.Groups, GroupID{ID: g, HostID: host, HostMapped: ok})
	}

	if mode == ModeRootless {
		r.UIDRanges, r.GIDRanges = self.usableUIDs(), self.usableGIDs()
		r.ParentUIDRanges, r.ParentGIDRanges = self.usableParentUIDs(), self.usableParentGIDs()
	}
	cred, err := resolveCredential(mode, cfg.Credential, self)
	if err == nil {
		err = validate(cfg, mode, cred)
	}
	if err != nil {
		r.Error = asSetupError(StageCredentials, err)
		return r
	}
	r.Credential = &cred
	var plan idMapPlan
	want := cred
	if mode == ModeRootless {
		plan, err = planIDMaps(self, cred)
		if err == nil {
			want.UID, _ = plan.uidMap.ToParent(cred.UID)
			want.GID, _ = plan.gidMap.ToParent(cred.GID)
			r.InheritsGroups = !plan.setGroups
		}
	} else {
		want, err = rootfulCredential(self, cred)
	}
	if err != nil {
		r.Error = asSetupError(StageCredentials, err)
		if mode == ModeRootless {
			r.Features.IDMapping = FeatureUnavailable
		}
		return r
	}

	s, err := Open(ctx, cfg)
	if err != nil {
		r.Error = asSetupError(StageHelper, err)
		r.Features = featuresAfterFailure(r.Features, mode, r.Error.Stage, cfg.IPv6)
		return r
	}
	defer s.Close()
	r.Features = Features{
		UserNamespace: FeatureAvailable, NetworkNamespace: FeatureAvailable, MountNamespace: FeatureAvailable,
		PIDNamespace: FeatureAvailable, IDMapping: FeatureAvailable, TUN: FeatureAvailable,
		IPv4: FeatureAvailable, IPv6: FeatureUnknown, Supervisor: FeatureAvailable,
	}
	if mode == ModeRootful {
		r.Features.UserNamespace = FeatureUnknown
	}
	if cfg.IPv6 {
		r.Features.IPv6 = FeatureAvailable
	}
	identity, err := s.Identity()
	if err != nil {
		r.Error = asSetupError(StageCredentials, err)
		return r
	}
	r.Session = &identity
	r.IdentityVerified = identity.CallerUID == want.UID && identity.CallerGID == want.GID
	if mode == ModeRootless {
		r.IdentityVerified = r.IdentityVerified && slices.Equal(identity.UIDMap, plan.uidMap) && slices.Equal(identity.GIDMap, plan.gidMap)
	}
	if r.InheritsGroups {
		r.IdentityVerified = r.IdentityVerified && sameGroupSet(identity.CallerGroups, self.Groups)
	}
	if !r.IdentityVerified {
		r.Error = &SetupError{Stage: StageCredentials, Message: fmt.Sprintf(
			"the probe session runs as %d:%d in Yuhaiin's user namespace, but %d:%d was planned", identity.CallerUID, identity.CallerGID, want.UID, want.GID)}
	}
	return r
}

func sameGroupSet(a, b []uint32) bool {
	a, b = slices.Clone(a), slices.Clone(b)
	slices.Sort(a)
	slices.Sort(b)
	return slices.Equal(slices.Compact(a), slices.Compact(b))
}

func asSetupError(stage Stage, err error) *SetupError {
	var setup *SetupError
	if errors.As(err, &setup) {
		return setup
	}
	return &SetupError{Stage: stage, Message: strings.TrimPrefix(err.Error(), "sessionnet: "), Err: err}
}

// featuresAfterFailure marks the stages a failed Open completed as
// available, the failed one as unavailable and the rest as unknown. Stages
// run in the order: namespaces (one clone), ID maps, credentials, mounts and
// resolver, TUN, link configuration, diagnostics, supervisor.
// stageSupervisor groups the stages after the TUN link is configured.
const stageSupervisor Stage = "supervisor"

func featuresAfterFailure(f Features, mode Mode, stage Stage, ipv6 bool) Features {
	order := []Stage{StageNamespaces, StageUIDMap, StageCredentials, StageMount, StageTUN, StageNetwork, stageSupervisor}
	failedAt := map[Stage]Stage{
		StageUserNamespace: StageNamespaces, StagePIDNamespace: StageNamespaces, StageNamespaces: StageNamespaces,
		StageHelper: StageNamespaces, StageCgroup: StageNamespaces,
		StageUIDMap: StageUIDMap, StageGIDMap: StageUIDMap, StageCredentials: StageCredentials,
		StageMount: StageMount, StageResolver: StageMount, StageTUN: StageTUN, StageNetwork: StageNetwork,
		StageDiagnostics: stageSupervisor, StagePrivileges: stageSupervisor, StageHandshake: stageSupervisor,
	}[stage]
	reached := slices.Index(order, failedAt)
	if reached < 0 {
		return f
	}
	status := func(step Stage) FeatureStatus {
		switch i := slices.Index(order, step); {
		case i < reached:
			return FeatureAvailable
		case i == reached:
			return FeatureUnavailable
		}
		return FeatureUnknown
	}
	if failedAt != StageNamespaces {
		f.NetworkNamespace, f.MountNamespace, f.PIDNamespace = FeatureAvailable, FeatureAvailable, FeatureAvailable
		if mode == ModeRootless {
			f.UserNamespace = FeatureAvailable
		}
	} else {
		switch stage {
		case StageUserNamespace:
			f.UserNamespace = FeatureUnavailable
		case StagePIDNamespace:
			f.PIDNamespace = FeatureUnavailable
		case StageNamespaces:
			f.NetworkNamespace, f.MountNamespace = FeatureUnavailable, FeatureUnavailable
		}
	}
	if mode == ModeRootless {
		f.IDMapping = status(StageUIDMap)
	}
	f.TUN = status(StageTUN)
	f.IPv4 = status(StageNetwork)
	if ipv6 {
		f.IPv6 = status(StageNetwork)
	}
	f.Supervisor = status(stageSupervisor)
	return f
}
