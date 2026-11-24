package sessionnet

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"slices"
	"strconv"
)

// IDMapping is one line of a user namespace ID map (/proc/PID/uid_map or
// gid_map): Count consecutive IDs starting at NamespaceID inside the
// namespace correspond to the IDs starting at ParentID in its parent user
// namespace. The parent is not necessarily the initial (host) namespace.
type IDMapping struct {
	NamespaceID uint32 `json:"namespaceID"`
	ParentID    uint32 `json:"parentID"`
	Count       uint32 `json:"count"`
}

// IDMap is a complete user namespace UID or GID map.
type IDMap []IDMapping

// maxIDMapExtents is the kernel limit on lines in one map (Linux 4.15+).
const maxIDMapExtents = 340

// noID is the 32-bit value the kernel never maps ((uid_t)-1). It is also
// what /proc/PID/uid_map shows for a parent ID the reader cannot see.
const noID = ^uint32(0)

// IdentityIDMap maps every ID to itself, as the initial user namespace does.
func IdentityIDMap() IDMap { return IDMap{{NamespaceID: 0, ParentID: 0, Count: noID}} }

// ParseIDMap parses the text format of /proc/PID/uid_map and gid_map and
// validates it like the kernel does: ranges must not overflow 32 bits or
// overlap in either column.
func ParseIDMap(data []byte) (IDMap, error) {
	var m IDMap
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		fields := bytes.Fields(scanner.Bytes())
		if len(fields) == 0 {
			continue
		}
		if len(fields) != 3 {
			return nil, fmt.Errorf("sessionnet: invalid ID map line %q", scanner.Text())
		}
		var values [3]uint32
		for i, field := range fields {
			v, err := strconv.ParseUint(string(field), 10, 32)
			if err != nil {
				return nil, fmt.Errorf("sessionnet: invalid ID map line %q: %w", scanner.Text(), err)
			}
			values[i] = uint32(v)
		}
		m = append(m, IDMapping{NamespaceID: values[0], ParentID: values[1], Count: values[2]})
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if err := m.Validate(); err != nil {
		return nil, err
	}
	return m, nil
}

// Validate rejects maps the kernel would refuse: empty or zero-length
// ranges, ranges that wrap around 2^32, too many lines, and ranges that
// overlap in the namespace or in the parent column.
func (m IDMap) Validate() error {
	if len(m) == 0 {
		return errors.New("sessionnet: empty ID map")
	}
	if len(m) > maxIDMapExtents {
		return fmt.Errorf("sessionnet: ID map has %d ranges; the kernel allows %d", len(m), maxIDMapExtents)
	}
	for i, r := range m {
		if r.Count == 0 {
			return fmt.Errorf("sessionnet: ID map range %d is empty", i)
		}
		if uint64(r.NamespaceID)+uint64(r.Count) > 1<<32 || uint64(r.ParentID)+uint64(r.Count) > 1<<32 {
			return fmt.Errorf("sessionnet: ID map range %d overflows 32 bits", i)
		}
		for j := range i {
			o := m[j]
			if overlaps(r.NamespaceID, r.Count, o.NamespaceID, o.Count) {
				return fmt.Errorf("sessionnet: ID map ranges %d and %d overlap inside the namespace", j, i)
			}
			if overlaps(r.ParentID, r.Count, o.ParentID, o.Count) {
				return fmt.Errorf("sessionnet: ID map ranges %d and %d overlap in the parent namespace", j, i)
			}
		}
	}
	return nil
}

func overlaps(a, an, b, bn uint32) bool {
	return uint64(a) < uint64(b)+uint64(bn) && uint64(b) < uint64(a)+uint64(an)
}

// ToParent translates an ID of the namespace into its parent namespace. It
// reports false for IDs the map does not cover; they appear as the
// overflow ID (normally 65534, "nobody") and never as another user.
func (m IDMap) ToParent(id uint32) (uint32, bool) {
	for _, r := range m {
		if id >= r.NamespaceID && uint64(id) < uint64(r.NamespaceID)+uint64(r.Count) {
			return r.ParentID + (id - r.NamespaceID), true
		}
	}
	return 0, false
}

// FromParent translates an ID of the parent namespace into the namespace,
// the inverse of ToParent.
func (m IDMap) FromParent(id uint32) (uint32, bool) {
	for _, r := range m {
		if id >= r.ParentID && uint64(id) < uint64(r.ParentID)+uint64(r.Count) {
			return r.NamespaceID + (id - r.ParentID), true
		}
	}
	return 0, false
}

// IsIdentity reports whether the map is the full identity map of the
// initial user namespace.
func (m IDMap) IsIdentity() bool {
	return len(m) == 1 && m[0] == IdentityIDMap()[0]
}

// ResolveIDChain translates an ID of the innermost namespace through a chain
// of maps, innermost first, to the outermost parent. It fails if any level
// does not map the ID; nothing is guessed.
func ResolveIDChain(id uint32, chain ...IDMap) (uint32, bool) {
	for _, m := range chain {
		var ok bool
		if id, ok = m.ToParent(id); !ok {
			return 0, false
		}
	}
	return id, true
}

// LookupIDChain is the inverse of ResolveIDChain: it translates an ID of the
// outermost namespace into the innermost one.
func LookupIDChain(id uint32, chain ...IDMap) (uint32, bool) {
	for _, m := range slices.Backward(chain) {
		var ok bool
		if id, ok = m.FromParent(id); !ok {
			return 0, false
		}
	}
	return id, true
}

// String renders the map in the /proc format.
func (m IDMap) String() string {
	var b []byte
	for _, r := range m {
		b = fmt.Appendf(b, "%d %d %d\n", r.NamespaceID, r.ParentID, r.Count)
	}
	return string(b)
}
