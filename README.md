# sessionnet

[![CI](https://github.com/yuhaiin/sessionnet/actions/workflows/ci.yml/badge.svg)](https://github.com/yuhaiin/sessionnet/actions/workflows/ci.yml)

`sessionnet` starts Linux processes in an isolated network environment and
exposes its TUN packet stream to a supervising application. It is intended
for integrations such as an SSH server whose commands must use an
application-controlled routing and policy engine.

**Status:** experimental Linux backend. Not an SSH server and not a
filesystem sandbox.

## Modes

- **Rootless (default).** No host privilege at all: no root, no `setcap`,
  no `CAP_SYS_ADMIN` or `CAP_NET_ADMIN` on the host. Sessions get user,
  network, mount and PID namespaces.
- **Rootful.** For callers that are root: network, mount and PID namespaces
  in the caller's user namespace, with an arbitrary non-root credential.

Both modes share one implementation; only namespace creation and the
credential switch differ.

## How it works

1. `Open` re-executes the current binary (`/proc/self/exe`) as a helper,
   cloned into `CLONE_NEWNET|CLONE_NEWNS|CLONE_NEWPID` (plus
   `CLONE_NEWUSER` when rootless). The package dispatches the helper from an
   `init` function, so the integrating binary needs no change to `main`.
2. Rootless: while the helper waits on its `SOCK_SEQPACKET` control socket,
   the parent writes the UID/GID maps (see [Credentials](#credentials)):
   each session ID is mapped to the ID of the caller's namespace it stands
   for. It writes them directly for its own IDs (denying `setgroups`), or for
   any ID of its namespace when it has `CAP_SETUID`/`CAP_SETGID`;
   subordinate IDs from `/etc/subuid`/`/etc/subgid` use
   `newuidmap`/`newgidmap` (initial namespace only), which are optional.
   Unmappable IDs fail before anything is started.
3. The helper, using capabilities of its own user namespace only, makes
   mounts private, bind-mounts a session `resolv.conf` (and optionally an
   `nsswitch.conf` with `hosts: files dns`) from an anonymous tmpfs, mounts a
   `/proc` for the PID namespace, enables loopback, creates the TUN with
   `TUNSETIFF`, and configures MTU, addresses and default routes via netlink
   in its own namespace. It opens a `NETLINK_SOCK_DIAG` socket.
4. The TUN, sock_diag socket and a network-namespace handle are sent to the
   parent with `SCM_RIGHTS`.
5. On one locked thread the helper clears the bounding set, locks securebits,
   switches credentials (rootful), clears ambient/inheritable/permitted/
   effective capabilities, sets `no_new_privs`, and `execve`s the supervisor.
   The supervisor verifies `/proc/self/status` shows no privileges, becomes
   non-dumpable, and reports ready. As PID 1 it starts commands, forwards
   signals and reaps every process, including orphans.

The parent never calls `setns`; nothing on the host (interfaces, routes,
rules, firewall, `/etc/resolv.conf`) is changed. There is no NAT, DNS server
or Internet access in this module: **the application's packet stack must
forward traffic and answer DNS.** On any failure `Open` returns a
`*SetupError` with a `Stage` and an actionable `Message`; it never exposes
the host network as a fallback.

## Example

```go
session, err := sessionnet.Open(ctx, sessionnet.Config{IPv6: true}) // rootless, caller's UID/GID
if err != nil {
    return err // e.g. "User Namespace is disabled: ..." or "/dev/net/tun is not accessible ..."
}
defer session.Close()

packets, err := session.DupTun()
if err != nil { return err }
closeStack, err := stackFactory(packets) // takes ownership of packets
if err != nil { _ = packets.Close(); return err }
defer closeStack()

if err := session.Release(); err != nil { return err } // packet path ready
p, err := session.Spawn(ctx, sessionnet.Config{Command: []string{"/bin/sh", "-l"}, Stdin: in, Stdout: out, Stderr: out})
if err != nil { return err }
return p.Wait() // *sessionnet.ExitError for a non-zero exit
```

`Config.Command` can instead name an initial command started by `Release`
(`Wait`/`Signal` then refer to it). `DupDiag` and `DupNetNS` give an
application socket-owner lookup inside the session without entering it.
`Probe` opens and closes a session to check a host at startup.
`SetupTimings` breaks down the cost of `Open`.

The application stack needs `172.31.254.1` (and `fd42:7d2a:9b31::1`) as
virtual addresses and must serve DNS on port 53. Sessions have
`172.31.254.2/30` and optionally `fd42:7d2a:9b31::2/64`; `Config.Addresses`
selects others. Loopback stays inside the session.

## Credentials

`Credential` IDs are **host IDs**: IDs of the initial user namespace. This
matters when the caller itself runs in a user namespace, for example under
`podman unshare`:

```
caller (podman unshare)   uid_map  0 1009 1 / 1 689824 65536
session for host UID 1009 uid_map  1009 0 1
```

The session process is UID 1009 inside, which is UID 0 of the caller's
namespace, which is host UID 1009. Files keep their host owners and are
shown under their host IDs and `/etc/passwd` names, and access is decided
exactly as for host UID 1009. An identity map (`1009 1009 1`) would instead
run the session as host UID 690832 (the caller's namespace UID 1009) and
show the user's files as `nobody`.

The second column of `/proc/self/uid_map` is an ID of the *parent*
namespace, which is the host only for a direct child of the initial
namespace. `CurrentUserNamespace` therefore measures the nesting depth: the
kernel allows nesting up to level 33, so the number of further levels a
chain of helper processes can create is `33 - depth`. A limit or policy can
only stop the chain early, never make a namespace look shallower. Results:

| Caller | Session IDs | Usable IDs |
|---|---|---|
| Initial namespace (native) | host IDs (identity map) | own; any with `CAP_SETUID`/`CAP_SETGID`; `/etc/subuid` via `newuidmap` |
| Depth 1 (`podman unshare`, `unshare -U`, rootless containers) | host IDs, translated through the caller's map | own; any ID the caller's map covers with `CAP_SETUID`/`CAP_SETGID` |
| Deeper or unmeasurable | the caller's namespace IDs | the caller's own identity only (nothing else can be verified) |

IDs that cannot be translated are rejected with a `uid-map`/`gid-map`
`SetupError`; nothing is guessed or substituted. The pure functions
`ParseIDMap`, `IDMap.ToParent`/`FromParent`, `ResolveIDChain` and
`LookupIDChain` implement the translation. Mapping UID 0 of the caller's
namespace (the Podman case) needs `CAP_SETFCAP` there (Linux 5.12+), which
namespace root normally holds.

The rootless default credential (`DefaultCredential`, or a nil
`Config.Credential`) is the caller's own identity. It **keeps the caller's
supplementary groups**: `setgroups` is denied in the session and the kernel
retains every group, including groups the caller's namespace does not map.
Those appear as `nogroup` (65534) but still grant their access, which is the
only way an unprivileged process can preserve them. A credential with a
different UID/GID replaces the groups with `Credential.Groups` when the
caller holds `CAP_SETGID` and its namespace allows `setgroups`, or via
`newgidmap`; otherwise `Credential.Groups` must be empty and the caller's
groups are inherited (only when the GID is the caller's own). If the
caller's own namespace has `setgroups` denied, no session can set groups.

Rootful sessions run in the caller's namespace: the host IDs are translated
into it, and neither the host IDs nor the translated IDs may be 0.

`Inspect` reports the namespace, the caller's identity and capabilities, the
usable ID ranges, and verifies a probe session through the kernel
(`Session.Identity` reads the supervisor's `/proc` entries as the caller sees
them). `Session.UIDToCaller` translates socket owners reported by `DupDiag`
(session IDs) into the caller's namespace, where `/proc` shows owners.

Session processes have no capabilities, an empty bounding set and
`no_new_privs`; setuid programs do not gain privilege.

## Process containment

Every session has a PID namespace. `Session.Close` kills PID 1; the kernel
then kills all remaining processes, including detached and daemonized ones,
before `Close` returns. If the parent dies, the supervisor sees EOF on its
control socket and exits with the same effect.

`CgroupManager` adds cgroup v2 containment on a writable, dedicated subtree:
the helper is placed atomically with `CLONE_INTO_CGROUP`, `cgroup.kill` ends
the tree, and a restarted supervisor reaps sessions orphaned by a crash. For
rootless callers, `DelegatedCgroupRoot` returns a subtree of the caller's own
cgroup only when systemd delegated it (`Delegate=yes`); otherwise use the
PID namespace alone.

## Requirements

- Linux with user (rootless), network, mount and PID namespaces enabled;
  unprivileged user namespaces allowed (`user.max_user_namespaces > 0`,
  `kernel.unprivileged_userns_clone=1` where present, and no AppArmor
  restriction such as Ubuntu's `kernel.apparmor_restrict_unprivileged_userns`).
- `/dev/net/tun` accessible to the caller (kernel default mode `0666`).
- A `/proc` that may be remounted in a user namespace.
- Rootful: `CAP_SYS_ADMIN` and `CAP_NET_ADMIN`.

No CGO and no networking CLI. Other operating systems get stubs returning
`ErrUnsupported`.

## Limitations and security boundaries

- **Network isolation, not a sandbox.** The host filesystem, filesystem
  Unix-domain sockets and inherited descriptors are shared. In rootless mode
  the session normally runs as the caller's own account and can access all
  of its files.
- The session `/proc` hides host processes, so same-user host processes
  cannot be inspected or ptraced from a session.
- Closing the last TUN descriptor unregisters the netdev, which costs the
  kernel ~10–20 ms of RCU grace periods; `Close` includes it.
- A target file that is itself a bind mount of a deleted file (left by older
  releases) cannot be mounted over; this is reported explicitly.

## Testing

```bash
go test -race ./...                       # rootless tests run as a normal user
SESSIONNET_REQUIRE_ROOTLESS=1 go test -v ./...   # fail instead of skip
```

Rootless tests skip, with the reason, only when the host cannot create
rootless sessions. `TestNestedNamespaceIdentity` runs sessions from a
namespace whose root is the test user (Podman's layout) and checks file
ownership, read/write/exec, traversal, creation, deletion and denied access
through the kernel. Under real Podman:

```bash
go test -c -o sessionnet.test .
podman unshare env SESSIONNET_REQUIRE_INHERITED=1 SESSIONNET_EXPECT_HOST_UID=$(id -u) \
    SESSIONNET_EXPECT_HOST_GID=$(id -g) SESSIONNET_GROUP_DIR=/srv/group-only \
    SESSIONNET_DENIED_DIR=/root ./sessionnet.test -test.run InPlace -test.v
``` Failure handling (disabled user/PID/network namespaces,
missing, inaccessible or invalid TUN, rejected UID/GID maps, cancellation)
is tested in nested user namespaces, and rootful mode runs as root of a
`newuidmap` namespace, so none of it needs host root. `TestRootfulModeAsRoot`
and the cgroup tests run on a real root CI host:

```bash
SESSIONNET_CGROUP_TEST_ROOT=/sys/fs/cgroup/<delegated> go test -run TestLinuxCgroup -v .
SESSIONNET_BENCH_MODES=1 go test -run TestBenchmarkModesSameEnvironment -v .
go test -run '^$' -bench BenchmarkSession -benchtime=200x .
```
