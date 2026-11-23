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
   the parent writes identity UID/GID maps. It writes them directly for its
   own IDs (denying `setgroups`), or for any ID when it has `CAP_SETUID`/
   `CAP_SETGID`; subordinate IDs from `/etc/subuid`/`/etc/subgid` use
   `newuidmap`/`newgidmap`, which are optional. Unmappable IDs fail before
   anything is started.
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

In rootless mode the default credential is the caller's effective UID/GID,
and every ID is identity-mapped, so file ownership keeps its host meaning.
An unprivileged caller cannot call `setgroups` for the session (the kernel
requires it to be denied), so the session **inherits the caller's
supplementary groups**; `Credential.Groups` must then be empty. A caller
with `CAP_SETGID`, or `newgidmap`, replaces them. Rootful sessions require
an explicit non-root credential and always replace groups.

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
rootless sessions. Failure handling (disabled user/PID/network namespaces,
missing, inaccessible or invalid TUN, rejected UID/GID maps, cancellation)
is tested in nested user namespaces, and rootful mode runs as root of a
`newuidmap` namespace, so none of it needs host root. `TestRootfulModeAsRoot`
and the cgroup tests run on a real root CI host:

```bash
SESSIONNET_CGROUP_TEST_ROOT=/sys/fs/cgroup/<delegated> go test -run TestLinuxCgroup -v .
SESSIONNET_BENCH_MODES=1 go test -run TestBenchmarkModesSameEnvironment -v .
go test -run '^$' -bench BenchmarkSession -benchtime=200x .
```
