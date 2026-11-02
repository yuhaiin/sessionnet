# sessionnet

[![CI](https://github.com/yuhaiin/sessionnet/actions/workflows/ci.yml/badge.svg)](https://github.com/yuhaiin/sessionnet/actions/workflows/ci.yml)

`sessionnet` is a small Go module that starts Linux processes in an isolated network namespace and exposes their TUN packet stream to a supervising application. It is intended for integrations such as an SSH server whose shell commands must use an application-controlled routing and policy engine.

**Status:** experimental Linux backend. The package is not an SSH server or a security sandbox.

## How it works

1. Open a nonpersistent L3 TUN device with `IFF_TUN | IFF_NO_PI`.
2. Start the session command behind a one-time startup gate in private network and mount namespaces as a non-root user.
3. Move the TUN interface into that network namespace, configure IPv4 and optional IPv6 addresses, and set namespace-local default routes.
4. Bind-mount an isolated `/etc/resolv.conf` with `172.31.254.1` as the DNS resolver. The host's DNS and routes are unchanged.
5. Duplicate the TUN file descriptor into the supervising application's packet stack. Only after its packet handler is ready, call `Release()` to run the command.
6. On cancellation or `Close()`, kill the session process group and release the owned TUN FD. The caller owns any duplicated FDs.

There is no NAT, built-in DNS server, or Internet access in this module. **The supervising application's packet stack must forward traffic and answer DNS.** If initialization fails, `Open()` fails and does not expose the host network as a fallback.

## Address selection

The default IPv4 link is `172.31.254.1` (gateway) and `172.31.254.2/30`
(session). The optional IPv6 link is `fd42:7d2a:9b31::1` (gateway) and
`fd42:7d2a:9b31::2/64` (session). The defaults deliberately avoid the
`198.18.0.0/15` FakeIP benchmark range, `2001:2::/48` FakeIP IPv6 range,
and Tailscale's `fd7a:115c:a1e0::/48` ULA prefix.

An integrator can provide `Config.Addresses` as `AddressConfig` to choose
another /30 IPv4 and /64 IPv6 subnet. `Resolve(ipv6)` applies defaults and
validates the network endpoints. **The embedding application must additionally
check these links for overlap with its active FakeIP or VPN routes**; no
hardcoded private subnet can guarantee avoiding every deployment-specific route.

## Strict process containment (cgroup v2)

For SSH access, create one `CgroupManager` per listening SSH inbound:

```go
manager, err := sessionnet.NewCgroupManager("/sys/fs/cgroup/yuhaiin/ssh/<stable-inbound-id>")
if err != nil { return err }
defer manager.Close()

session, err := sessionnet.Open(ctx, sessionnet.Config{
    Command: []string{"/bin/sh", "-l"},
    Credential: &sessionnet.Credential{UID: 65534, GID: 65534},
    Cgroup: manager,
})
```

The manager holds an exclusive lock on this stable cgroup v2 root, kills
`session-*` cgroups left by the previous supervisor before accepting traffic,
and fails closed if cleanup or locking is unavailable. The kernel atomically
places the namespace owner and every `Session.Spawn` child in the same
cgroup via `CLONE_INTO_CGROUP`. On shutdown `cgroup.kill` kills the full
process tree, including detached process groups. No PID enumeration is used.

The root MUST be a writable cgroup v2 directory delegated to the supervisor;
not a normal data directory. Linux kernel 5.14+ with `cgroup.kill` and
`clone3(CLONE_INTO_CGROUP)` support is required. The library never falls
back to a racy post-start PID migration. Use one distinct, stable root per
SSH inbound, and do not grant guest users write access to the cgroup tree.
A running supervisor holds a root lock to prevent a second instance from
reaping live sessions. The lock is automatically released if the process dies.

With `Config.Cgroup == nil`, existing standalone callers retain the earlier
best-effort process-group cleanup. SSH integrations SHOULD require a manager
and refuse to enable the listener if the cgroup root cannot be prepared.
Cgroup isolation does not isolate host filesystems or Unix sockets.

## Requirements

- Linux with `/dev/net/tun`, `CAP_SYS_ADMIN`, and `CAP_NET_ADMIN` for the supervising process.
- A valid **non-root** UID/GID to run the command. The supplied supplementary groups replace inherited groups.
- A packet stack that reads/writes raw L3 packets from the TUN FD and applies the application's routing policy.

No CGO and no system networking CLI dependencies. Linux network setup uses `vishvananda/netlink`, `vishvananda/netns`, and `golang.org/x/sys/unix`. The package exposes API stubs that return `ErrUnsupported` on other operating systems.

## Example

```go
package example

import (
    "context"
    "os"

    "github.com/yuhaiin/sessionnet"
)

func run(ctx context.Context, stackFactory func(*os.File) (func() error, error)) error {
    session, err := sessionnet.Open(ctx, sessionnet.Config{
        Command: []string{"/bin/sh", "-l"},
        Credential: &sessionnet.Credential{UID: 65534, GID: 65534},
        IPv6: true,
    })
    if err != nil { return err }
    defer session.Close()

    packets, err := session.DupTun()
    if err != nil { return err }
    // stackFactory takes ownership of packets on success.
    closeStack, err := stackFactory(packets)
    if err != nil { _ = packets.Close(); return err }
    defer closeStack()

    // The child cannot connect until the packet stack is running.
    if err := session.Release(); err != nil { return err }
    return session.Wait()
}
```

The application stack needs `172.31.254.1` as a virtual IPv4 address (and `fd42:7d2a:9b31::1` for IPv6), must handle IP packets from the session's TUN, and must serve DNS on UDP/TCP port 53. The session has `172.31.254.2/30` and optionally `fd42:7d2a:9b31::2/64`. Local loopback (`127.0.0.1` and `::1`) intentionally remains inside the session namespace.

The SSH server, authentication, PTYs, user identity, routing rules and all outbound connections belong to the integrating application. In Yuhaiin, the intended target is the existing lightweight network stack and inbound handlers.

## Limitations and security boundaries

- **This is network isolation, not a general-purpose sandbox.** It does not isolate the host filesystem, processes, Unix-domain sockets, inherited descriptors, or setuid programs. Do not expose untrusted SSH users without separate filesystem/privilege isolation and a narrowly scoped privileged helper.
- The supervisor requires broad Linux capabilities. A production deployment should move privileged setup into an audited helper and drop privileges before accepting user input.
- Process-group cleanup is only best-effort without `Config.Cgroup`; for SSH or long-lived sessions, require `CgroupManager` to kill all descendants and recover orphaned groups at startup.
- Namespace-local routes alone do not stop a sufficiently privileged guest from changing its own network configuration; the command should always run without effective networking capabilities.
- Do not use application packet handling or resolver failures as a reason to dial directly from the isolated process. The integrating application must fail closed and close the session when its packet stack stops.
- Network configuration uses namespace-scoped Netlink handles. The resolver bind mount uses `setns`, `unshare(CLONE_FS)`, and `mount` syscalls on a locked OS thread. Namespace restoration is mandatory before returning the thread to Go.
- It has not yet been tested with a production SSH implementation.

## Testing

```bash
go test ./...
go test -race ./...
go vet ./...

# Requires a suitably privileged Linux VM or host.
SESSIONNET_INTEGRATION=1 go test -run TestLinuxSessionIntegration -v ./...

# Requires a writable, dedicated cgroup v2 parent on a test VM.
SESSIONNET_CGROUP_TEST_ROOT=/sys/fs/cgroup/sessionnet-test go test -run 'TestLinuxCgroup' -v ./...
```

Ordinary unit tests require no capabilities. CI runs formatting, unit tests, race detection, vetting, cross-platform builds, and privileged Linux namespace tests on an ephemeral GitHub-hosted runner. Locally, privileged tests are opt-in and should run only on an isolated test host.
