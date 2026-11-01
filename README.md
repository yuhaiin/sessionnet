# sessionnet

[![CI](https://github.com/yuhaiin/sessionnet/actions/workflows/ci.yml/badge.svg)](https://github.com/yuhaiin/sessionnet/actions/workflows/ci.yml)

`sessionnet` is a small Go module that starts Linux processes in an isolated network namespace and exposes their TUN packet stream to a supervising application. It is intended for integrations such as an SSH server whose shell commands must use an application-controlled routing and policy engine.

**Status:** experimental Linux backend. The package is not an SSH server or a security sandbox.

## How it works

1. Open a nonpersistent L3 TUN device with `IFF_TUN | IFF_NO_PI`.
2. Start the session command behind a one-time startup gate in private network and mount namespaces as a non-root user.
3. Move the TUN interface into that network namespace, configure IPv4 and optional IPv6 addresses, and set namespace-local default routes.
4. Bind-mount an isolated `/etc/resolv.conf` with `198.18.0.1` as the DNS resolver. The host's DNS and routes are unchanged.
5. Duplicate the TUN file descriptor into the supervising application's packet stack. Only after its packet handler is ready, call `Release()` to run the command.
6. On cancellation or `Close()`, kill the session process group and release the owned TUN FD. The caller owns any duplicated FDs.

There is no NAT, built-in DNS server, or Internet access in this module. **The supervising application's packet stack must forward traffic and answer DNS.** If initialization fails, `Open()` fails and does not expose the host network as a fallback.

## Requirements

- Linux with `/dev/net/tun`, `CAP_SYS_ADMIN`, and `CAP_NET_ADMIN` for the supervising process.
- `ip` from iproute2 and `nsenter`/`mount` from util-linux.
- A valid **non-root** UID/GID to run the command. The supplied supplementary groups replace inherited groups.
- A packet stack that reads/writes raw L3 packets from the TUN FD and applies the application's routing policy.

No CGO and no external Go module dependencies. The package exposes API stubs that return `ErrUnsupported` on other operating systems.

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

The application stack needs `198.18.0.1` as a virtual IPv4 address (and `fd7a:115c:a1e0::1` for IPv6), must handle IP packets from the session's TUN, and must serve DNS on UDP/TCP port 53. The session has `198.18.0.2/30` and optionally `fd7a:115c:a1e0::2/64`. Local loopback (`127.0.0.1` and `::1`) intentionally remains inside the session namespace.

The SSH server, authentication, PTYs, user identity, routing rules and all outbound connections belong to the integrating application. In Yuhaiin, the intended target is the existing lightweight network stack and inbound handlers.

## Limitations and security boundaries

- **This is network isolation, not a general-purpose sandbox.** It does not isolate the host filesystem, processes, Unix-domain sockets, inherited descriptors, or setuid programs. Do not expose untrusted SSH users without separate filesystem/privilege isolation and a narrowly scoped privileged helper.
- The supervisor requires broad Linux capabilities. A production deployment should move privileged setup into an audited helper and drop privileges before accepting user input.
- Process-group cleanup handles normal descendants but does **not** contain children that daemonize into new process groups/sessions. Strict containment requires cgroup v2, including recovery after supervisor crashes.
- Namespace-local routes alone do not stop a sufficiently privileged guest from changing its own network configuration; the command should always run without effective networking capabilities.
- Do not use application packet handling or resolver failures as a reason to dial directly from the isolated process. The integrating application must fail closed and close the session when its packet stack stops.
- This initial implementation uses command-line `ip`, `nsenter` and `mount`. It needs controlled executable paths and a trustworthy host installation.
- It has not yet been tested with a production SSH implementation.

## Testing

```bash
go test ./...
go test -race ./...
go vet ./...

# Requires a suitably privileged Linux VM or host.
SESSIONNET_INTEGRATION=1 go test -run TestLinuxSessionIntegration -v ./...
```

Ordinary unit tests require no capabilities. CI runs formatting, unit tests, race detection, vetting, cross-platform builds, and privileged Linux namespace tests on an ephemeral GitHub-hosted runner. Locally, privileged tests are opt-in and should run only on an isolated test host.
