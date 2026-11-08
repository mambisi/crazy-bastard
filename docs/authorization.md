# Network and execution authorization

Status: proposed architecture, researched on 8 November 2026. This backend and
its TUI are not implemented. `cb host code --monitor` remains a polling observer;
network notifications do not block connections and execution observations occur
after execution may have started. This design does not change that behavior.

[The product design](product.md) now prioritizes a bounded workflow around an
existing isolated-workspace runtime. [The comparison](comparison.md) found close
overlap with existing runtime/editor approval tools. This document retains the
possible native-host authorization adapter; it is a later option if the target
workflow needs it, rather than a commitment to rebuild those engines first.
`cb code` requires isolation and currently refuses launch. Host review requires
`cb host code` explicitly.

## Boundary and components

The intended guarded mode must start enforcement before VS Code or the workspace
runs. Unknown actions are denied unless a matching, narrowly scoped authorization
exists. The terminal UI presents decisions; it is not the security boundary.

| Component | Proposed responsibility |
| --- | --- |
| Network provider | Apply connection decisions using macOS Network Extension flow filtering. |
| Execution and file provider | Use Endpoint Security authorization events to decide covered executions and file operations before they proceed. |
| Broker | Own session identity, request deadlines, bounded queues, one-use grants and enforcement health. |
| TUI | Show verified requests and submit decisions for their exact identities. |
| Current polling observer | Supply best-effort observations without pretending to authorize an operation. |

[Apple's Endpoint Security presentation](https://developer.apple.com/videos/play/wwdc2020/10159/)
distinguishes authorization from notification and directs networking controls to
Network Extension. An Endpoint Security client needs an
[entitlement granted by Apple](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.developer.endpoint-security.client).
The current CLI build is not a provisioned Endpoint Security client.
A supported distribution needs a signed agent/extension, appropriate Network
Extension capabilities, installation approvals and testing on supported systems.
Neither a TUI crate nor `sudo` supplies a missing entitlement. Do not disable SIP
or Code's own sandbox to bypass these requirements.

Network flow verdicts can hold or reject covered traffic before forwarding it.
[Apple documents](https://developer.apple.com/documentation/networkextension/nefilternewflowverdict/pause())
different pause lifetimes for TCP and UDP; a prompt cannot assume that every
request can be kept pending indefinitely. Proxy environment variables alone are
not network isolation: a client can ignore them. A proxy design needs a verified
boundary preventing direct sockets and other unapproved routes.

## Decisions and display

This is a proposed display, not a runnable command or current enforcement UI:

```text
CB authorization | example workspace | enforcement verified

Action:     Execute
Process:    Code Helper -> requested child
Executable: /usr/bin/example-tool
Arguments:  ["example-tool", "scripts/setup"]
State:      Denied; no execution authorized
Reason:     No matching permission for this workspace session

[D] Keep denied   [A] Approve one matching retry   [Q] End session
```

The label names an action requested by a process associated with a workspace.
It must not accuse a repository of an attack merely because it uses a terminal,
build tool or network connection. Display process ancestry and the executable
identity, escaped argument boundaries and the requested file or destination.
When a hostname is unavailable, show the actual IP, port and protocol rather
than guessing a domain. Paths and argument bytes are untrusted terminal input;
controls and directional characters must be visible text. Arguments may contain
secrets: do not persist or upload them, and provide local redaction/reveal rules
without claiming perfect secret detection.

Known-denied operations stay denied and produce a reason. Unknown operations
start denied. There is no blanket permission for all signed programs, all
installed software, `node`, shells or Git: trusted interpreters can execute
untrusted source without changing their executable identity. Network permissions
must be limited to a captured destination/protocol and session. Source and
credential access need separate controls; command approval alone does not stop
in-process payloads or exfiltration to an approved destination.

The deny policy must cover sensitive home resources, persistence destinations
and developer-tool installations outside the repository. Read-only protection
for tool directories matters as well as watching new executables: replacing an
already installed tool can affect later, otherwise ordinary commands.
Repository settings cannot replace broker policy or grant permissions.

## Deadlines and one-use permission

Do not block an Endpoint Security callback while waiting indefinitely for a
person. Each authorization has an OS deadline. Apple's documented behavior for
a missed deadline includes an implicit allow and client termination; ordinary
client restarts are not proof of fail-closed protection. Return an explicit
deny before the deadline, queue a bounded explanation and let a user approve a
subsequent matching attempt. A held request may only receive an allow while its
original deadline and authority are still valid. Never replay an arbitrary
application's rejected command from the broker under a different parent or
working directory.

Apple's newer documentation also defines an explicit
[fail-closed deadline mode](https://developer.apple.com/documentation/endpointsecurity/es_set_deadline_miss_mode(_:_:)).
Use it only after checking OS/API availability and a successful configuration
response; the documentation includes beta availability. Verify its actual
behavior on each supported release. It addresses missed authorization deadlines
and full authorization queues, not every failure or operation outside the event
model. Keep explicit deadlines and deny responses for older supported systems.

A one-use grant captures the session, immutable request, process identity and
creation generation, executable/file identity, exact arguments where applicable,
working directory and requested destination/access. Changing the target,
replacing an executable, ending the process/session, changing policy or expiring
a deadline invalidates the grant. Use OS process identities, not PID alone;
descendant scope must survive ordinary reparenting without accidentally including
an unrelated process. Reuse the backend's original operation handle and check
the allow/deny response result. Do not enable broad authorization caching for
one-use grants. The displayed state comes from an accepted backend response.

Queue overflow, TUI exit or a disconnected control channel must not mint grants.
The daemon independently owns deny decisions and deadlines; rendering cannot
keep an operation alive or authorize one by default. Authenticate the UI and
its messages, protect the agent and policy against the workload, and never give
its control channel to Code or descendants. Same-user filesystem permissions
alone are not a sufficient separation from a compromised host process.

## Launch and failure behavior

A future guarded command must verify process, file and network enforcement,
install the session's deny policy, capture its scope and only then start the
application. Missing permissions, unsigned/unprovisioned components, failed
registration or unsupported OS capabilities prevent guarded launch. No automatic
fallback to polling or an ordinary host window is permitted.

Provider crashes, deliberate deactivation, OS exceptions, indirect services and
traffic outside a filter's coverage need native tests and an explicit coverage
statement. Until those failure behaviors are established, CB must not claim
that closing a UI or losing an agent leaves the workload isolated. A VM with no
host sharing and controlled network/file brokers remains a separate boundary.
Keep a clearly labelled host-review mode distinct from guarded mode.

Before guarded mode can become the default, verify denies before the first
covered action, stale/reused identities, concurrent requests, deadlines, broker
and UI disconnection, policy replacement, IPv4/IPv6, DNS/UDP and direct-socket
bypasses, interpreter payloads, protected file replacement, reparented children
and coexistence with other endpoint tools. Use owned synthetic fixtures rather
than real malware, credentials or attacker infrastructure.

The Rust policy core can remain standard library plus `libc`. A TUI library, if
adopted, should be optional behind a feature and should not add dependencies to
the enforcement core. Review its actual transitive dependency tree before
choosing it. Native Apple framework adapters and their signed packaging are
separate from the renderer.

## Existing tools

The expanded, dated feature and build/buy assessment is in
[comparison.md](comparison.md), including OpenShell, nono and Lima.


| Tool | Relevant capabilities and limits |
| --- | --- |
| [LuLu](https://objective-see.org/products/lulu.html) | Free/open-source outbound firewall with connection decisions. Its documentation notes coverage and hostname limitations; broad existing-program rules need review. |
| [Little Snitch](https://obdev.at/products/littlesnitch/index.html) | Application firewall with connection prompts and rules. Silent mode can allow new connections, so mode selection matters. |
| [Santa](https://northpole.dev/features/binary-authorization/) | Binary authorization and file-access controls. Interpreted payloads require more than binary allowlisting; see its [documented limitations](https://github.com/northpolesec/santa). |
| [Anthropic sandbox runtime](https://github.com/anthropics/sandbox-runtime) | OS sandboxing and proxy-based network policy for CLI workloads. Useful design reference; not evidence that wrapping the Code GUI is compatible. |

These are references for separate controls, not claims that any combination
provides universal attack detection or a disposable developer VM. No tool was
installed, configured or adopted as a dependency for this research.

## Public incident illustrating the risk

Binance's [3 November 2026 report](https://www.binance.com/en/blog/community/3229153443759566763)
describes a fake interview assignment executing malware during setup, replacement
of a developer tool, and later abuse of an internal service and stolen
credentials before its 29 October theft. The
[FBI attributed that theft to TraderTraitor](https://www.fbi.gov/investigate/cyber/alerts/2026/north-korea-responsible-for-6-billion-binance-attack).
This illustrates why command, network, credential and tool-write controls need
to work together.

A shared interview/repository technique does not establish a shared attacker.
[ReversingLabs' 4 November analysis](https://www.reversinglabs.com/blog/binance-heist-what-we-know-and-what-rl-sees-in-tradertraitors-toolkit)
notes that endpoint malware hashes, command-and-control details and the assignment
repository had not been published. Keep unverified correlations out of incident
attribution. This document contains only public information and synthetic
examples, not a private incident timeline or a reproduced payload.
