# Feature comparison and build decision

Reviewed 8 November 2026 using the linked project/vendor documentation. This is
a documented-capability comparison, not a penetration test or independent
security audit. Defaults, versions, platforms and configured policy matter.
An empty cell or a limitation here is not a claim that a product can never
implement that feature. Third-party tools were not installed or executed for this
comparison.

## Decision

Do not build another general-purpose firewall, sandbox engine, credential proxy
or network-approval TUI as CB's main product. Existing tools already cover much
of that scope. A small repository-review workflow is a conditional experiment:
CB must demonstrate a useful safety or usability improvement over calling an
existing runtime directly. New command names alone are not that improvement.

The closest overlap is OpenShell, which documents both blocked-endpoint approval
and editor connections. Its existing interface already removes much of the
original rationale for building a new engine. nono also makes the CLI sandbox
and permission-broker space crowded. These are reasons to narrow CB, not evidence
that its proposed workflow is unique.

## Documented capabilities

| Tool | File/process boundary | Network and decisions | Editor/workspace fit | Implication for CB |
| --- | --- | --- | --- | --- |
| [OpenShell](https://docs.nvidia.com/openshell/latest/security/best-practices) | Linux Landlock, seccomp and runtime isolation; several runtime choices. | Deny unlisted endpoints and review them in a TUI. Approvals persist within a sandbox. | [VS Code/Cursor remote connection commands](https://docs.nvidia.com/openshell/latest/how-it-works/sandboxes/overview) already exist. | First runtime to evaluate; substantial overlap with CB's proposed product. |
| [nono networking](https://nono.sh/docs/cli/features/networking) | Kernel capability controls, with host/platform differences. | Proxy domain rules and terminal host approvals are documented. Network is unrestricted without restrictive configuration. | General process/tool workflows. | Reuse/evaluate before inventing a command sandbox or proxy. |
| [nono supervisor](https://nono.sh/docs/cli/features/supervisor) | Dynamic file capability expansion uses Linux seccomp notification. | Terminal/webhook approval interfaces. | macOS does not offer the same transparent file expansion. | Do not project Linux approval capabilities onto macOS. |
| [Lima](https://lima-vm.io/docs/examples/vscode/) | VM workspace and documented VS Code Remote-SSH workflow; `--mount-none` avoids host mounts. | VM existence alone does not establish CB's desired egress or approval policy. | Existing path to keep project tools in a guest. | Candidate outer VM boundary; not a complete approval broker by itself. |
| [LuLu](https://objective-see.org/products/lulu.html) | Host application firewall, not a guest workspace. | Outgoing connection rules and prompts. Default broad installed/Apple-program permissions and hostname/coverage limitations need review. | Host app/process scope. | Use an existing endpoint firewall for host egress needs rather than cloning it. |
| [Little Snitch](https://help.obdev.at/littlesnitch6/alert-overview) | Host network controls. | Connection decisions and scoped rules. [Operation mode](https://help.obdev.at/littlesnitch7/concepts-opmodes) affects unmatched traffic. | Existing network operator UI. | A general network notification UI is already served. |
| [Santa](https://northpole.dev/features/binary-authorization/) | Binary authorization and file-access policy; [scripts/interpreters have limitations](https://github.com/northpolesec/santa). | A separate network control is needed. | Host/fleet endpoint controls. | Avoid starting a new system-wide application-control product. |
| [Anthropic sandbox runtime](https://github.com/anthropics/sandbox-runtime) | OS process sandbox for CLI workloads. | Proxy-based network policy; external decision integration is documented. | Does not establish compatibility for wrapping the Code GUI. | Useful CLI reference/possible component, not a whole-app VM replacement. |
| [Agent Safehouse](https://agent-safehouse.dev/docs/overview) | macOS Seatbelt profiles for developer-agent workloads. | Networking is allowed by default. | Curated CLI/tool compatibility. | Prefer studying existing profiles over promising universal app containment. |
| CB today | Bounded static inspection; single-process Seatbelt experiment; explicit host review and Git hook policy. | The host observer reports networking after it may occur and can stop benign activity. | Isolated editor launch is unavailable and refuses host fallback. | No integrated VM, authorization TUI, runtime adapter or universal malicious-code detector. |

OpenShell's [installation documentation](https://docs.nvidia.com/openshell/latest/about/installation/)
lists runtime requirements. Validate an exact release/driver and effective
policy; a CLI being installed is not evidence that its enforcement is active.
Its [operator approval policy](https://docs.nvidia.com/openshell/latest/security/best-practices#operator-approval)
expands a sandbox's durable policy: CB must not label that action "allow once."

nono's dedicated networking and supervisor pages are the basis for this matrix.
Broader marketing descriptions and older platform-specific pages should not be
used to infer defaults. Its [security model](https://nono.sh/docs/cli/internals/security-model)
also distinguishes host capability control from a separate-kernel boundary.
A guest VM running Linux controls is different from sandboxing the host's native
VS Code GUI. Neither should be advertised as the other.

## Where a small CB experiment could help

Focus on reviewing an unfamiliar repository or assessment before normal tools
consume its configuration. The candidate workflow combines bounded static
inspection, controlled source import, a trusted runtime policy, an isolated
workspace and explicit review/export of changes. These are hypotheses to test,
not capabilities missing from every competitor.

CB should own that workflow and its verification, not a second copy of a
runtime's policy engine. Delegate supported decisions to the runtime's existing
operator UI first. Add a CB TUI only if it improves the workflow and can preserve
the backend's real permission scope and deadlines.

A host/macOS Endpoint Security product would be a separate investment: signing,
entitlements, installation, lifecycle, OS-version compatibility and ongoing
security response. Defer it unless the required workflow cannot be served by a
trusted host editor talking to an isolated guest workspace.

## Go/no-go experiment

Before a full implementation, compare the same synthetic unfamiliar-repository
workflow using OpenShell directly, nono where applicable, and a minimal CB
adapter. Measure setup steps, time to a usable editor, required configuration,
permission decisions, cleanup behavior and recovery. Record results rather than
inventing a feature score or claiming an unmeasured advantage.

The CB route must establish that project startup code was not run on the host;
host home, credentials and agent sockets were not imported; unapproved outbound
traffic was denied before forwarding; source import/export could not escape its
captured destination; and editor/approval scopes stayed attached to the correct
workspace. Test stale permissions, direct sockets, interpreter payloads, unsafe
repository configuration and cleanup failures with harmless fixtures.

Proceed only if CB both passes those checks and measurably reduces user mistakes
or workflow friction. Stop or keep it as a small personal utility if a documented
direct-runtime setup is equally usable and safe. If users merely want a host
firewall, use LuLu/Little Snitch; if they want endpoint execution policy, evaluate
Santa; if they want sandboxed agent sessions, evaluate OpenShell/nono directly.

## Dependency and trust budget

Default and static-inspector builds remain standard library plus pinned `libc`.
The optional review build adds pinned ast-grep-core and four selected grammar
packages. The current Cargo.lock records 45 third-party packages including
transitive/build dependencies and libc; [review.md](review.md) lists the direct
pins. This is a larger supply-chain surface than the default build.
An optional TUI crate is permitted, but not selected by this redesign. An
external runtime, guest image, extension, signing service or update channel is
still part of the trusted system even when it is absent from `Cargo.lock`.
Pin and verify evaluated artifacts; do not execute install scripts or policy
from the repository under review. A short Rust dependency list alone does not
prove a small or secure end-to-end boundary.
