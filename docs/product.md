# Product and command design

CB is a small experimental tool for reviewing unfamiliar repositories and making
execution boundaries explicit. The build decision is conditional: validate a
useful repository workflow around existing runtimes before investing in a new
enforcement engine. See the [feature comparison](comparison.md).

## Scope

The proposed primary workflow is inspect, import, isolate, review decisions,
then explicitly export or discard changes. It is aimed at unfamiliar repositories
and assessment projects, not at being a universal antivirus, a new fleet EDR,
a general firewall or a replacement VM implementation.

The implementation currently provides inspection, an experimental single-process
launcher and explicit host helpers. It does not yet provide the complete
isolated-workspace workflow. The command boundary changes below are implemented;
provider integration and its TUI are not.

An optional `review` feature now adds selected-file AST checks and advisory Codex
CLI analysis to inspection. It is separate from workspace execution and grants
no project permissions; [review.md](review.md) defines disclosure, confinement,
login and validation limits. Other harnesses are not yet integrated.

## Command contract

| Command | Meaning today |
| --- | --- |
| `cb inspect DIRECTORY` | Bounded static launch-surface review; requires the `scanner` feature. `cb scan` remains a read-only alias. |
| `cb run --experimental-seatbelt -- COMMAND` | Existing experimental macOS single-process containment. No network, fork/spawn, interactive input or GUI support. |
| `cb code [DIRECTORY]` | Isolation-required editor workspace. Refuses launch because no verified workspace adapter is integrated. Never opens the original project on the host as a fallback. |
| `cb host code [--monitor] [DIRECTORY]` | Explicit hardened host review. Uses original editable files and no additional OS filesystem/network isolation. Monitoring is observation plus selected stop rules. |
| `cb host git ...` | Host Git with hook/fsmonitor suppression. Host files, credentials and networking remain available to Git and other configured facilities. |
| `cb doctor` | Reports shipped feature and boundary status without executing runtimes or project tools. Installation alone cannot make an adapter verified. |
| `cb-git ...` | Existing executable-name adapter for editor integration; unchanged host hook policy. |

Help is available at `cb --help`, `cb code --help`, `cb host --help`,
`cb host code --help`, `cb inspect --help` and `cb run --help`. Git arguments
after `cb host git` belong to Git and are passed literally.

This is an intentional prototype command migration. Old `cb code .` host-review
behavior moves to `cb host code .`; `cb code --monitor .` now requires the explicit
host spelling. Old `cb git ...` returns a migration error without running Git.
`cb-git` remains compatible. Old `cb code --vm .` means isolation-required launch;
`--vm` is refused under `cb host code`. No security-intent flag is silently
ignored. Scanner report schema and exit codes remain unchanged.

## Candidate isolated-workspace flow

The following is a proposed integration sequence, not a list of shipped actions:

1. Capture the selected physical root and inspect launch surfaces without Git,
   package installation, shell startup or editor activation. A scanner result is
   review data, not an automatic trust grant or a malware-free certificate.
2. Import bounded source data using verified file identities and containment.
   Do not follow links out of the source or automatically copy `.git`, credentials,
   sockets, editor trust state or generated caches. Do not honor repository
   `.devcontainer`, VM, shell or runtime policy as host launch instructions.
3. Create a fresh runtime from a trusted, evaluated template/image. Grant no host
   home, credential agents, Docker socket, clipboard or shared writable checkout.
   Enforce default-deny egress and a separately authenticated decision channel.
4. Verify effective file, process, network and lifetime controls before any
   project command starts. A missing adapter, failed health check or unsupported
   capability prevents launch. Never substitute polling for authorization.
5. Connect a trusted editor frontend to the guest workspace. Remote workspace
   execution is distinct from whole-GUI isolation. Preserve the frontend's own
   sandbox and avoid loading arbitrary local extensions or restoring trust state.
6. Use the provider's operator interface first. Permission choices must describe
   its actual effect: a persistent endpoint rule is not a one-use approval.
   An optional CB TUI must preserve captured session/request identity, expiry
   and backend acknowledgement, and must not invent an accepted result.
7. Retain the original workspace identity through disconnects and cleanup. Review
   changes before any explicit export; validate the original physical destination,
   symlinks, new local edits and access scope. Do not automatically copy changes
   onto host tools, hooks, startup configuration or credentials. Cleanup failures
   remain visible and do not count as successful revocation.

## Runtime strategy

Evaluate OpenShell first for a workspace backend. It already documents both
network approval and editor connectivity; a new CB engine would duplicate these
features. Evaluate Lima as an outer VM and nono or a similar capability layer
where finer controls are needed. Lima alone must not be assumed to supply a
network approval broker. Profiles, actual enforcement and supported platforms
need validation for the chosen versions. No runtime is integrated or automatically
installed by this redesign.

Keep the existing Seatbelt launcher as a bounded experiment rather than widening
it into a permissive GUI profile. Keep host review as an explicitly selected
utility. The native-host Endpoint Security/Network Extension design remains a
possible later adapter, not a prerequisite for the first guest-workspace
experiment. Its requirements are in [authorization.md](authorization.md).

Do not add lifecycle commands such as approve, sessions, stop or export until
there is an owning runtime and real receipt to operate on. Do not persist
approval booleans, process IDs or imaginary provider health in project settings.
No approval authority may come from the repository being inspected.

## Build budget and success condition

The default core and static scanner stay standard library plus `libc`. The
optional review feature adds exactly pinned ast-grep-core and selected grammars,
with a committed transitive lockfile. AST parsing runs in a separate confined
worker, rather than exposing the parent to source parsing. An optional TUI
should be isolated from the enforcement core.
External programs and images still count toward the security and maintenance
budget, regardless of the Cargo dependency count.

A bounded prototype should prove safer defaults and lower user error than a
direct runtime invocation. If it only changes command spelling, stop the product
expansion. The detailed comparison and acceptance experiment are in
[comparison.md](comparison.md). No competitive or isolation claim in those plans
substitutes for native tests with owned synthetic workloads.
