# Security model

The optional selected-source/Codex review has a distinct, explicitly requested
harness networking/authentication profile. Its controls and limits are in
[review.md](review.md); the `cb run` prototype policy below is unchanged.

The experimental `cb run` launcher starts with a deny-by-default policy. Its
implemented boundary is a single noninteractive command on macOS. A successful compatibility probe is
required before that command starts; a rejected policy stops the launch.

`cb code` requires an isolated editor workspace and currently refuses launch.
The separate `cb host code` helper provides explicit host review; its optional
observer is not this sandbox policy and does not block network access. Host Git
is explicitly `cb host git`/`cb-git`. Read [product.md](product.md) for command
admission and [comparison.md](comparison.md) for the runtime reuse decision.

## Granted access

- Read access to selected operating-system executable and library directories.
- Read-only filesystem metadata access, which can reveal path existence and
  system information but does not grant file contents.
- Read/write access to a new private session directory owned by the user.
- Copies of explicitly selected regular input files and, when necessary, the
  selected executable. No host directories are mounted or copied recursively.
- Pipes for stdout and stderr; stdin is disconnected. Control characters are
  escaped before they reach the calling terminal.

Paths enter the sandbox policy as `sandbox-exec -D` parameter values. They are
not interpolated into policy source. Input paths are opened component by
component with retained directory descriptors and `O_NOFOLLOW`, preventing
symlink traversal and ancestor substitutions. Inputs and combined input data
are capped at 64 MiB; executable copies are capped at 256 MiB.

## Denied access

The policy grants no host home, browser profile, cloud credential directory,
Keychain database, SSH agent, Docker socket, outbound or inbound network,
Mach service lookup, or process creation through fork. Host files are denied
even when their Unix permissions would let the current account read them.
An application cannot make a child less restricted by changing its environment.

The environment is built from an explicit allowlist. It contains private
`HOME`/`TMPDIR` paths, system executable paths and a few fixed locale and Git
values. It does not carry parent tokens, credentials, loader injection
variables or agent sockets. System identity and kernel information are not
hidden; this is not an anonymity tool.

Inherited file descriptors above stdin/stdout/stderr are marked close-on-exec.
Process inspection and broad kernel queries are restricted. Explicit denial
rules are intentional and must be retained during policy changes. Automated
checks use synthetic files, processes and local sockets.

## Lifetime and output

The launcher owns one command. Fork is denied, so a descendant cannot retain
output pipes or detach from the owned lifetime. A wall deadline, output failure,
SIGINT or SIGTERM stops and reaps only the child CB started. Successful runs
report cleanup failures rather than silently claiming removal. Session cleanup
does not follow symlinks.

SIGKILL, host crashes and power loss cannot be handled by Rust destructors.
They may leave a private session or a still-contained command behind. A future
VM supervisor must own crash recovery and durable session cleanup.

## Limits

`sandbox-exec` and its policy language are deprecated/private interfaces.
macOS updates may change behavior. CB requires a compatibility check and has
no permissive fallback. Native denial tests exercise the listed boundaries on
compatible macOS systems.
They do not constitute an independent security audit or prove coverage of every
kernel-mediated interface.

CB shares the host kernel. It does not defend against kernel vulnerabilities,
an already compromised host, other malicious processes running as the same
user, all covert channels, or comprehensive CPU/memory/disk exhaustion. File
size and descriptor limits are partial resource controls. A program can expose
any input the person deliberately grants and can print data it can access.

Do not use this release to detonate real malware. GUI applications, clipboard
integration, app brokers, extensions, debuggers, recursive project snapshots,
network exceptions, interactive terminals and subprocess trees are unsupported.
The Git adapter is a separate hook policy; it does not inherit the launcher's
file/network restrictions.

## Strong-isolation direction

Evaluate existing guest-workspace runtimes before implementing a new VM or host
enforcement engine. The intended guest boundary has a private disk, no shared
home, clipboard or credential-agent forwarding, and default-deny egress. A
trusted host editor connected to a guest workspace is distinct from a macOS GUI
inside a guest. Guest startup, effective-policy probes and teardown need verified
receipts before the workspace is reported as protected. Imported/exported source
and approved network destinations require explicit brokers. No such adapter is
integrated yet; failure cannot downgrade into the host-review mode.

Sources: [Apple App Sandbox](https://developer.apple.com/documentation/security/app-sandbox),
[Apple's deprecation discussion](https://developer.apple.com/forums/tags/app-sandbox),
[Apple Virtualization](https://developer.apple.com/documentation/virtualization),
and [Git's hook configuration](https://git-scm.com/docs/git-config#Documentation/git-config.txt-corehooksPath).
