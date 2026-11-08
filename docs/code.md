# VS Code host launcher and monitor

`cb host code .` launches a new VS Code instance for one existing folder. Omitting
the folder selects `.`. `--` ends CB option parsing. Arbitrary VS Code flags,
workspace-definition files and additional folders are refused. This avoids
passing options that can replace the profile or disable Workspace Trust.

This command currently supports macOS with VS Code installed in `/Applications`.
The application is launched directly, without searching `PATH`, invoking the
`code` shell wrapper or using Launch Services to reuse an existing window.
Application bundle links and portable data are refused because portable mode
can override the requested profile directories. It assumes the installed editor
and host OS are trusted; it does not authenticate or defend against their
replacement by another process running as the same user.

## Default host hardening

Each invocation creates a new private session directory, a home, a user-data
profile and an empty extensions directory. The environment is replaced with
explicit system paths, locale and session values. Host tokens, shell injection
variables, editor IPC pointers and credential agent sockets are not inherited.
CB sets its own `VSCODE_CLI=1` so Code does not obtain the original shell's
login environment. Extra inherited descriptors are marked close-on-exec and
core dumps are disabled. Standard streams are disconnected from the editor.

The generated user settings enable Workspace Trust, leave unfamiliar folders in
Restricted Mode without an initial trust prompt, disable automatic tasks and
terminals in untrusted workspaces, disable built-in Git discovery and fetching,
and disable extension updates, recommendations, telemetry, product updates and
AI features. `--disable-extensions` is also passed explicitly. Some settings may
differ across editor versions. Built-in application code still executes.

A fresh profile avoids inheriting the normal profile's trusted-folder catalogue,
installed extensions and saved login state. CB refuses the real home directory
and its ancestors as workspace roots. It does not edit `.vscode`, `.git` or the
normal user's settings. The original selected directory remains editable.

The title says `CB host review (not sandboxed)`. Restricted Mode is an editor
control, not a filesystem or network boundary. A process can still obtain host
access through its account, and selecting Trust can re-enable execution features.
Keep unfamiliar projects untrusted. GUI isolation is a separate VM feature.

Keep CB running in the terminal. On macOS, closing the last window can leave
Code running: quit this dedicated application instance to finish the session.
Ctrl-C/SIGTERM stops the group created for it and reaps the owned root. CB keeps
the root PID unreaped through group cleanup, preventing PID reuse from retargeting
the signal. It never kills applications by name. Normal exit also cleans up
remaining group members before removing the profile. Processes that move to
another group or are launched by a system service can escape this cleanup.
SIGKILL, crashes and power loss can leave profile data or processes behind.

## Optional monitoring

`cb host code --monitor .` polls every 250 ms. It uses macOS `libproc` for the owned
process group, not a global host process inventory. PID start times are checked
around observations. Rules stop that group on:

- An executable outside Code and a short, explicit list of Code helper binaries.
  Shells, package tools and external interpreters are outside the allowlist.
- An observed open file or directory descriptor in the real home outside the selected
  workspace and private session. File contents are never read by the monitor.
- Changes to the generated protective settings, incomplete process/descriptor
  observations or exceeded monitoring budgets.

IPv4/IPv6 sockets with remote peers, including loopback, generate a notification
when observed IP activity starts. Unused/listening sockets are ignored. This is
not a per-connection log or packet inspection. Network activity alone is not
classified as malicious and does not stop the editor. The monitor is not a
firewall; data may already have been sent before the notification.

Limits are 128 processes, 4,096 descriptors per process and 16,384 descriptors per
poll. Descriptor details use a small, repository-owned C shim compiled with the
system SDK's structures; Rust does not guess their layout. The shim uses no
third-party library. Monitoring failures stop the session, rather than silently
continuing without observations. Some macOS versions or parent sandboxes can
prevent inspection. Benign application activity can also trigger the rules.

Reports contain a generic reason rather than paths, endpoints, arguments or
environment values. They are printed to stderr and are not saved to an incident
log or sent anywhere. A rule match establishes that an observation broke the
review policy; it does not establish malicious intent or data theft.

Polling can observe an action after data has already been read, written or sent.
It can miss short-lived children and file opens, descriptor reuse, mapped-file
access, unconnected UDP, Unix sockets, Mach services, processes that leave the
group, indirect launches and in-process payloads in allowed executables. A
workspace-contained link may resolve to a sensitive path; only an observed open
path outside the selected workspace is caught. Previously read or subsequently
closed descriptors leave no history in this monitor. It does not catch every
attack, prove a clean host or replace VM isolation.

True authorization before covered operations requires an OS enforcement backend.
Apple's Endpoint Security framework requires a restricted entitlement and other
installation permissions. It is not implemented or silently approximated by
this polling observer. Code retains its own built-in sandbox. CB does not wrap the GUI in its CLI
Seatbelt policy, which is incompatible with Code helper sandbox initialization.
The host monitor applies no additional OS network or filesystem denial policy.

## Isolation-required mode and migration

`cb code .` now requires an isolated workspace and refuses launch before touching
the target because no verified workspace adapter is integrated. Its former host
behavior is available only as `cb host code .`. `cb code --monitor .` directs the
caller to the explicit host spelling. This prevents a forgotten isolation flag
from opening an unfamiliar project on the host.

`cb code --vm .` remains a legacy isolation request and also refuses launch.
`cb host code --vm .` is rejected rather than ignoring the requested boundary.
There is no automatic fallback. The [product design](product.md) and
[feature comparison](comparison.md) prioritize evaluating existing isolated
workspace runtimes; a new native-host enforcer is a later option, not a shipped
capability. The host window keeps its existing behavior and limitations.

## Checks

```sh
cargo test --locked --no-default-features
cargo test --locked --all-features
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked --all-features --lib code:: -- --ignored --test-threads=1
```

The last check needs native macOS inspection permission. It uses owned sleep
processes, synthetic files and a loopback connection. It does not open a real
project or read credentials. Launcher tests check profile separation, literal
arguments, replaced environments, refused flags, VM refusal and owned cleanup.

References: [VS Code CLI](https://code.visualstudio.com/docs/configure/command-line),
[Workspace Trust](https://code.visualstudio.com/docs/editing/workspaces/workspace-trust),
[portable mode](https://code.visualstudio.com/docs/setup/portable),
[Apple libproc](https://github.com/apple-oss-distributions/xnu/blob/main/libsyscall/wrappers/libproc/libproc.h)
and [Endpoint Security](https://developer.apple.com/documentation/endpointsecurity).
