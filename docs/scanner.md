# Repository scanner

This guide describes plain static inspection. The separately gated `review`
feature adds explicitly selected source AST checks and optional Codex CLI
analysis; see [review.md](review.md). Plain inspection keeps the behavior and
schema described here, even in a review-enabled build.

Build with `cargo build --locked --features scanner --bin cb`, then run
`./target/debug/cb inspect DIRECTORY`. Add `--json` for a structured report.
Use `--` before a directory whose name begins with a dash. `cb scan` remains a
read-only compatibility alias. Exactly one directory is required. Use `--git-dir DIRECTORY` to inspect an explicitly selected Git metadata directory
(including linked worktree metadata), or `--hooks DIRECTORY` for a custom hook
directory. These modes are mutually exclusive and inspect only that directory.
The default build excludes the scanner module and internal JSON parser, and
gives a build instruction if `scan` is requested. The parser uses the standard
library; enabling the scanner adds no third-party dependencies.

The scanner reviews selected execution surfaces. It does not determine whether
an application has exploitable logic bugs, whether dependencies have known
vulnerabilities, whether a command previously executed, or whether a host is
compromised. It does not execute commands or make a safety certification.

## Coverage and rules

| Rule | What prompts review |
| --- | --- |
| `EDITOR_SETTINGS` | Nonempty workspace settings, including extension-defined settings not covered by a specific rule. |
| `EDITOR_TERMINAL` | Terminal profile, default/automation profile, legacy shell/arguments or environment overrides. |
| `EDITOR_PROTECTION` | Requests to weaken trust, allow terminals in untrusted workspaces or allow automatic tasks. Workspace scope may prevent these from taking effect. |
| `EDITOR_TOOL` | Selected executable, interpreter, runtime, language server or Git tool settings. |
| `EDITOR_AUTORUN` | A task with `runOptions.runOn` set to `folderOpen`. Editor trust and automatic-task permission still apply. |
| `EDITOR_TASK`, `EDITOR_LAUNCH`, `EDITOR_COMMAND_INPUT` | Workspace tasks, debugger configurations and command-valued inputs. |
| `GIT_HOOK` | A non-sample hook file, with executable files marked `high`. The name must still be recognized or explicitly configured for Git to invoke it. |
| `GIT_HOOKS_PATH`, `GIT_FSMONITOR`, `GIT_CONFIGURED_HOOK` | Hook/monitor configuration. Values requesting disabled behavior are still shown for review; the scanner does not compute effective Git configuration. |
| `GIT_INCLUDE` | An include or conditional include. Targets are not read. |
| `GIT_ALIAS`, `GIT_FILTER`, `GIT_DIFF_COMMAND`, `GIT_MERGE_DRIVER` | Aliases and selected filter/diff/merge commands. Non-shell aliases can also invoke executable Git operations. |
| `GIT_HELPER`, `GIT_COMMAND_SETTING` | Selected helper, signer, editor, pager, browser and transport settings. Coverage is not every Git configuration key. |
| `PACKAGE_LIFECYCLE`, `PACKAGE_SCRIPT` | Nonempty package scripts; install/preparation lifecycle scripts receive `high`. Other scripts can also be lifecycle hooks for explicitly requested operations. |
| `RUST_BUILD_SCRIPT` | Presence of `build.rs`; the scanner does not parse Cargo manifests or resolve custom/dependency build scripts or procedural macros. |

The scanner checks only the selected root's `.vscode` settings/tasks/launch,
top-level `*.code-workspace` files, `.git` metadata, `package.json` and `build.rs`.
Embedded workspace settings/tasks/launch receive the same checks as `.vscode`
files. JSONC comments and trailing commas are accepted in editor files. Escaped
strings remain strings; duplicate object keys are rejected rather than choosing
one interpretation. Package manifests require ordinary JSON.

A directory with `HEAD`, `objects` and `config` is treated as bare Git metadata
when explicitly selected. This lets a user inspect a referenced metadata
directory separately. The scanner does not invoke Git, read the index, resolve
revisions, inspect committed trees or discover nested repositories.

Git parsing recognizes sections/subsections, case-insensitive section/key names,
comments, quoted values and line continuations. Unsupported syntax is reported
as incomplete rather than interpreted by launching Git. This is deliberately a
review parser, not a replacement for Git's effective-configuration machinery.

## Incomplete scans and boundaries

A `.git` pointer file, `commondir`, configuration include, configured hooks path
or workspace folder other than `.` produces an incomplete item. The referenced
location is never opened automatically, including paths that appear to remain
inside the repository. After reviewing where it leads, use `cb inspect --git-dir DIRECTORY` for Git metadata
or `cb inspect --hooks DIRECTORY` for hook files. Run a normal repository scan on
workspace folders. Review configuration include files manually; this version
does not have a standalone config-file mode.
Custom hooks paths remain incomplete even if a value appears to disable hooks.

The root the user selects is resolved once. Subsequent reads use retained
directory descriptors and `openat` with `O_NOFOLLOW`; descendant links are refused.
Regular files are opened nonblocking, checked for type/size, read with a limit
and checked for metadata changes. Directories have bounded enumeration and are
checked for changes during enumeration. FIFO, device, socket, directory-as-file,
unreadable and oversized inputs become incomplete items. An opened parent
cannot be retargeted by replacing its path with a symlink.

Limits are 1 MiB per file, 8 MiB of file contents, 128 file read attempts, 2,048 entries per
enumerated directory and 256 findings. Findings are capped with an incomplete
notice; incomplete items are also bounded at 256. JSON nesting is capped at 64 levels and 100,000 values. Missing files count as read attempts. Failed reads conservatively consume
their full byte allowance, so repeated failures cannot bypass the budget.
Enumeration is not recursive. No project-supplied search patterns,
ignore files, plugins or executable rules are evaluated.

This remains a read of a live filesystem, without an atomic snapshot or a lock
against another process. Concurrent modification can prevent complete results.
The scan excludes nested projects, user/system Git and editor settings,
environment-based Git configuration, installed extensions, OS persistence,
processes and arbitrary application source. An attacker can use an execution
surface outside these checks or otherwise evade static inspection. A report
with no findings is not evidence of absence of malware.

## Reading and sharing results

Text and JSON reports contain relative paths, generic reasons, rule IDs and
locations. Git findings use line numbers; task/launch findings use array indexes;
settings use generic locations to avoid exposing user-defined keys. Reports do
not contain command strings, environment values, package script names, Git
subsection names or parser error excerpts. Terminal and directional controls in
paths are escaped. File names themselves are retained and can contain private
information, so review a report before sharing it.

JSON schema version 1 uses `mode`, `status`, `scope`, `findings`, `incomplete`,
`scanned_files` and `limits`. Status is `no_findings_in_scope`, `findings` or
`incomplete`; exit codes are 0, 1 and 2 respectively. Command-line errors also
exit 2 and print an error to stderr. An invalid root is an incomplete report,
including in JSON mode. Output errors fail rather than returning success.

Review `high` findings before opening terminals, allowing tasks, checking out
files or installing packages. Review other findings under the same trust policy.
Do not run a flagged command to see what it does on the host. Resolve incomplete
items with separate bounded scans and inspect configuration in a plain-text
viewer with execution features disabled. The scanner makes no automatic fixes
and never grants trust or changes file permissions.

Sources: [VS Code profiles](https://code.visualstudio.com/docs/terminal/profiles),
[tasks](https://code.visualstudio.com/docs/debugtest/tasks),
[Workspace Trust](https://code.visualstudio.com/docs/editing/workspaces/workspace-trust),
and [Git configuration](https://git-scm.com/docs/git-config).
