# VS Code and Git hardening

An editor's project configuration can be executable code. Workspace terminal
profiles can supply shell commands, tasks can run commands, debuggers can start
programs, and extensions can act on workspace settings. Trust is a code-execution
decision. Changing a global terminal profile does not prevent a trusted workspace
from defining another one.

Use these user-level VS Code settings for unfamiliar workspaces:

```json
{
  "security.workspace.trust.enabled": true,
  "security.workspace.trust.startupPrompt": "never",
  "security.workspace.trust.emptyWindow": false,
  "security.workspace.trust.untrustedFiles": "newWindow",
  "security.workspace.trust.banner": "always",
  "terminal.integrated.allowInUntrustedWorkspace": false,
  "task.allowAutomaticTasks": "off",
  "git.openRepositoryInParentFolders": "never",
  "git.path": "/absolute/path/to/cb-git"
}
```

`startupPrompt: never` leaves new untrusted folders in Restricted Mode with a
banner instead of asking for immediate trust. It does not grant trust. Previously
trusted folders and trusted parent directories retain their trust: review them
with **Workspaces: Manage Workspace Trust** and avoid trusting broad locations
such as the home directory or a folder containing arbitrary downloaded projects.
An explicit trust decision enables additional execution capabilities.

The `cb-git` executable is a copy or symlink of the compiled `cb` binary with that
name. It routes VS Code Git operations through `cb host git`. It does not intercept
terminals, other editors or tools that invoke another Git binary. For those,
use `cb host git` explicitly. Remote SSH, WSL and containers have separate settings
and executable installations.

Reload the VS Code window after changing `git.path` so an already-running Git
extension picks up the adapter. Save work before reloading; CB does not close
editor windows or terminate their terminals automatically.

`git config --global core.hooksPath /dev/null` is a useful default for normal
clones, but local/worktree configuration can override it. It is not an enforcement
boundary. The adapter applies its hook policy after caller global options on
each invocation. Hooks stay disabled for trusted repositories too; run reviewed
hooks deliberately with the real Git executable when needed. Do not remove this
restriction just to make an unfamiliar project's setup instructions succeed.

Restricted Mode and a Git hook policy do not sandbox builds, package lifecycle
scripts, language servers, credential helpers or arbitrary commands. Do not mount
your real home, browser profiles, SSH agent or Docker socket into an environment
used to inspect unfamiliar code. Use a disposable VM for full applications or
code requiring broad capabilities. Do not use an outdated container runtime as
a substitute for that boundary.

Sources: [VS Code Workspace Trust](https://code.visualstudio.com/docs/editing/workspaces/workspace-trust),
[VS Code setting scopes](https://code.visualstudio.com/docs/configure/settings),
[Git hook paths and configuration precedence](https://git-scm.com/docs/git-config).
