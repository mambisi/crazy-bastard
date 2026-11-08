use super::{Report, fs::Directory};
use std::{ffi::OsStr, path::Path};

pub(super) fn scan(root: &Directory, report: &mut Report) {
    // Try the regular-file form first only after directory opening fails. Never resolve gitdir pointers.
    let git = match root.directory(OsStr::new(".git")) {
        Ok(Some(git)) => git,
        Ok(None) => {
            // A bare repository is supported when explicitly selected as the root.
            if root.entries(super::MAX_ENTRIES).is_ok_and(|entries| {
                entries.iter().any(|n| n == "HEAD")
                    && entries.iter().any(|n| n == "objects")
                    && entries.iter().any(|n| n == "config")
            }) {
                metadata(root, report);
            }
            return;
        }
        Err(_) => {
            if report.read(root, OsStr::new(".git")).is_some() {
                report.issue(Path::new(".git"), "Git metadata is referenced by a file (for example a worktree or submodule); its target was not followed. Scan the actual metadata directory separately.");
            } else {
                report.issue(Path::new(".git"), "Git metadata could not be inspected; links, special files and unreadable paths are refused.");
            }
            return;
        }
    };
    metadata(&git, report);
}
pub(super) fn metadata(git: &Directory, report: &mut Report) {
    config(git, "config", report);
    config(git, "config.worktree", report);
    if report.read(git, OsStr::new("commondir")).is_some() {
        report.issue(
            &git.path.join("commondir"),
            "Shared Git metadata was not followed; scan the common directory separately.",
        );
    }
    hooks(git, report);
}
fn hooks(git: &Directory, report: &mut Report) {
    let Some(hooks) = report.child(git, "hooks") else {
        return;
    };
    hook_files(&hooks, report);
}
pub(super) fn hook_files(hooks: &Directory, report: &mut Report) {
    for name in report.entries(hooks) {
        if name.to_str().is_some_and(|s| s.ends_with(".sample")) {
            continue;
        }
        if report.read(hooks, &name).is_none() {
            continue;
        }
        match hooks.executable(&name) {
            Ok(executable) => report.finding(&hooks.path.join(&name), "file", "GIT_HOOK", if executable {"high"} else {"review"}, if executable {"An executable non-sample hook file is present. Git may invoke recognized hook names during routine operations; configured hooks may use other names."} else {"A non-sample hook file is present without executable permission; review its contents before enabling or invoking it."}),
            Err(_) => report.issue(&hooks.path.join(&name), "Hook changed or could not be inspected."),
        }
    }
}
fn config(git: &Directory, name: &str, report: &mut Report) {
    let Some(bytes) = report.read(git, OsStr::new(name)) else {
        return;
    };
    let path = git.path.join(name);
    let Ok(text) = std::str::from_utf8(&bytes) else {
        report.issue(
            &path,
            "Git configuration is not UTF-8 and was not interpreted.",
        );
        return;
    };
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    if text.contains('\0') {
        report.issue(
            &path,
            "Git configuration contains a NUL byte and was not interpreted.",
        );
        return;
    }
    let mut section = String::new();
    let mut logical = String::new();
    let mut start = 1;
    for (index, line) in text.lines().enumerate() {
        if logical.is_empty() {
            start = index + 1;
        }
        logical.push_str(line);
        // Backslash-newline continuation is supported without evaluating substitutions.
        if continues(&logical) {
            logical.pop();
            continue;
        }
        if parse_line(&logical, start, &mut section, &path, report).is_err() {
            report.issue(
                &path,
                "Git configuration contains unsupported or malformed syntax; review it manually.",
            );
        }
        logical.clear();
    }
    if !logical.is_empty() {
        report.issue(
            &path,
            "Git configuration ends with an incomplete continuation.",
        );
    }
}
fn continues(line: &str) -> bool {
    let mut quoted = false;
    let mut escape = false;
    for c in line.chars() {
        if escape {
            escape = false;
            continue;
        }
        match c {
            '\\' => escape = true,
            '"' => quoted = !quoted,
            '#' | ';' if !quoted => return false,
            _ => (),
        }
    }
    escape
}
fn parse_line(
    line: &str,
    number: usize,
    section: &mut String,
    path: &Path,
    report: &mut Report,
) -> Result<(), ()> {
    let mut clean = String::new();
    let mut quoted = false;
    let mut escape = false;
    for c in line.chars() {
        if escape {
            if !matches!(c, 'n' | 't' | 'b' | '\\' | '"') {
                return Err(());
            }
            clean.push(c);
            escape = false;
            continue;
        }
        if c == '\\' {
            clean.push(c);
            escape = true;
            continue;
        }
        if c == '"' {
            quoted = !quoted;
            clean.push(c);
            continue;
        }
        if !quoted && matches!(c, '#' | ';') {
            break;
        }
        clean.push(c);
    }
    if quoted || escape {
        return Err(());
    }
    let line = clean.trim();
    if line.is_empty() {
        return Ok(());
    }
    if line.starts_with('[') {
        let inner = line
            .strip_prefix('[')
            .and_then(|s| s.strip_suffix(']'))
            .ok_or(())?
            .trim();
        let name = inner.split([' ', '\t', '.']).next().ok_or(())?;
        if name.is_empty() || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
            return Err(());
        }
        let suffix = inner[name.len()..].trim();
        if !suffix.is_empty()
            && !(suffix.starts_with('"') && suffix.ends_with('"'))
            && !(suffix.starts_with('.') && suffix.len() > 1)
        {
            return Err(());
        }
        *section = name.to_ascii_lowercase();
        return Ok(());
    }
    if section.is_empty() {
        return Err(());
    }
    let end = line
        .find(|c: char| c == '=' || c.is_ascii_whitespace())
        .unwrap_or(line.len());
    let key = &line[..end];
    if !key.bytes().next().is_some_and(|b| b.is_ascii_alphabetic())
        || !key.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
    {
        return Err(());
    }
    let rest = line[end..].trim();
    if !rest.is_empty() && !rest.starts_with('=') {
        return Err(());
    }
    let key = key.to_ascii_lowercase();
    let location = format!("line {number}");
    if matches!(section.as_str(), "include" | "includeif") {
        report.finding(path, &location, "GIT_INCLUDE", "review", "Git configuration includes another file; the included configuration can add executable settings.");
        report.issue(
            path,
            "Git include targets were not followed; effective configuration is incomplete.",
        );
    }
    let rule = match (section.as_str(), key.as_str()) {
        ("core", "hookspath") => Some((
            "GIT_HOOKS_PATH",
            "A custom hook path is configured; its target is not followed, even when it appears to disable hooks.",
        )),
        ("core", "fsmonitor") => Some((
            "GIT_FSMONITOR",
            "A filesystem monitor is configured; depending on its value and Git version it can invoke an executable or a monitor service.",
        )),
        ("hook", _) => Some((
            "GIT_CONFIGURED_HOOK",
            "Configured hooks can register commands independently of files in .git/hooks; review the full hook section.",
        )),
        ("alias", _) => Some((
            "GIT_ALIAS",
            "A Git alias is configured; shell aliases and aliases of executable Git operations need review before use.",
        )),
        ("filter", "clean" | "smudge" | "process") => Some((
            "GIT_FILTER",
            "A filter command can run while files are checked out, added or diffed.",
        )),
        ("diff", "external" | "command" | "textconv") => Some((
            "GIT_DIFF_COMMAND",
            "Diff configuration can invoke an external command or text converter.",
        )),
        ("merge", "driver") => Some((
            "GIT_MERGE_DRIVER",
            "A merge driver command can run during a merge.",
        )),
        ("credential", "helper")
        | ("core", "sshcommand" | "askpass" | "editor" | "pager" | "alternaterefscommand")
        | ("sequence", "editor")
        | ("gpg", "program")
        | ("gpg", "defaultkeycommand") => Some((
            "GIT_HELPER",
            "Git configuration selects a helper, editor, signer, pager or transport command that runs on the host.",
        )),
        ("pager", _)
        | ("man", "cmd")
        | ("web", "browser")
        | ("browser", "cmd")
        | ("protocol", "allow")
        | ("uploadpack", "packobjectshook")
        | ("remote", "vcs" | "uploadpack" | "receivepack" | "proxy") => Some((
            "GIT_COMMAND_SETTING",
            "A setting can select an external command or enable additional command execution; review before using the affected Git operation.",
        )),
        _ => None,
    };
    if let Some((rule, reason)) = rule {
        report.finding(path, location, rule, "review", reason);
    }
    if section == "core" && key == "hookspath" {
        // A path may be relative, expanded or overridden. Do not guess and silently miss its hooks.
        report.issue(
            path,
            "Configured hook directories were not followed; review their contents separately.",
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn git_keys_are_case_insensitive_and_subsections_do_not_hide_commands() {
        let mut report = Report::default();
        let mut section = String::new();
        for (line, text) in [
            "[Core]",
            "fsMonitor = false",
            "[filter \"fixture\"]",
            "process = \"dummy # not a comment\"",
            "[diff.fixture]",
            "textconv=dummy",
            "[includeIf \"gitdir:example\"]",
            "path=elsewhere",
        ]
        .iter()
        .enumerate()
        {
            parse_line(
                text,
                line + 1,
                &mut section,
                Path::new(".git/config"),
                &mut report,
            )
            .unwrap();
        }
        assert_eq!(
            report.findings.iter().map(|f| f.rule).collect::<Vec<_>>(),
            [
                "GIT_FSMONITOR",
                "GIT_FILTER",
                "GIT_DIFF_COMMAND",
                "GIT_INCLUDE"
            ]
        );
        assert_eq!(report.exit_code(), 2);
    }
    #[test]
    fn malformed_git_config_is_never_silently_accepted() {
        for text in [
            "[core",
            "[core] extra",
            "[core extra]",
            "key without-equals",
            "9key=value",
            "key=\"unterminated",
            "key=bad\\q",
        ] {
            assert!(
                parse_line(
                    text,
                    1,
                    &mut "core".to_owned(),
                    Path::new("config"),
                    &mut Report::default()
                )
                .is_err(),
                "{text}"
            );
        }
    }
}
