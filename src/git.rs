//! Host-side hook suppression, separate from isolated execution.
use crate::{Result, invalid};
use std::{
    ffi::OsString,
    os::unix::process::CommandExt,
    process::{Command, Stdio},
};
pub const EVENTS: &[&str] = &[
    "applypatch-msg",
    "pre-applypatch",
    "post-applypatch",
    "pre-commit",
    "pre-merge-commit",
    "prepare-commit-msg",
    "commit-msg",
    "post-commit",
    "pre-rebase",
    "post-checkout",
    "post-merge",
    "pre-push",
    "pre-receive",
    "update",
    "proc-receive",
    "post-receive",
    "post-update",
    "reference-transaction",
    "push-to-checkout",
    "pre-auto-gc",
    "post-rewrite",
    "sendemail-validate",
    "fsmonitor-watchman",
    "p4-changelist",
    "p4-prepare-changelist",
    "p4-post-changelist",
    "p4-pre-submit",
    "post-index-change",
];
pub fn arguments(args: &[OsString]) -> Result<Vec<OsString>> {
    let mut index = 0;
    let mut globals = Vec::new();
    while index < args.len() {
        let text = args[index]
            .to_str()
            .ok_or_else(|| invalid("Git global options must be UTF-8"))?;
        if !text.starts_with('-') || (matches!(text, "--version" | "-v") && index + 1 == args.len())
        {
            break;
        }
        if matches!(
            text,
            "-c" | "-C" | "--config-env" | "--git-dir" | "--work-tree" | "--namespace"
        ) {
            if index + 1 >= args.len() {
                return Err(invalid("missing Git global option value"));
            }
            globals.extend_from_slice(&args[index..index + 2]);
            index += 2;
        } else if matches!(
            text,
            "--no-pager"
                | "--paginate"
                | "-p"
                | "-P"
                | "--bare"
                | "--literal-pathspecs"
                | "--glob-pathspecs"
                | "--noglob-pathspecs"
                | "--icase-pathspecs"
                | "--no-replace-objects"
                | "--no-optional-locks"
                | "--no-lazy-fetch"
        ) || (text.len() > 2 && (text.starts_with("-c") || text.starts_with("-C")))
            || [
                "--config-env=",
                "--git-dir=",
                "--work-tree=",
                "--namespace=",
            ]
            .iter()
            .any(|p| text.starts_with(p))
        {
            globals.push(args[index].clone());
            index += 1;
        } else {
            return Err(invalid("unsupported Git global option; no command was run"));
        }
    }
    let tail = &args[index..];
    if let Some(verb) = tail.first() {
        let allowed = "add am apply archive bisect blame branch bundle cat-file check-attr check-ignore check-mailmap check-ref-format checkout checkout-index cherry cherry-pick clean clone commit commit-tree config count-objects describe diff diff-files diff-index diff-tree fetch for-each-ref format-patch fsck gc grep hash-object index-pack init interpret-trailers log ls-files ls-remote ls-tree maintenance merge merge-base merge-file merge-tree mv name-rev notes pack-objects pack-refs prune pull push range-diff read-tree rebase reflog remote repack replace reset restore rev-list rev-parse revert rm shortlog show show-ref sparse-checkout stash status submodule switch symbolic-ref tag unpack-objects update-index update-ref var verify-commit verify-pack verify-tag version worktree write-tree --version -v";
        if !allowed.split_whitespace().any(|word| verb == word) {
            return Err(invalid(
                "aliases, hook run and external subcommands are disabled",
            ));
        }
    }
    for value in [
        "core.hooksPath=/dev/null",
        "core.fsmonitor=false",
        "protocol.ext.allow=never",
    ] {
        globals.extend(["-c".into(), value.into()]);
    }
    for event in EVENTS {
        globals.extend(["-c".into(), format!("hook.{event}.enabled=false").into()]);
    }
    globals.extend_from_slice(tail);
    Ok(globals)
}
pub fn execute(args: &[OsString]) -> Result<i32> {
    let version = Command::new("/usr/bin/git").arg("--version").output()?;
    if !version.status.success() || !supported_version(&String::from_utf8_lossy(&version.stdout)) {
        return Err(invalid(
            "Git 2.36 or newer is required for safe fsmonitor boolean semantics",
        ));
    }
    let error = Command::new("/usr/bin/git")
        .args(arguments(args)?)
        .env_remove("GIT_EXEC_PATH")
        .env_remove("GIT_EXTERNAL_DIFF")
        .env("GIT_PAGER", "cat")
        .env("PAGER", "cat")
        .stdin(Stdio::inherit())
        .exec();
    Err(error.into())
}
fn supported_version(version: &str) -> bool {
    let Some(number) = version.split_whitespace().nth(2) else {
        return false;
    };
    let mut parts = number.split('.');
    match (
        parts.next().and_then(|p| p.parse::<u32>().ok()),
        parts.next().and_then(|p| p.parse::<u32>().ok()),
    ) {
        (Some(major), Some(minor)) => (major, minor) >= (2, 36),
        _ => false,
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn caller_options_cannot_override_the_hook_policy() {
        let r = arguments(&["-c".into(), "core.hooksPath=evil".into(), "status".into()]).unwrap();
        assert!(
            r.iter()
                .position(|v| v == "core.hooksPath=/dev/null")
                .unwrap()
                > r.iter().position(|v| v == "core.hooksPath=evil").unwrap()
        );
        assert_eq!(r.last().unwrap(), "status");
    }
    #[test]
    fn aliases_and_explicit_hooks_are_refused() {
        for v in ["evil-alias", "hook"] {
            assert!(arguments(&[v.into()]).is_err());
        }
    }
    #[test]
    fn unknown_global_options_are_refused() {
        assert!(arguments(&["--exec-path=evil".into(), "status".into()]).is_err());
    }
    #[test]
    fn old_fsmonitor_path_semantics_are_refused() {
        assert!(!supported_version("git version 2.35.1"));
        assert!(!supported_version("unrecognized"));
        assert!(supported_version("git version 2.40.0 (Example Build)"));
    }
}
