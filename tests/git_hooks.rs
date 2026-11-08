use crazy_bastard::session::Session;
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::Path,
    process::{Command, Output},
};

fn git(root: &Path, args: &[&str]) -> Output {
    let output = Command::new("/usr/bin/git")
        .args([
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "core.fsmonitor=false",
        ])
        .args(args)
        .current_dir(root)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    output
}
fn fixture() -> Session {
    let root = Session::create().unwrap();
    git(root.root(), &["init", "--template=", "-b", "main"]);
    git(root.root(), &["config", "user.name", "Fixture"]);
    git(
        root.root(),
        &["config", "user.email", "fixture@example.invalid"],
    );
    git(root.root(), &["config", "commit.gpgsign", "false"]);
    git(
        root.root(),
        &["commit", "--allow-empty", "-m", "Initial fixture"],
    );
    root
}
fn hook(root: &Path, name: &str) {
    fs::create_dir_all(root.join("hooks")).unwrap();
    let path = root.join("hooks").join(name);
    fs::write(&path, "#!/bin/sh\nprintf invoked > hook-ran\n").unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
}
#[test]
fn checkout_hooks_are_suppressed_despite_local_cli_and_environment_overrides() {
    let root = fixture();
    hook(root.root(), "post-checkout");
    git(root.root(), &["config", "core.hooksPath", "hooks"]);
    git(root.root(), &["branch", "topic"]);
    // First prove that this harmless hook is runnable in the fixture.
    git(
        root.root(),
        &["-c", "core.hooksPath=hooks", "switch", "topic"],
    );
    assert!(root.root().join("hook-ran").exists());
    fs::remove_file(root.root().join("hook-ran")).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_cb"))
        .args(["git", "-C"])
        .arg(root.root())
        .args(["-c", "core.hooksPath=hooks", "switch", "main"])
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_COUNT", "1")
        .env("GIT_CONFIG_KEY_0", "core.hooksPath")
        .env("GIT_CONFIG_VALUE_0", "hooks")
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    assert!(!root.root().join("hook-ran").exists());
}
#[test]
fn commit_and_reference_transaction_hooks_are_suppressed() {
    let root = fixture();
    for name in ["pre-commit", "commit-msg", "reference-transaction"] {
        hook(root.root(), name);
    }
    git(root.root(), &["config", "core.hooksPath", "hooks"]);
    let output = Command::new(env!("CARGO_BIN_EXE_cb"))
        .args(["git", "-C"])
        .arg(root.root())
        .args(["commit", "--allow-empty", "-m", "Guarded fixture"])
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    assert!(!root.root().join("hook-ran").exists());
}
