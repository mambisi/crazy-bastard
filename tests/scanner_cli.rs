use std::process::Command;

#[cfg(all(feature = "scanner", not(feature = "review")))]
#[test]
fn the_static_only_build_refuses_review_before_launching_a_tool() {
    let output = Command::new(env!("CARGO_BIN_EXE_cb"))
        .args(["inspect", ".", "--with", "codex"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("--features review"));
    assert!(output.stdout.is_empty());
}

#[cfg(not(feature = "scanner"))]
#[test]
fn the_default_binary_reports_the_feature_required_for_inspection() {
    let output = Command::new(env!("CARGO_BIN_EXE_cb"))
        .args(["inspect", "."])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(
        String::from_utf8(output.stderr)
            .unwrap()
            .contains("scanner feature is disabled")
    );
    let output = Command::new(env!("CARGO_BIN_EXE_cb"))
        .arg("--help")
        .output()
        .unwrap();
    let help = String::from_utf8(output.stdout).unwrap();
    assert!(help.contains("cb inspect"));
    assert!(help.contains("Scanner feature: disabled"));
}

#[cfg(feature = "scanner")]
#[test]
fn json_cli_distinguishes_findings_from_incomplete_scans() {
    use crazy_bastard::session::Session;
    let session = Session::create().unwrap();
    for (expected, contents) in [
        (0, "{}"),
        (1, r#"{"scripts":{"postinstall":"example-data"}}"#),
        (2, "{invalid}"),
    ] {
        std::fs::write(session.root().join("package.json"), contents).unwrap();
        let output = Command::new(env!("CARGO_BIN_EXE_cb"))
            .args(["inspect", "--json", "--"])
            .arg(session.root())
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(expected));
        assert!(output.stderr.is_empty());
        let value = crazy_bastard::scanner::json::parse(&output.stdout, false).unwrap();
        assert_eq!(value["schema_version"], 1);
        assert!(
            !String::from_utf8(output.stdout)
                .unwrap()
                .contains("example-data")
        );
    }
    let hooks = session.root().join("hooks");
    std::fs::create_dir(&hooks).unwrap();
    std::fs::write(hooks.join("pre-commit"), "#!/bin/sh\nexit 0\n").unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_cb"))
        .args(["scan", "--json", "--hooks"])
        .arg(&hooks)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    let value = crazy_bastard::scanner::json::parse(&output.stdout, false).unwrap();
    assert_eq!(value["mode"], "hooks");
    assert_eq!(value["findings"][0]["rule"], "GIT_HOOK");
    for arguments in [
        vec!["scan"],
        vec!["scan", "--unknown", "."],
        vec!["scan", ".", "."],
        vec!["scan", "--git-dir", "--hooks", "."],
        vec!["scan", "--hooks", "--hooks", "."],
    ] {
        assert_eq!(
            Command::new(env!("CARGO_BIN_EXE_cb"))
                .args(arguments)
                .output()
                .unwrap()
                .status
                .code(),
            Some(2)
        );
    }
}

#[cfg(feature = "scanner")]
#[test]
fn scan_alias_preserves_the_inspection_report() {
    let session = crazy_bastard::session::Session::create().unwrap();
    let invoke = |name: &str| {
        Command::new(env!("CARGO_BIN_EXE_cb"))
            .args([name, "--json"])
            .arg(session.root())
            .output()
            .unwrap()
    };
    let canonical = invoke("inspect");
    let legacy = invoke("scan");
    assert_eq!(canonical.status.code(), legacy.status.code());
    assert_eq!(canonical.stdout, legacy.stdout);
    assert!(legacy.stderr.is_empty());
}
