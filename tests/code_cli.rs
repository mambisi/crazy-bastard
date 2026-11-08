use std::process::Command;
#[test]
fn unavailable_isolated_editor_launch_never_starts_a_host_application() {
    for args in [
        vec!["code"],
        vec!["code", "."],
        vec!["code", "--vm", "."],
        vec!["code", "/missing/example"],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_cb"))
            .args(args)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2));
        assert!(
            String::from_utf8(output.stderr)
                .unwrap()
                .contains("no host application was launched")
        );
    }
}
#[test]
fn host_namespace_refuses_isolation_flags_and_arbitrary_editor_options() {
    for args in [
        vec!["host", "code", "--vm", "."],
        vec!["host", "code", "--disable-workspace-trust", "."],
        vec!["host", "code", "--user-data-dir", "example"],
        vec!["code", "--monitor", "."],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_cb"))
            .args(args)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2));
    }
}
#[test]
fn legacy_git_is_a_migration_error_and_never_runs_git() {
    let output = Command::new(env!("CARGO_BIN_EXE_cb"))
        .args(["git", "--version"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert!(
        String::from_utf8(output.stderr)
            .unwrap()
            .contains("cb host git")
    );
}
#[test]
fn help_and_doctor_explain_available_boundaries_without_launching_editors() {
    for args in [
        vec!["--help"],
        vec!["code", "--help"],
        vec!["host", "--help"],
        vec!["host", "code", "--help"],
        vec!["inspect", "--help"],
        vec!["run", "--help"],
        vec!["doctor"],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_cb"))
            .args(args)
            .output()
            .unwrap();
        assert!(output.status.success());
        assert!(output.stderr.is_empty());
        assert!(!output.stdout.is_empty());
    }
}
