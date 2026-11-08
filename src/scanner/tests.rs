use super::*;
use crate::session::Session;
use std::{
    fs,
    os::unix::fs::{PermissionsExt, symlink},
};

fn fixture(files: &[(&str, &str)]) -> Session {
    let session = Session::create().unwrap();
    for (name, contents) in files {
        let path = session.root().join(name);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, contents).unwrap();
    }
    session
}
fn rules(report: &Report) -> Vec<&'static str> {
    report.findings.iter().map(|f| f.rule).collect()
}

#[test]
fn an_empty_selected_folder_has_no_findings_with_a_limited_scope() {
    let session = fixture(&[]);
    let report = scan(session.root());
    assert_eq!(report.exit_code(), 0);
    assert_eq!(report.to_json()["status"], "no_findings_in_scope");
    assert!(
        report.to_json()["scope"]
            .as_str()
            .unwrap()
            .contains("not a CVE")
    );
}
#[test]
fn executable_surfaces_are_reported_without_running_them_or_printing_values() {
    let session = fixture(&[
        (
            ".vscode/settings.json",
            r#"{// example
            "terminal.integrated.profiles.osx":{"Example":{"path":"/bin/sh","args":["-c","touch CB_TEST_FIXTURE"]}},
            "terminal.integrated.env.osx":{"EXAMPLE_TOKEN":"example-data"},
            "git.path":"example-data",
        }"#,
        ),
        (
            ".vscode/tasks.json",
            r#"{"tasks":[{"label":"example-data","command":"touch CB_TEST_FIXTURE","runOptions":{"runOn":"folderOpen"}}]}"#,
        ),
        (
            ".vscode/launch.json",
            r#"{"configurations":[{"program":"example-data"}],"inputs":[{"type":"command","command":"example-data"}]}"#,
        ),
        (
            ".git/config",
            "[core]\n repositoryformatversion=0\n[filter \"example-data\"]\nprocess=touch CB_TEST_FIXTURE\n[alias]\nx=!touch CB_TEST_FIXTURE\n",
        ),
        (
            ".git/hooks/post-checkout",
            "#!/bin/sh\ntouch CB_TEST_FIXTURE\n",
        ),
        (".git/hooks/pre-commit.sample", "#!/bin/sh\nexit 0\n"),
        (
            "package.json",
            r#"{"scripts":{"postinstall":"touch CB_TEST_FIXTURE","test":"example-data"}}"#,
        ),
        ("build.rs", "fn main() {}"),
    ]);
    fs::set_permissions(
        session.root().join(".git/hooks/post-checkout"),
        fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    // An absolute synthetic marker also detects an accidental launch from another working folder.
    for file in [
        ".vscode/settings.json",
        ".vscode/tasks.json",
        ".git/config",
        ".git/hooks/post-checkout",
        "package.json",
    ] {
        let path = session.root().join(file);
        let contents = fs::read_to_string(&path).unwrap().replace(
            "touch CB_TEST_FIXTURE",
            &format!("touch {}", session.root().join("CB_TEST_FIXTURE").display()),
        );
        fs::write(path, contents).unwrap();
    }
    let report = scan(session.root());
    assert!(report.incomplete.is_empty(), "{:?}", report.incomplete);
    assert_eq!(report.exit_code(), 1);
    for rule in [
        "EDITOR_TERMINAL",
        "EDITOR_TOOL",
        "EDITOR_AUTORUN",
        "EDITOR_LAUNCH",
        "EDITOR_COMMAND_INPUT",
        "GIT_FILTER",
        "GIT_ALIAS",
        "GIT_HOOK",
        "PACKAGE_LIFECYCLE",
        "PACKAGE_SCRIPT",
        "RUST_BUILD_SCRIPT",
    ] {
        assert!(rules(&report).contains(&rule), "missing {rule}");
    }
    let output = report.to_json().to_string();
    for private in [
        "example-data",
        "CB_TEST_FIXTURE",
        "/bin/sh",
        "EXAMPLE_TOKEN",
        "pre-commit.sample",
        session.root().to_str().unwrap(),
    ] {
        assert!(!output.contains(private), "leaked {private}");
    }
    assert!(!session.root().join("CB_TEST_FIXTURE").exists());
}
#[test]
fn includes_custom_hooks_and_external_metadata_remain_incomplete() {
    let session = fixture(&[
        (
            ".git/config",
            "[includeIf \"gitdir:example\"]\npath=../other\n[core]\nhooksPath=../hooks\n",
        ),
        (".git/commondir", "../shared"),
    ]);
    let report = scan(session.root());
    assert_eq!(report.exit_code(), 2);
    assert!(rules(&report).contains(&"GIT_INCLUDE"));
    assert!(rules(&report).contains(&"GIT_HOOKS_PATH"));
    fs::remove_dir_all(session.root().join(".git")).unwrap();
    fs::write(session.root().join(".git"), "gitdir: ../external").unwrap();
    assert_eq!(scan(session.root()).exit_code(), 2);
}
#[test]
fn symlinked_files_directories_and_external_targets_are_refused() {
    let session = fixture(&[("private/settings.json", "{}")]);
    symlink(
        session.root().join("private"),
        session.root().join(".vscode"),
    )
    .unwrap();
    assert_eq!(scan(session.root()).exit_code(), 2);
    fs::remove_file(session.root().join(".vscode")).unwrap();
    fs::create_dir(session.root().join(".vscode")).unwrap();
    symlink(
        session.root().join("private/settings.json"),
        session.root().join(".vscode/settings.json"),
    )
    .unwrap();
    assert_eq!(scan(session.root()).exit_code(), 2);
    symlink(session.root().join("private"), session.root().join(".git")).unwrap();
    assert_eq!(scan(session.root()).exit_code(), 2);
}
#[test]
fn fifo_inputs_are_refused_without_waiting_for_a_writer() {
    use std::{ffi::CString, os::unix::ffi::OsStrExt};
    let session = fixture(&[]);
    let fifo = CString::new(session.root().join("package.json").as_os_str().as_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
    assert_eq!(scan(session.root()).exit_code(), 2);
}
#[test]
fn byte_entry_file_and_finding_limits_produce_incomplete_reports() {
    let session = fixture(&[("package.json", &"x".repeat(MAX_FILE + 1))]);
    assert_eq!(scan(session.root()).exit_code(), 2);
    fs::remove_file(session.root().join("package.json")).unwrap();
    for n in 0..=MAX_ENTRIES {
        fs::write(session.root().join(format!("entry-{n}")), "").unwrap();
    }
    assert_eq!(scan(session.root()).exit_code(), 2);
    let mut report = Report::default();
    for _ in 0..=MAX_FINDINGS {
        report.finding(
            Path::new("fixture"),
            "file",
            "FIXTURE",
            "review",
            "Synthetic example.",
        );
    }
    assert_eq!(report.findings.len(), MAX_FINDINGS);
    assert_eq!(report.exit_code(), 2);
    let mut report = Report {
        bytes: MAX_TOTAL,
        ..Report::default()
    };
    let (root, _) = Directory::root(session.root()).unwrap();
    assert!(report.read(&root, OsStr::new("entry-0")).is_none());
    assert_eq!(report.exit_code(), 2);
    let mut report = Report {
        read_attempts: MAX_FILES,
        ..Report::default()
    };
    assert!(report.read(&root, OsStr::new("entry-0")).is_none());
    assert_eq!(report.exit_code(), 2);
}
#[test]
fn duplicate_keys_invalid_shapes_and_unreadable_roots_are_incomplete() {
    for (file, text) in [
        (".vscode/settings.json", r#"{"a":1,"a":2}"#),
        ("package.json", "[]"),
        (".vscode/tasks.json", "{\"tasks\":{}}"),
        (".git/config", "[core\nfsmonitor=example"),
        (".vscode/launch.json", "{\"configurations\":[1]}"),
    ] {
        let session = fixture(&[(file, text)]);
        assert_eq!(scan(session.root()).exit_code(), 2, "{file}");
    }
    let session = fixture(&[]);
    assert_eq!(scan(&session.root().join("missing")).exit_code(), 2);
}
#[test]
fn workspace_embedded_settings_and_tasks_are_checked_without_following_folders() {
    let session = fixture(&[(
        "example.code-workspace",
        r#"{
      "folders":[{"path":"../other"}],
      "settings":{"security.workspace.trust.enabled":false},
      "tasks":{"tasks":[{"runOptions":{"runOn":"folderOpen"}}]},
      "launch":{"configurations":[{"request":"launch"}]}
    }"#,
    )]);
    let report = scan(session.root());
    for rule in ["EDITOR_PROTECTION", "EDITOR_AUTORUN", "EDITOR_LAUNCH"] {
        assert!(rules(&report).contains(&rule));
    }
    assert_eq!(report.exit_code(), 2);
}
#[test]
fn an_open_directory_cannot_be_retargeted_by_a_symlink_swap() {
    let session = fixture(&[
        (".vscode/settings.json", "{}"),
        ("elsewhere/settings.json", "private-example"),
    ]);
    let (root, _) = Directory::root(session.root()).unwrap();
    let editor = root.directory(OsStr::new(".vscode")).unwrap().unwrap();
    fs::rename(
        session.root().join(".vscode"),
        session.root().join("original"),
    )
    .unwrap();
    symlink(
        session.root().join("elsewhere"),
        session.root().join(".vscode"),
    )
    .unwrap();
    assert_eq!(
        editor
            .read(OsStr::new("settings.json"), MAX_FILE)
            .unwrap()
            .unwrap(),
        b"{}"
    );
    assert!(root.directory(OsStr::new(".vscode")).is_err());
}
#[test]
fn terminal_controls_in_paths_are_visible_instead_of_executed() {
    let path = Path::new(".git/hooks/\x1b]52;fixture\x07\n\u{202e}");
    let safe = safe_path(path);
    assert!(!safe.chars().any(char::is_control));
    assert!(!safe.contains('\u{202e}'));
    assert!(safe.contains("\\u{1b}"));
}
#[test]
fn bare_metadata_is_checked_when_explicitly_selected() {
    let session = fixture(&[
        ("HEAD", "ref: refs/heads/example"),
        ("config", "[core]\nfsmonitor=example\n"),
        ("objects/example", ""),
    ]);
    assert!(rules(&scan(session.root())).contains(&"GIT_FSMONITOR"));
}

#[test]
fn comments_cannot_hide_the_next_git_setting_with_a_trailing_backslash() {
    let session = fixture(&[(
        ".git/config",
        "# comment\\\n[core]\nrepositoryformatversion=0 # comment\\\nfsmonitor=example\n[filter \"fixture\"]\npro\\\ncess=example\n",
    )]);
    let report = scan(session.root());
    assert!(report.incomplete.is_empty());
    assert!(rules(&report).contains(&"GIT_FSMONITOR"));
    assert!(rules(&report).contains(&"GIT_FILTER"));
}

#[test]
fn explicit_modes_cover_linked_metadata_and_custom_hooks_without_following_references() {
    let session = fixture(&[
        ("metadata/HEAD", "ref: refs/heads/example"),
        ("metadata/config.worktree", "[core]\nfsmonitor=example\n"),
        ("metadata/commondir", "../shared"),
        ("hooks/post-checkout", "#!/bin/sh\nexit 0\n"),
    ]);
    let metadata = scan_mode(&session.root().join("metadata"), ScanMode::GitDirectory);
    assert_eq!(metadata.exit_code(), 2);
    assert!(rules(&metadata).contains(&"GIT_FSMONITOR"));
    assert_eq!(metadata.to_json()["mode"], "git-dir");
    let hooks = scan_mode(&session.root().join("hooks"), ScanMode::Hooks);
    assert_eq!(hooks.exit_code(), 1);
    assert!(rules(&hooks).contains(&"GIT_HOOK"));
    assert_eq!(hooks.to_json()["mode"], "hooks");
    assert_eq!(
        scan_mode(session.root(), ScanMode::GitDirectory).exit_code(),
        2
    );
}

#[test]
fn unreadable_files_are_incomplete_instead_of_skipped() {
    let session = fixture(&[("package.json", "{}")]);
    let path = session.root().join("package.json");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o000)).unwrap();
    assert_eq!(scan(session.root()).exit_code(), 2);
}

#[test]
fn failed_reads_consume_a_bounded_allowance() {
    let session = fixture(&[]);
    symlink("missing-target", session.root().join("linked")).unwrap();
    let (root, _) = Directory::root(session.root()).unwrap();
    let mut report = Report::default();
    for _ in 0..10 {
        assert!(report.read(&root, OsStr::new("linked")).is_none());
    }
    assert_eq!(report.bytes, MAX_TOTAL);
    assert_eq!(report.read_attempts, MAX_TOTAL / MAX_FILE);
    assert_eq!(report.exit_code(), 2);
}
