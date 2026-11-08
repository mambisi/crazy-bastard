use super::*;
fn args(items: &[&str]) -> Vec<OsString> {
    items.iter().map(OsString::from).collect()
}
#[test]
fn isolated_launch_is_the_default_and_host_review_is_explicit() {
    let isolated = Options::parse(&[]).unwrap();
    assert_eq!(isolated.directory, Path::new("."));
    assert_eq!(isolated.mode, Mode::IsolatedWorkspace);
    let host = Options::parse_host(&args(&["--monitor", "--", "-folder"])).unwrap();
    assert!(host.monitor);
    assert_eq!(host.mode, Mode::HostReview);
    assert_eq!(host.directory, Path::new("-folder"));
    assert!(Options::parse_host(&args(&["--vm", "."])).is_err());
    assert!(Options::parse(&args(&["--monitor", "."])).is_err());
    for a in [
        &["--disable-workspace-trust"][..],
        &["--user-data-dir", "example"],
        &["--monitor", "--monitor"],
        &["one", "two"],
    ] {
        assert!(Options::parse_host(&args(a)).is_err());
    }
}
#[test]
fn unavailable_isolation_never_falls_back_to_host_review_or_reads_the_target() {
    for a in [
        &["/missing/example"][..],
        &["--vm", "/missing/example"],
        &["--", "-folder"],
    ] {
        let o = Options::parse(&args(a)).unwrap();
        assert!(
            execute(&o)
                .unwrap_err()
                .to_string()
                .contains("no host application was launched")
        );
    }
}
#[test]
fn separate_profiles_keep_trust_controls_out_of_the_project() {
    let s = Session::create().unwrap();
    let path = profile(&s).unwrap();
    assert_eq!(fs::read_to_string(&path).unwrap(), SETTINGS);
    assert!(path.starts_with(s.root()));
    assert!(s.root().join("extensions").is_dir());
    #[cfg(feature = "scanner")]
    {
        let settings = crate::scanner::json::parse(SETTINGS.as_bytes(), false).unwrap();
        assert_eq!(
            settings["security.workspace.trust.enabled"],
            crate::scanner::json::Value::Bool(true)
        );
        assert_eq!(settings["task.allowAutomaticTasks"], "off");
        assert_eq!(
            settings["git.enabled"],
            crate::scanner::json::Value::Bool(false)
        );
    }
}
#[test]
fn host_commands_use_fixed_arguments_and_a_replaced_environment() {
    let s = Session::create().unwrap();
    let c = command(
        Path::new("/bin/echo"),
        s.root(),
        Path::new("/example/project $(literal)"),
    )
    .unwrap();
    let arguments: Vec<_> = c
        .get_args()
        .map(|a| a.to_string_lossy().into_owned())
        .collect();
    assert_eq!(arguments.last().unwrap(), "/example/project $(literal)");
    assert!(arguments.contains(&"--disable-extensions".into()));
    assert!(!arguments.contains(&"--disable-workspace-trust".into()));
    let env: Vec<_> = c
        .get_envs()
        .map(|(k, v)| (k.to_string_lossy().into_owned(), v.unwrap().to_os_string()))
        .collect();
    assert!(!env.iter().any(|(k, _)| k.starts_with("DYLD_")
        || k.contains("TOKEN")
        || (k.starts_with("VSCODE_") && k != "VSCODE_CLI")));
    assert!(
        env.iter()
            .any(|(k, v)| k == "HOME" && v == s.root().join("home").as_os_str())
    );
}
#[test]
fn broad_home_selections_and_workspace_files_are_refused() {
    let s = Session::create().unwrap();
    assert!(workspace(s.root(), s.root()).is_err());
    assert!(workspace(s.root().parent().unwrap(), s.root()).is_err());
    fs::write(s.root().join("example.code-workspace"), "{}").unwrap();
    assert!(
        workspace(
            &s.root().join("example.code-workspace"),
            Path::new("/example/home")
        )
        .is_err()
    );
    assert_eq!(
        workspace(&s.root().join("work"), s.root()).unwrap(),
        s.root().join("work")
    );
}
#[cfg(target_os = "macos")]
#[test]
fn owned_group_cleanup_does_not_signal_an_unrelated_process() {
    let mut unrelated = Command::new("/bin/sleep").arg("5").spawn().unwrap();
    let child = Command::new("/bin/sleep")
        .arg("5")
        .process_group(0)
        .spawn()
        .unwrap();
    let mut owned = OwnedApplication {
        child,
        finished: false,
    };
    assert!(!owned.exited().unwrap());
    owned.stop().unwrap();
    assert!(owned.finished);
    assert!(unrelated.try_wait().unwrap().is_none());
    unrelated.kill().unwrap();
    unrelated.wait().unwrap();
}
