use crate::{Result, invalid};
use std::{collections::BTreeMap, ffi::OsString, path::Path};

pub const PROFILE: &str = r#"(version 1)
(deny default)
(deny process-info*)
(allow process-exec)
(allow sysctl-read (sysctl-name "hw.pagesize") (sysctl-name "hw.pagesize_compat") (sysctl-name "kern.usrstack") (sysctl-name "kern.usrstack64"))
(allow file-read-metadata)
(allow file-read* (literal "/"))
(allow file-read* file-map-executable
    (subpath "/System/Library")
    (subpath "/System/Volumes/Preboot/Cryptexes/OS")
    (subpath "/private/preboot/Cryptexes/OS")
    (subpath "/Library/Apple")
    (subpath "/usr/lib") (subpath "/usr/libexec") (subpath "/usr/share")
    (subpath "/usr/bin") (subpath "/usr/sbin") (subpath "/bin") (subpath "/sbin"))
(allow file-read* (literal "/dev/random") (literal "/dev/urandom"))
(allow file-read* file-write-data (literal "/dev/null") (literal "/dev/zero"))
(allow file-read* file-write* file-map-executable (subpath (param "CB_ROOT")))
"#;

pub fn require_backend() -> Result<()> {
    if !cfg!(target_os = "macos") || !Path::new("/usr/bin/sandbox-exec").is_file() {
        return Err(invalid(
            "a compatible macOS Seatbelt backend is required; no command was run",
        ));
    }
    Ok(())
}
pub fn environment(root: &Path) -> BTreeMap<OsString, OsString> {
    let mut env = BTreeMap::new();
    for (key, value) in [
        ("HOME", root.join("home").into_os_string()),
        ("TMPDIR", root.join("tmp").into_os_string()),
        ("CB_INPUT_DIR", root.join("input").into_os_string()),
        ("PATH", OsString::from("/usr/bin:/bin:/usr/sbin:/sbin")),
        ("USER", OsString::from("cb")),
        ("LOGNAME", OsString::from("cb")),
        ("LANG", OsString::from("C")),
        ("LC_ALL", OsString::from("C")),
        ("TERM", OsString::from("dumb")),
        ("GIT_CONFIG_NOSYSTEM", OsString::from("1")),
        ("GIT_CONFIG_GLOBAL", OsString::from("/dev/null")),
    ] {
        env.insert(OsString::from(key), value);
    }
    env
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn credentials_and_host_ipc_are_not_inherited() {
        let env = environment(Path::new("/private/tmp/example"));
        for k in [
            "AWS_SECRET_ACCESS_KEY",
            "SSH_AUTH_SOCK",
            "DOCKER_HOST",
            "NODE_OPTIONS",
            "DYLD_INSERT_LIBRARIES",
            "GITHUB_TOKEN",
        ] {
            assert!(!env.contains_key(&OsString::from(k)));
        }
        assert_eq!(env[&OsString::from("HOME")], "/private/tmp/example/home");
    }
    #[test]
    fn network_mach_services_and_fork_are_not_granted() {
        for text in [
            "(allow network",
            "(allow mach-lookup",
            "(allow process-fork",
            "(subpath \"/System\")",
            "(import",
        ] {
            assert!(!PROFILE.contains(text));
        }
        assert!(PROFILE.contains("(param \"CB_ROOT\")"));
        assert!(PROFILE.contains("(deny process-info*)"));
    }
}
