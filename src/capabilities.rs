//! Reports shipped capabilities without starting Git, editors, agents or external runtimes.
use std::path::Path;

pub const WORKSPACE_UNAVAILABLE: &str = "isolated editor workspaces are not integrated yet; no host application was launched. Use cb host code . only for explicit host review, which does not isolate host files or networking. See docs/product.md for the runtime integration plan";

pub fn doctor() -> String {
    let inspection = if cfg!(feature = "scanner") {
        "enabled; static launch-surface review"
    } else {
        "disabled; build with --features scanner"
    };
    let seatbelt = if cfg!(target_os = "macos") && Path::new("/usr/bin/sandbox-exec").is_file() {
        "experimental; executable found, policy probed at launch"
    } else {
        "unavailable; compatible macOS sandbox-exec required"
    };
    let host_code = if cfg!(target_os = "macos") {
        "host review only; application and monitor permissions checked at launch"
    } else {
        "unavailable; macOS required"
    };
    let review = if cfg!(feature = "review") {
        "experimental; bundled ast-grep-core 0.51.1, selected sources and opt-in Codex CLI; macOS checks at launch"
    } else {
        "disabled; build with --features review (includes scanner)"
    };
    format!(
        "crazy-bastard (cb) 0.1.0\nPlatform: {}\ncb inspect: {inspection}\nSource/harness review: {review}\ncb run: {seatbelt}\ncb code: unavailable; no verified workspace runtime adapter\ncb host code: {host_code}\ncb host git / cb-git: host hook policy; Git version checked at launch\nNetwork/command approval TUI: not implemented\nOpenShell/Lima/nono adapters: not integrated; installation alone does not enable them\nNo command was launched; runtime presence is not a security certification.",
        std::env::consts::OS
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn diagnostics_distinguish_host_review_from_unavailable_workspace_enforcement() {
        let text = doctor();
        assert!(text.contains("cb code: unavailable"));
        assert!(text.contains("host review only") || !cfg!(target_os = "macos"));
        assert!(text.contains("approval TUI: not implemented"));
        assert!(text.contains(if cfg!(feature = "scanner") {
            "cb inspect: enabled"
        } else {
            "cb inspect: disabled"
        }));
    }
}
