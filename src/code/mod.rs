//! Separate, hardened host VS Code window. No OS sandbox is claimed by this mode.
mod monitor;
use crate::{Result, invalid, session::Session};
use std::{
    ffi::OsString,
    fs, io,
    os::unix::{
        ffi::OsStrExt,
        process::{CommandExt, ExitStatusExt},
    },
    path::{Path, PathBuf},
    process::{Child, Command, ExitStatus, Stdio},
    thread,
    time::{Duration, Instant},
};

const APP: &str = "/Applications/Visual Studio Code.app";
const SETTINGS: &str = r#"{
  "security.workspace.trust.enabled": true,
  "security.workspace.trust.startupPrompt": "never",
  "security.workspace.trust.emptyWindow": false,
  "security.workspace.trust.untrustedFiles": "newWindow",
  "security.workspace.trust.banner": "always",
  "task.allowAutomaticTasks": "off",
  "terminal.integrated.allowInUntrustedWorkspace": false,
  "terminal.integrated.inheritEnv": false,
  "git.enabled": false,
  "chat.disableAIFeatures": true,
  "git.autoRepositoryDetection": false,
  "git.openRepositoryInParentFolders": "never",
  "git.autofetch": false,
  "extensions.autoCheckUpdates": false,
  "extensions.autoUpdate": false,
  "extensions.ignoreRecommendations": true,
  "telemetry.telemetryLevel": "off",
  "update.mode": "none",
  "workbench.enableExperiments": false,
  "workbench.startupEditor": "none",
  "window.restoreWindows": "none",
  "window.title": "CB host review (not sandboxed) | ${activeEditorShort}"
}
"#;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    IsolatedWorkspace,
    HostReview,
}

#[derive(Debug)]
pub struct Options {
    directory: PathBuf,
    monitor: bool,
    mode: Mode,
}
impl Options {
    pub fn parse(args: &[OsString]) -> Result<Self> {
        Self::parse_mode(args, Mode::IsolatedWorkspace)
    }
    pub fn parse_host(args: &[OsString]) -> Result<Self> {
        Self::parse_mode(args, Mode::HostReview)
    }
    fn parse_mode(args: &[OsString], mode: Mode) -> Result<Self> {
        let mut directory = None;
        let mut monitor = false;
        let mut legacy_vm = false;
        let mut positional = false;
        for arg in args {
            if !positional && arg == "--" {
                positional = true;
                continue;
            }
            if !positional && arg == "--vm" {
                if mode == Mode::HostReview {
                    return Err(invalid(
                        "--vm cannot be combined with host review; use cb code DIRECTORY; no application was launched",
                    ));
                }
                if legacy_vm {
                    return Err(invalid("duplicate --vm option"));
                }
                legacy_vm = true;
                continue;
            }
            if !positional && arg == "--monitor" {
                if mode == Mode::IsolatedWorkspace {
                    return Err(invalid(
                        "--monitor observes host activity; use cb host code --monitor DIRECTORY for explicit host review. No application was launched",
                    ));
                }
                if monitor {
                    return Err(invalid("duplicate --monitor option"));
                }
                monitor = true;
                continue;
            }
            if !positional && arg.as_bytes().starts_with(b"-") {
                return Err(invalid(
                    "unsupported editor option; use cb code --help or cb host code --help",
                ));
            }
            if directory.replace(PathBuf::from(arg)).is_some() {
                return Err(invalid("code opens exactly one folder"));
            }
        }
        Ok(Self {
            directory: directory.unwrap_or_else(|| PathBuf::from(".")),
            monitor,
            mode,
        })
    }
}

fn workspace(path: &Path, home: &Path) -> Result<PathBuf> {
    let directory = path
        .canonicalize()
        .map_err(|_| invalid("code needs an existing directory"))?;
    if !directory.is_dir() {
        return Err(invalid(
            "code accepts a folder, not a file or workspace definition",
        ));
    }
    if home.starts_with(&directory) {
        return Err(invalid(
            "refusing to open the real home directory or one of its parents as a review workspace",
        ));
    }
    Ok(directory)
}
fn real_home() -> Result<PathBuf> {
    use std::{
        ffi::{CStr, OsStr},
        os::unix::ffi::OsStrExt,
    };
    let mut record: libc::passwd = unsafe { std::mem::zeroed() };
    let mut result = std::ptr::null_mut();
    let mut buffer = vec![0u8; 16384];
    let error = unsafe {
        libc::getpwuid_r(
            libc::getuid(),
            &mut record,
            buffer.as_mut_ptr().cast(),
            buffer.len(),
            &mut result,
        )
    };
    if error != 0 || result.is_null() || record.pw_dir.is_null() {
        return Err(invalid("cannot identify the account home directory"));
    }
    let path = PathBuf::from(OsStr::from_bytes(
        unsafe { CStr::from_ptr(record.pw_dir) }.to_bytes(),
    ));
    path.canonicalize()
        .map_err(|_| invalid("cannot resolve the account home directory"))
}
fn application() -> Result<PathBuf> {
    let app = Path::new(APP);
    if app.symlink_metadata().is_err() || app.is_symlink() {
        return Err(invalid(
            "install Visual Studio Code in /Applications; application bundle links are refused",
        ));
    }
    let portable = app.parent().unwrap().join("code-portable-data");
    if portable.symlink_metadata().is_ok() {
        return Err(invalid(
            "VS Code portable data can override the private profile; no application was launched",
        ));
    }
    let exe = app.join("Contents/MacOS/Code");
    let file = crate::session::open_regular_no_symlinks(&exe).map_err(|_| {
        invalid("VS Code executable must be a regular file without linked ancestors")
    })?;
    use std::os::unix::fs::PermissionsExt;
    if file.metadata()?.permissions().mode() & 0o111 == 0 {
        return Err(invalid("VS Code executable is not executable"));
    }
    Ok(exe)
}
fn profile(session: &Session) -> Result<PathBuf> {
    for relative in ["vscode/User", "extensions"] {
        fs::create_dir_all(session.root().join(relative))?;
    }
    let settings = session.root().join("vscode/User/settings.json");
    fs::write(&settings, SETTINGS)?;
    Ok(settings)
}
fn command(executable: &Path, root: &Path, workspace: &Path) -> Result<Command> {
    let inherited: Vec<i32> = fs::read_dir("/dev/fd")?
        .map(|e| e.map(|e| e.file_name()))
        .collect::<io::Result<Vec<_>>>()?
        .iter()
        .filter_map(|n| n.to_str()?.parse().ok())
        .filter(|fd| *fd >= 3)
        .collect();
    let mut c = Command::new(executable);
    c.args([
        "--new-window",
        "--disable-extensions",
        "--skip-add-to-recently-opened",
        "--disable-updates",
        "--disable-telemetry",
    ])
    .arg("--user-data-dir")
    .arg(root.join("vscode"))
    .arg("--extensions-dir")
    .arg(root.join("extensions"))
    .arg("--")
    .arg(workspace)
    .current_dir(root.join("work"))
    .env_clear()
    .envs(crate::sandbox::environment(root))
    .env("VSCODE_CLI", "1")
    .env("SHELL", "/bin/zsh")
    .env("ZDOTDIR", root.join("home"))
    .stdin(Stdio::null())
    .stdout(Stdio::null())
    .stderr(Stdio::null())
    .process_group(0);
    // Do not pass host descriptors or loader/IPC variables to the new GUI instance.
    unsafe {
        c.pre_exec(move || {
            for fd in &inherited {
                let flags = libc::fcntl(*fd, libc::F_GETFD);
                if flags < 0 {
                    if io::Error::last_os_error().raw_os_error() == Some(libc::EBADF) {
                        continue;
                    }
                    return Err(io::Error::last_os_error());
                }
                if libc::fcntl(*fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) < 0 {
                    return Err(io::Error::last_os_error());
                }
            }
            let limit = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            if libc::setrlimit(libc::RLIMIT_CORE, &limit) != 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    Ok(c)
}

struct OwnedApplication {
    child: Child,
    finished: bool,
}
impl OwnedApplication {
    fn exited(&self) -> Result<bool> {
        let mut status: libc::siginfo_t = unsafe { std::mem::zeroed() };
        let result = unsafe {
            libc::waitid(
                libc::P_PID,
                self.child.id(),
                &mut status,
                libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
            )
        };
        if result != 0 {
            return Err(io::Error::last_os_error().into());
        }
        Ok(unsafe { status.si_pid() } != 0)
    }
    fn finish(&mut self) -> Result<ExitStatus> {
        // The root is still unreaped, retaining this group's identifier during cleanup.
        if self.child.id() <= 1 {
            return Err(invalid("invalid owned process group"));
        }
        unsafe {
            libc::kill(-(self.child.id() as i32), libc::SIGKILL);
        }
        let status = self.child.wait()?;
        self.finished = true;
        Ok(status)
    }
    fn stop(&mut self) -> Result<()> {
        if self.finished {
            return Ok(());
        }
        // Only this owner waits/reaps. A live or unreaped root PID cannot be reused
        // while it identifies the process group that CB created at spawn.
        if self.child.id() <= 1 {
            return Err(invalid("invalid owned process group"));
        }
        unsafe {
            libc::kill(-(self.child.id() as i32), libc::SIGTERM);
        }
        let until = Instant::now() + Duration::from_secs(2);
        loop {
            // Observe without reaping so the group identifier cannot be reused before SIGKILL.
            let mut status: libc::siginfo_t = unsafe { std::mem::zeroed() };
            let result = unsafe {
                libc::waitid(
                    libc::P_PID,
                    self.child.id(),
                    &mut status,
                    libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
                )
            };
            if result != 0 || unsafe { status.si_pid() } != 0 || Instant::now() >= until {
                break;
            }
            thread::sleep(Duration::from_millis(20));
        }
        self.finish()?;
        Ok(())
    }
}
impl Drop for OwnedApplication {
    fn drop(&mut self) {
        if !self.finished {
            let _ = self.stop();
        }
    }
}

pub fn execute(options: &Options) -> Result<i32> {
    if options.mode == Mode::IsolatedWorkspace {
        return Err(invalid(crate::capabilities::WORKSPACE_UNAVAILABLE));
    }
    if !cfg!(target_os = "macos") {
        return Err(invalid("cb host code currently supports macOS only"));
    }
    let home = real_home()?;
    let workspace = workspace(&options.directory, &home)?;
    let executable = application()?;
    if options.monitor {
        monitor::preflight()?;
    }
    let _signals = crate::interrupt::Guard::install()?;
    let session = Session::create()?;
    let settings = profile(&session)?;
    eprintln!(
        "cb: opening a hardened host VS Code window; this is not OS isolation. The original folder is editable. Keep it in Restricted Mode."
    );
    eprintln!(
        "cb: quit this dedicated VS Code instance to finish the session. Ctrl-C stops its process group."
    );
    if options.monitor {
        eprintln!(
            "cb: monitor enabled: 250 ms polling for unexpected executables, IP sockets with a remote peer and observed open files in the real home outside the workspace. Detection can occur after access and can miss activity."
        );
    }
    let mut app = OwnedApplication {
        child: command(&executable, session.root(), &workspace)?.spawn()?,
        finished: false,
    };
    let mut watcher = if options.monitor {
        Some(monitor::Watcher::new(
            app.child.id(),
            &executable,
            &workspace,
            session.root(),
            &home,
        )?)
    } else {
        None
    };
    let mut network_reported = false;
    let result = loop {
        if app.exited()? {
            let status = app.finish()?;
            break Ok(status
                .code()
                .unwrap_or_else(|| 128 + status.signal().unwrap_or(1)));
        }
        if crate::interrupt::interrupted() {
            break Err(invalid("VS Code session interrupted"));
        }
        if let Some(watcher) = &mut watcher {
            if crate::session::open_regular_no_symlinks(&settings)
                .and_then(|mut f| {
                    use std::io::Read;
                    let mut bytes = Vec::new();
                    (&mut f)
                        .take(SETTINGS.len() as u64 + 1)
                        .read_to_end(&mut bytes)?;
                    if bytes == SETTINGS.as_bytes() {
                        Ok(())
                    } else {
                        Err(invalid("profile changed"))
                    }
                })
                .is_err()
            {
                break Err(invalid(
                    "monitor: protective profile settings changed; stopping the owned process group",
                ));
            }
            match watcher.poll() {
                Ok(active) => {
                    if active && !network_reported {
                        eprintln!(
                            "cb: monitor: an IP socket with a remote peer was observed. Host review does not block traffic; this is not proof of an attack."
                        );
                    }
                    network_reported = active;
                }
                Err(reason) => {
                    break Err(invalid(format!(
                        "monitor: {reason}; stopping the owned process group. Earlier access or escaped processes cannot be ruled out"
                    )));
                }
            }
        }
        thread::sleep(Duration::from_millis(250));
    };
    if !app.finished {
        app.stop()?;
    }
    session.close()?;
    result
}

#[cfg(test)]
mod tests;
