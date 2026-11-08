//! Polling observations of CB's process group, not authorization or malware classification.
use crate::{Result, invalid};
use std::path::{Path, PathBuf};

#[derive(Debug, PartialEq, Eq)]
enum Observation {
    Executable(PathBuf),
    IpSocket,
    File(PathBuf),
}
#[derive(Debug)]
struct Policy {
    executable: PathBuf,
    workspace: PathBuf,
    session: PathBuf,
    home: PathBuf,
}
impl Policy {
    fn check(&self, event: &Observation) -> std::result::Result<(), &'static str> {
        match event {
            Observation::Executable(path) if !self.allowed_executable(path) => {
                Err("unexpected executable observed")
            }
            Observation::File(path)
                if path.starts_with(&self.home)
                    && !path.starts_with(&self.workspace)
                    && !path.starts_with(&self.session) =>
            {
                Err("an open file in the real home outside the selected workspace was observed")
            }
            _ => Ok(()),
        }
    }
    fn allowed_executable(&self, path: &Path) -> bool {
        if path == self.executable {
            return true;
        }
        let Some(contents) = self.executable.parent().and_then(Path::parent) else {
            return false;
        };
        let Ok(relative) = path.strip_prefix(contents.join("Frameworks")) else {
            return false;
        };
        [
            "Code Helper.app/Contents/MacOS/Code Helper",
            "Code Helper (GPU).app/Contents/MacOS/Code Helper (GPU)",
            "Code Helper (Plugin).app/Contents/MacOS/Code Helper (Plugin)",
            "Code Helper (Renderer).app/Contents/MacOS/Code Helper (Renderer)",
            "Electron Framework.framework/Versions/A/Helpers/chrome_crashpad_handler",
        ]
        .iter()
        .any(|p| relative == Path::new(p))
    }
}

#[cfg(target_os = "macos")]
mod native {
    use super::*;
    use std::{
        ffi::{CStr, OsStr},
        os::unix::ffi::OsStrExt,
    };
    const MAX_PROCESSES: usize = 128;
    const MAX_FDS: usize = 4096;
    const MAX_TOTAL_FDS: usize = 16384;
    unsafe extern "C" {
        fn cb_monitor_descriptor(
            pid: i32,
            fd: i32,
            kind: u32,
            path: *mut libc::c_char,
            capacity: u32,
        ) -> i32;
    }
    #[derive(Clone, Copy, PartialEq, Eq)]
    struct Identity {
        pid: u32,
        seconds: u64,
        micros: u64,
    }
    fn info(pid: i32) -> Result<Option<libc::proc_bsdinfo>> {
        let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
        let count = unsafe {
            libc::proc_pidinfo(
                pid,
                libc::PROC_PIDTBSDINFO,
                0,
                (&mut info as *mut libc::proc_bsdinfo).cast(),
                size_of::<libc::proc_bsdinfo>() as i32,
            )
        };
        if count == size_of::<libc::proc_bsdinfo>() as i32 {
            return Ok(Some(info));
        }
        let error = std::io::Error::last_os_error();
        if matches!(error.raw_os_error(), Some(libc::ESRCH | libc::ENOENT)) {
            return Ok(None);
        }
        Err(invalid("process observation unavailable"))
    }
    fn identity(info: &libc::proc_bsdinfo) -> Identity {
        Identity {
            pid: info.pbi_pid,
            seconds: info.pbi_start_tvsec,
            micros: info.pbi_start_tvusec,
        }
    }
    pub fn preflight() -> Result<()> {
        if info(std::process::id() as i32)?.is_none() {
            return Err(invalid("monitor process inspection is unavailable"));
        }
        Ok(())
    }
    pub struct Watcher {
        root: Identity,
        policy: Policy,
    }
    impl Watcher {
        pub fn new(
            pid: u32,
            executable: &Path,
            workspace: &Path,
            session: &Path,
            home: &Path,
        ) -> Result<Self> {
            let root = info(pid as i32)?
                .ok_or_else(|| invalid("cannot capture owned process identity"))?;
            if root.pbi_pgid != pid {
                return Err(invalid(
                    "owned application did not receive its private process group",
                ));
            }
            Ok(Self {
                root: identity(&root),
                policy: Policy {
                    executable: executable.to_owned(),
                    workspace: workspace.to_owned(),
                    session: session.to_owned(),
                    home: home.to_owned(),
                },
            })
        }
        pub fn poll(&mut self) -> std::result::Result<bool, &'static str> {
            let observations = self
                .observe()
                .map_err(|_| "monitor observation failed or exceeded its limits")?;
            let network = observations.contains(&Observation::IpSocket);
            for observation in observations {
                self.policy.check(&observation)?;
            }
            Ok(network)
        }
        fn observe(&mut self) -> Result<Vec<Observation>> {
            let root =
                info(self.root.pid as i32)?.ok_or_else(|| invalid("owned process disappeared"))?;
            if identity(&root) != self.root || root.pbi_pgid != self.root.pid {
                return Err(invalid("owned process identity changed"));
            }
            let mut pids = [0i32; MAX_PROCESSES + 1];
            let count = unsafe {
                libc::proc_listpgrppids(
                    self.root.pid as i32,
                    pids.as_mut_ptr().cast(),
                    size_of_val(&pids) as i32,
                )
            };
            if count <= 0 || count as usize > MAX_PROCESSES {
                return Err(invalid("process group observation incomplete"));
            }
            let mut events = Vec::new();
            let mut total = 0;
            for pid in &pids[..count as usize] {
                let Some(before) = info(*pid)? else {
                    continue;
                };
                if before.pbi_pgid != self.root.pid || before.pbi_uid != unsafe { libc::geteuid() }
                {
                    return Err(invalid("process left the owned group"));
                }
                let mut path = [0u8; 4096];
                let length = unsafe {
                    libc::proc_pidpath(*pid, path.as_mut_ptr().cast(), path.len() as u32)
                };
                if length <= 0 {
                    if info(*pid)?.is_none() {
                        continue;
                    }
                    return Err(invalid("executable observation incomplete"));
                }
                let end = path
                    .iter()
                    .position(|b| *b == 0)
                    .ok_or_else(|| invalid("executable path truncated"))?;
                let executable = PathBuf::from(OsStr::from_bytes(&path[..end]));
                let mut observed = vec![Observation::Executable(executable)];
                let mut fds: Vec<libc::proc_fdinfo> = (0..=MAX_FDS)
                    .map(|_| libc::proc_fdinfo {
                        proc_fd: 0,
                        proc_fdtype: 0,
                    })
                    .collect();
                let bytes = unsafe {
                    libc::proc_pidinfo(
                        *pid,
                        libc::PROC_PIDLISTFDS,
                        0,
                        fds.as_mut_ptr().cast(),
                        (fds.len() * size_of::<libc::proc_fdinfo>()) as i32,
                    )
                };
                if bytes <= 0 {
                    if info(*pid)?.is_none() {
                        continue;
                    }
                    return Err(invalid("descriptor observation incomplete"));
                }
                let count = bytes as usize / size_of::<libc::proc_fdinfo>();
                total += count;
                if bytes as usize % size_of::<libc::proc_fdinfo>() != 0
                    || count > MAX_FDS
                    || total > MAX_TOTAL_FDS
                {
                    return Err(invalid("descriptor budget exceeded"));
                }
                for fd in &fds[..count] {
                    let mut path = [0i8; 4096];
                    match unsafe {
                        cb_monitor_descriptor(
                            *pid,
                            fd.proc_fd,
                            fd.proc_fdtype,
                            path.as_mut_ptr(),
                            path.len() as u32,
                        )
                    } {
                        0 | 3 => (),
                        1 => observed.push(Observation::IpSocket),
                        2 => {
                            let bytes = unsafe { CStr::from_ptr(path.as_ptr()) }.to_bytes();
                            observed
                                .push(Observation::File(PathBuf::from(OsStr::from_bytes(bytes))));
                        }
                        _ => {
                            if info(*pid)?.is_none() {
                                break;
                            }
                            return Err(invalid("descriptor details unavailable"));
                        }
                    }
                }
                if info(*pid)?.is_some_and(|after| {
                    identity(&after) == identity(&before) && after.pbi_pgid == self.root.pid
                }) {
                    events.extend(observed);
                }
            }
            Ok(events)
        }
    }
}
#[cfg(target_os = "macos")]
pub(super) use native::{Watcher, preflight};
#[cfg(not(target_os = "macos"))]
pub(super) fn preflight() -> Result<()> {
    Err(invalid("monitor requires macOS"))
}
#[cfg(not(target_os = "macos"))]
pub(super) struct Watcher;
#[cfg(not(target_os = "macos"))]
impl Watcher {
    pub fn new(_: u32, _: &Path, _: &Path, _: &Path, _: &Path) -> Result<Self> {
        preflight()?;
        Ok(Self)
    }
    pub fn poll(&mut self) -> std::result::Result<bool, &'static str> {
        Err("monitor requires macOS")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn policy() -> Policy {
        Policy {
            executable: PathBuf::from("/Applications/Visual Studio Code.app/Contents/MacOS/Code"),
            workspace: PathBuf::from("/example/home/project"),
            session: PathBuf::from("/example/session"),
            home: PathBuf::from("/example/home"),
        }
    }
    #[test]
    fn monitoring_flags_execution_and_sockets_without_using_command_arguments() {
        let p = policy();
        assert!(
            p.check(&Observation::Executable(p.executable.clone()))
                .is_ok()
        );
        assert!(
            p.check(&Observation::Executable(PathBuf::from("/bin/sh")))
                .is_err()
        );
        assert!(
            p.check(&Observation::Executable(PathBuf::from(
                "/Applications/Visual Studio Code.app/Contents/Resources/unexpected"
            )))
            .is_err()
        );
        assert!(p.check(&Observation::IpSocket).is_ok());
    }
    #[test]
    fn open_home_paths_are_compared_by_components() {
        let p = policy();
        for path in [
            "/example/home/project/file",
            "/example/session/file",
            "/System/Library/example",
        ] {
            assert!(p.check(&Observation::File(path.into())).is_ok());
        }
        for path in [
            "/example/home/private/example",
            "/example/home/project-other/file",
        ] {
            assert!(p.check(&Observation::File(path.into())).is_err());
        }
    }
}

#[cfg(all(test, target_os = "macos"))]
mod native_tests {
    use super::*;
    use std::{
        fs::File,
        net::{TcpListener, TcpStream},
        os::{fd::AsRawFd, unix::process::CommandExt},
        process::{Command, Stdio},
    };
    fn observe_descriptor(
        fd: i32,
        workspace: &Path,
        session: &Path,
        home: &Path,
    ) -> std::result::Result<bool, &'static str> {
        let mut command = Command::new("/bin/sleep");
        command
            .arg("5")
            .process_group(0)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        unsafe {
            command.pre_exec(move || {
                let flags = libc::fcntl(fd, libc::F_GETFD);
                if flags < 0 || libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let mut app = crate::code::OwnedApplication {
            child: command.spawn().unwrap(),
            finished: false,
        };
        let mut watcher = Watcher::new(
            app.child.id(),
            Path::new("/bin/sleep"),
            workspace,
            session,
            home,
        )
        .unwrap();
        let result = watcher.poll();
        app.stop().unwrap();
        result
    }
    #[test]
    #[ignore = "requires native macOS process inspection"]
    fn native_observations_detect_dummy_home_files_and_loopback_sockets() {
        let session = crate::session::Session::create().unwrap();
        let root = session.root();
        std::fs::write(root.join("home/example"), "synthetic example").unwrap();
        let file = File::open(root.join("home/example")).unwrap();
        assert!(
            observe_descriptor(
                file.as_raw_fd(),
                &root.join("work"),
                &root.join("tmp"),
                &root.join("home")
            )
            .unwrap_err()
            .contains("open file")
        );
        assert!(
            observe_descriptor(
                file.as_raw_fd(),
                &root.join("home"),
                &root.join("tmp"),
                &root.join("home")
            )
            .is_ok()
        );
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let stream = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        assert!(
            observe_descriptor(
                stream.as_raw_fd(),
                &root.join("work"),
                root,
                &root.join("home")
            )
            .unwrap()
        );
    }
}
