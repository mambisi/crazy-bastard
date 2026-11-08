use crate::{Result, cli::RunOptions, invalid, output, sandbox, session::Session};
use std::{
    ffi::OsStr,
    io,
    os::unix::{
        fs::PermissionsExt,
        process::{CommandExt, ExitStatusExt},
    },
    path::{Path, PathBuf},
    process::{Child, Command, ExitStatus, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

struct OwnedChild {
    child: Child,
    finished: bool,
}
impl Drop for OwnedChild {
    fn drop(&mut self) {
        if !self.finished {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}
fn wait(child: &mut OwnedChild, timeout: Duration, failed: &AtomicBool) -> Result<ExitStatus> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child.child.try_wait()? {
            child.finished = true;
            return Ok(status);
        }
        if crate::interrupt::interrupted() {
            return Err(invalid("interrupted; command stopped"));
        }
        if failed.load(Ordering::Relaxed) {
            return Err(invalid(
                "output failed or exceeded the limit; command stopped",
            ));
        }
        if Instant::now() >= deadline {
            return Err(invalid("time limit reached; command stopped"));
        }
        thread::sleep(Duration::from_millis(10));
    }
}
fn command(root: &Path, executable: &Path, arguments: &[std::ffi::OsString]) -> Result<Command> {
    // Snapshot inherited descriptors before spawn creates its own CLOEXEC pipes.
    // This CLI has not started relay threads yet. No extra host file descriptor
    // is an intentional capability of the launched command.
    let inherited: Vec<i32> = std::fs::read_dir("/dev/fd")?
        .map(|entry| entry.map(|entry| entry.file_name()))
        .collect::<std::io::Result<Vec<_>>>()?
        .iter()
        .filter_map(|name| name.to_str()?.parse().ok())
        .filter(|fd| *fd >= 3)
        .collect();
    let mut c = Command::new("/usr/bin/sandbox-exec");
    let mut parameter = std::ffi::OsString::from("CB_ROOT=");
    parameter.push(root);
    c.arg("-D")
        .arg(parameter)
        .arg("-p")
        .arg(sandbox::PROFILE)
        .arg(executable)
        .args(arguments)
        .env_clear()
        .envs(sandbox::environment(root))
        .current_dir(root.join("work"))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // Only async-signal-safe libc operations run between fork and exec.
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
            for (resource, soft, hard) in [
                (libc::RLIMIT_CORE, 0, 0),
                (libc::RLIMIT_FSIZE, 64 * 1024 * 1024, 64 * 1024 * 1024),
                (libc::RLIMIT_NOFILE, 128, 128),
            ] {
                let limit = libc::rlimit {
                    rlim_cur: soft,
                    rlim_max: hard,
                };
                if libc::setrlimit(resource, &limit) != 0 {
                    return Err(io::Error::last_os_error());
                }
            }
            Ok(())
        });
    }
    Ok(c)
}
fn resolve_program(program: &OsStr) -> Result<PathBuf> {
    let path = Path::new(program);
    let candidate = if path.components().count() > 1 || path.is_absolute() {
        path.to_owned()
    } else {
        ["/usr/bin", "/bin", "/usr/sbin", "/sbin"]
            .iter()
            .map(|base| Path::new(base).join(path))
            .find(|p| p.is_file())
            .ok_or_else(|| invalid("command not found in system paths; provide an explicit path"))?
    };
    let resolved = candidate.canonicalize()?;
    if resolved
        .components()
        .any(|p| p.as_os_str().to_string_lossy().ends_with(".app"))
    {
        return Err(invalid(
            "GUI bundles need a future VM backend; no application was launched",
        ));
    }
    if !resolved.is_file() || resolved.metadata()?.permissions().mode() & 0o111 == 0 {
        return Err(invalid("command must be an executable regular file"));
    }
    Ok(resolved)
}
pub fn run(options: &RunOptions) -> Result<i32> {
    sandbox::require_backend()?;
    let _signals = crate::interrupt::Guard::install()?;
    let source = resolve_program(&options.program)?;
    let session = Session::create()?;
    let mut total = 0;
    for (index, input) in options.inputs.iter().enumerate() {
        total += session.copy_input(input, index)?.metadata()?.len();
        if total > crate::session::MAX_INPUT_BYTES {
            return Err(invalid("combined inputs exceed 64 MiB"));
        }
    }
    let executable = if ["/usr/bin", "/bin", "/usr/sbin", "/sbin", "/usr/libexec"]
        .iter()
        .any(|base| source.starts_with(base))
    {
        source
    } else {
        session.copy_program(&source)?
    };
    let mut probe = OwnedChild {
        child: command(session.root(), Path::new("/usr/bin/true"), &[])?.spawn()?,
        finished: false,
    };
    if !wait(&mut probe, Duration::from_secs(5), &AtomicBool::new(false))?.success() {
        return Err(invalid(
            "macOS rejected the sandbox probe; no requested command was run",
        ));
    }
    let failed = Arc::new(AtomicBool::new(false));
    let mut child = OwnedChild {
        child: command(session.root(), &executable, &options.arguments)?.spawn()?,
        finished: false,
    };
    let stdout = child
        .child
        .stdout
        .take()
        .ok_or_else(|| invalid("missing stdout pipe"))?;
    let stderr = child
        .child
        .stderr
        .take()
        .ok_or_else(|| invalid("missing stderr pipe"))?;
    let flag = Arc::clone(&failed);
    let out = thread::spawn(move || {
        if output::relay(stdout, io::stdout().lock()).is_err() {
            flag.store(true, Ordering::Relaxed);
        }
    });
    let flag = Arc::clone(&failed);
    let err = thread::spawn(move || {
        if output::relay(stderr, io::stderr().lock()).is_err() {
            flag.store(true, Ordering::Relaxed);
        }
    });
    let result = wait(&mut child, options.timeout, &failed);
    // The policy denies fork, so no descendants may retain these output pipes.
    if result.is_err() {
        let _ = child.child.kill();
        let _ = child.child.wait();
        child.finished = true;
    }
    out.join().map_err(|_| invalid("stdout relay failed"))?;
    err.join().map_err(|_| invalid("stderr relay failed"))?;
    let status = result?;
    if failed.load(Ordering::Relaxed) {
        return Err(invalid("output failed or exceeded the limit"));
    }
    session.close()?;
    Ok(status
        .code()
        .unwrap_or_else(|| 128 + status.signal().unwrap_or(1)))
}
