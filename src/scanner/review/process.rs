//! Bounded pipes and an unreaped process-group owner. No shell or relay threads.
use crate::{Result, invalid};
use std::{
    io::{self, Read, Write},
    os::{fd::AsRawFd, unix::process::CommandExt},
    process::{Child, Command, ExitStatus, Stdio},
    thread,
    time::{Duration, Instant},
};

const LIMIT: usize = 1024 * 1024;
pub(super) struct Output {
    pub status: ExitStatus,
    pub stdout: Vec<u8>,
    #[cfg(test)]
    pub stderr: Vec<u8>,
}
struct Owned {
    child: Child,
    reaped: bool,
}
impl Owned {
    fn exited(&self) -> Result<bool> {
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        if unsafe {
            libc::waitid(
                libc::P_PID,
                self.child.id(),
                &mut info,
                libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
            )
        } != 0
        {
            return Err(io::Error::last_os_error().into());
        }
        Ok(unsafe { info.si_pid() } != 0)
    }
    fn finish(&mut self) -> Result<ExitStatus> {
        // This root is still unreaped, so its group ID cannot have been reused.
        unsafe {
            libc::kill(-(self.child.id() as i32), libc::SIGKILL);
        }
        let status = self.child.wait()?;
        self.reaped = true;
        Ok(status)
    }
}
impl Drop for Owned {
    fn drop(&mut self) {
        if !self.reaped {
            let _ = self.finish();
        }
    }
}
fn nonblocking(fd: i32) -> Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(io::Error::last_os_error().into());
    }
    Ok(())
}
fn drain(reader: &mut impl Read, bytes: &mut Vec<u8>) -> Result<bool> {
    let mut buffer = [0; 8192];
    // Yield even if a child writes continuously, so the deadline remains effective.
    for _ in 0..32 {
        match reader.read(&mut buffer) {
            Ok(0) => return Ok(true),
            Ok(n) => {
                if bytes.len() + n > LIMIT {
                    return Err(invalid("review tool output exceeded 1 MiB"));
                }
                bytes.extend_from_slice(&buffer[..n]);
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Ok(false),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e.into()),
        }
    }
    Ok(false)
}
pub(super) fn capture(mut command: Command, input: &[u8], timeout: Duration) -> Result<Output> {
    command
        .process_group(0)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut owner = Owned {
        child: command.spawn()?,
        reaped: false,
    };
    let mut stdin = owner.child.stdin.take();
    let mut stdout = owner
        .child
        .stdout
        .take()
        .ok_or_else(|| invalid("missing review stdout"))?;
    let mut stderr = owner
        .child
        .stderr
        .take()
        .ok_or_else(|| invalid("missing review stderr"))?;
    nonblocking(
        stdin
            .as_ref()
            .ok_or_else(|| invalid("missing review stdin"))?
            .as_raw_fd(),
    )?;
    nonblocking(stdout.as_raw_fd())?;
    nonblocking(stderr.as_raw_fd())?;
    let mut written = 0;
    let mut out = Vec::new();
    let mut err = Vec::new();
    let deadline = Instant::now() + timeout;
    loop {
        if crate::interrupt::interrupted() {
            return Err(invalid("review interrupted"));
        }
        if Instant::now() >= deadline {
            return Err(invalid("review tool exceeded its deadline"));
        }
        if let Some(pipe) = &mut stdin {
            match pipe.write(&input[written..]) {
                Ok(n) => written += n,
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                    ) => {}
                Err(e) => return Err(e.into()),
            }
            if written == input.len() {
                stdin = None;
            }
        }
        let out_eof = drain(&mut stdout, &mut out)?;
        let err_eof = drain(&mut stderr, &mut err)?;
        if owner.exited()? {
            // Kill any retained group members before draining and reaping the root.
            let status = owner.finish()?;
            drain(&mut stdout, &mut out)?;
            drain(&mut stderr, &mut err)?;
            if written != input.len() {
                return Err(invalid("review tool did not consume the input"));
            }
            // Never print a harness diagnostic: it can include credentials or source text.
            return Ok(Output {
                status,
                stdout: out,
                #[cfg(test)]
                stderr: err,
            });
        }
        if out_eof && err_eof {
            thread::sleep(Duration::from_millis(5));
        } else {
            thread::sleep(Duration::from_millis(2));
        }
    }
}
