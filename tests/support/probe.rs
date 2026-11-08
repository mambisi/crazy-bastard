//! Harmless probes, built only for explicit platform integration tests.
use std::{
    fs, io,
    net::{SocketAddr, TcpStream},
    os::unix::net::UnixStream,
    time::Duration,
};
#[cfg(feature = "review")]
mod review_probe;

fn outcome<T>(result: io::Result<T>) {
    match result {
        Ok(_) => println!("allowed"),
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => println!("denied"),
        Err(error) => println!("other-error:{:?}", error.kind()),
    }
}
fn main() {
    let args: Vec<_> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        #[cfg(feature = "review")]
        Some("run" | "exec") => review_probe::run(&args),
        Some("read") => outcome(fs::read(&args[1])),
        Some("write") => outcome(fs::write(&args[1], b"dummy fixture")),
        Some("tcp") => {
            let address: SocketAddr = args[1].parse().unwrap();
            outcome(TcpStream::connect_timeout(&address, Duration::from_secs(1)));
        }
        Some("unix") => outcome(UnixStream::connect(&args[1])),
        Some("environment") => println!(
            "{}",
            if std::env::var_os("CB_TEST_FIXTURE").is_none() {
                "absent"
            } else {
                "present"
            }
        ),
        Some("fd") => {
            let fd: i32 = args[1].parse().unwrap();
            let mut buffer = [0u8; 1];
            let result = unsafe { libc::read(fd, buffer.as_mut_ptr().cast(), 1) };
            if result < 0 && io::Error::last_os_error().raw_os_error() == Some(libc::EBADF) {
                println!("closed");
            } else {
                println!("inherited");
            }
        }
        Some("fork") => {
            // A successful test child exits immediately and touches no files.
            let pid = unsafe { libc::fork() };
            if pid < 0 {
                outcome::<()>(Err(io::Error::last_os_error()));
            } else if pid == 0 {
                unsafe {
                    libc::_exit(0);
                }
            } else {
                unsafe {
                    libc::waitpid(pid, std::ptr::null_mut(), 0);
                }
                println!("allowed");
            }
        }
        Some("spawn") => {
            let path = std::ffi::CString::new("/usr/bin/true").unwrap();
            let argv = [path.as_ptr().cast_mut(), std::ptr::null_mut()];
            let env = [std::ptr::null_mut()];
            let mut pid = 0;
            let code = unsafe {
                libc::posix_spawn(
                    &mut pid,
                    path.as_ptr(),
                    std::ptr::null(),
                    std::ptr::null(),
                    argv.as_ptr(),
                    env.as_ptr(),
                )
            };
            if code == 0 {
                unsafe {
                    libc::waitpid(pid, std::ptr::null_mut(), 0);
                }
                println!("allowed");
            } else {
                outcome::<()>(Err(io::Error::from_raw_os_error(code)));
            }
        }
        Some("spin") => {
            println!("pid={}", std::process::id());
            let start = std::time::Instant::now();
            while start.elapsed() < Duration::from_secs(5) {
                std::hint::spin_loop();
            }
        }
        _ => std::process::exit(2),
    }
}
