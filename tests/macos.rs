#![cfg(all(target_os = "macos", feature = "test-probe"))]
use crazy_bastard::session::Session;
use std::{
    fs,
    net::TcpListener,
    os::unix::net::UnixListener,
    process::{Command, Output},
    time::{Duration, Instant},
};

fn probe(operation: &str, argument: Option<&str>) -> Output {
    let mut c = Command::new(env!("CARGO_BIN_EXE_cb"));
    c.args([
        "run",
        "--experimental-seatbelt",
        "--timeout",
        "2",
        "--",
        env!("CARGO_BIN_EXE_cb-test-probe"),
        operation,
    ]);
    if let Some(argument) = argument {
        c.arg(argument);
    }
    c.env("CB_TEST_FIXTURE", "example-data").output().unwrap()
}
fn denied(operation: &str, argument: Option<&str>) {
    let output = probe(operation, argument);
    assert!(output.status.success(), "{output:?}");
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        "denied",
        "{output:?}"
    );
}

#[test]
#[ignore = "requires native macOS sandbox permissions"]
fn a_dummy_host_file_cannot_be_read_or_overwritten() {
    let host = Session::create().unwrap();
    let file = host.root().join("dummy-host-file");
    fs::write(&file, "not a credential").unwrap();
    denied("read", file.to_str());
    denied("write", file.to_str());
    assert_eq!(fs::read_to_string(&file).unwrap(), "not a credential");
}

#[test]
#[ignore = "requires native macOS sandbox permissions"]
fn tcp_and_unix_socket_connections_are_denied() {
    let tcp = TcpListener::bind("127.0.0.1:0").unwrap();
    tcp.set_nonblocking(true).unwrap();
    denied("tcp", Some(&tcp.local_addr().unwrap().to_string()));
    assert_eq!(
        tcp.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
    let host = Session::create().unwrap();
    let path = host.root().join("dummy.socket");
    let socket = UnixListener::bind(&path).unwrap();
    socket.set_nonblocking(true).unwrap();
    denied("unix", path.to_str());
    assert_eq!(
        socket.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}

#[test]
#[ignore = "requires native macOS sandbox permissions"]
fn parent_environment_variables_and_fork_are_blocked() {
    let output = probe("environment", None);
    assert!(output.status.success(), "{output:?}");
    assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), "absent");
    denied("fork", None);
    denied("spawn", None);
}

#[test]
#[ignore = "requires native macOS sandbox permissions"]
fn selected_input_is_copied_and_the_session_is_cleaned() {
    let host = Session::create().unwrap();
    let path = host.root().join("input.txt");
    fs::write(&path, "fixture\n").unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_cb"))
        .args(["run", "--experimental-seatbelt", "--input"]).arg(&path)
        .args(["--", "/bin/sh", "-c", "read -r value < \"$CB_INPUT_DIR/000-input.txt\"; printf '%s\\n%s\\n' \"$value\" \"$HOME\""])
        .output().unwrap();
    assert!(output.status.success(), "{output:?}");
    let text = String::from_utf8(output.stdout).unwrap();
    let mut lines = text.lines();
    assert_eq!(lines.next().unwrap(), "fixture");
    assert!(!std::path::Path::new(lines.next().unwrap()).exists());
    assert_eq!(fs::read_to_string(&path).unwrap(), "fixture\n");
}

#[test]
#[ignore = "requires native macOS sandbox permissions"]
fn the_wall_clock_limit_stops_the_owned_command() {
    let start = Instant::now();
    let output = probe("spin", None);
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("time limit"),
        "{output:?}"
    );
    assert!(start.elapsed() < Duration::from_secs(4));
}

#[test]
#[ignore = "requires native macOS sandbox permissions"]
fn terminating_the_launcher_stops_its_owned_command() {
    use std::io::{BufRead, BufReader};
    use std::process::Stdio;
    let mut child = Command::new(env!("CARGO_BIN_EXE_cb"))
        .args([
            "run",
            "--experimental-seatbelt",
            "--",
            env!("CARGO_BIN_EXE_cb-test-probe"),
            "spin",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut line = String::new();
    BufReader::new(child.stdout.take().unwrap())
        .read_line(&mut line)
        .unwrap();
    let pid: i32 = line.trim().strip_prefix("pid=").unwrap().parse().unwrap();
    // Both PIDs belong to processes started by this test.
    assert_eq!(unsafe { libc::kill(child.id() as i32, libc::SIGTERM) }, 0);
    let output = child.wait_with_output().unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("interrupted"));
    assert_eq!(unsafe { libc::kill(pid, 0) }, -1);
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(libc::ESRCH)
    );
}

#[test]
#[ignore = "requires native macOS sandbox permissions"]
fn inherited_host_file_descriptors_are_closed_before_exec() {
    use std::os::unix::{io::AsRawFd, process::CommandExt};
    let host = Session::create().unwrap();
    let path = host.root().join("dummy-open-file");
    fs::write(&path, "fixture").unwrap();
    let file = fs::File::open(&path).unwrap();
    let source_fd = file.as_raw_fd();
    let mut baseline = Command::new(env!("CARGO_BIN_EXE_cb-test-probe"));
    baseline.args(["fd", "42"]);
    unsafe {
        baseline.pre_exec(move || {
            if libc::dup2(source_fd, 42) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let output = baseline.output().unwrap();
    assert!(output.status.success());
    assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), "inherited");
    let mut command = Command::new(env!("CARGO_BIN_EXE_cb"));
    command.args([
        "run",
        "--experimental-seatbelt",
        "--",
        env!("CARGO_BIN_EXE_cb-test-probe"),
        "fd",
        "42",
    ]);
    unsafe {
        command.pre_exec(move || {
            if libc::dup2(source_fd, 42) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let output = command.output().unwrap();
    assert!(output.status.success(), "{output:?}");
    assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), "closed");
}

#[test]
#[ignore = "requires native macOS sandbox permissions"]
fn process_inspection_requires_permission() {
    let mut fixture = Command::new("/bin/sleep")
        .arg("5")
        .env_clear()
        .spawn()
        .unwrap();
    let pid = fixture.id().to_string();
    let baseline = Command::new("/bin/ps")
        .args(["-p", &pid, "-o", "pid="])
        .output()
        .unwrap();
    let checked = Command::new(env!("CARGO_BIN_EXE_cb"))
        .args([
            "run",
            "--experimental-seatbelt",
            "--",
            "/bin/ps",
            "-p",
            &pid,
            "-o",
            "pid=",
        ])
        .output()
        .unwrap();
    let _ = fixture.kill();
    let _ = fixture.wait();
    assert!(baseline.status.success());
    assert_eq!(String::from_utf8_lossy(&baseline.stdout).trim(), pid);
    assert!(!checked.status.success(), "{checked:?}");
    assert!(
        !String::from_utf8_lossy(&checked.stdout)
            .lines()
            .any(|line| line.trim() == pid)
    );
}
