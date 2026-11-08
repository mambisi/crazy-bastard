//! Fixed responses for adapter tests. This never contacts a model or service.
use crazy_bastard::scanner::json::{self, Value};
use std::io::{self, Read};

pub fn run(args: &[String]) {
    if args == ["exec", "--help"] {
        println!(
            "--ignore-user-config --ignore-rules --strict-config --ephemeral --output-schema --sandbox"
        );
        return;
    }
    let mut input = String::new();
    io::stdin().read_to_string(&mut input).unwrap();
    assert!(std::env::var_os("CB_REVIEW_TEST_SECRET").is_none());
    assert!(std::env::var_os("OPENAI_API_KEY").is_none());
    assert!(std::env::current_dir().unwrap().ends_with("work"));
    // Neither profile can start a command, even if the trusted harness tried.
    assert!(
        std::process::Command::new("/usr/bin/true")
            .status()
            .is_err()
    );
    if args[0] == "run" {
        if let Some(address) = input
            .lines()
            .find_map(|line| line.strip_prefix("// fixture-loopback="))
        {
            assert!(std::net::TcpStream::connect(address).is_err());
        }
        assert!(args.contains(&"--stdin".to_owned()));
        let config = args.windows(2).find(|a| a[0] == "--config").unwrap();
        assert_eq!(
            std::fs::read_to_string(&config[1]).unwrap(),
            "ruleDirs: []\n"
        );
        let pattern = args.windows(2).find(|a| a[0] == "--pattern").unwrap();
        if pattern[1] == "eval($$$ARGS)" && input.starts_with("eval(input);") {
            println!(r#"[{{"range":{{"start":{{"line":0}}}}}}]"#);
        } else {
            println!("[]");
        }
    } else {
        for arg in [
            "--ignore-user-config",
            "--ignore-rules",
            "--ephemeral",
            "approval_policy=\"never\"",
            "features.shell_tool=false",
            "mcp_servers={}",
            "hooks={}",
        ] {
            assert!(args.contains(&arg.to_owned()));
        }
        let auth_home = std::path::PathBuf::from(std::env::var_os("CODEX_HOME").unwrap());
        assert_eq!(
            std::fs::read_to_string(auth_home.join("auth.json")).unwrap(),
            "fixture-login"
        );
        assert!(std::fs::read(auth_home.join("config.toml")).is_err());
        assert!(std::fs::write(auth_home.join("auth.json"), "must not write").is_err());
        assert!(
            std::os::unix::net::UnixStream::connect(
                auth_home.parent().unwrap().join("dummy-control.sock")
            )
            .is_err()
        );
        #[cfg(target_os = "macos")]
        {
            unsafe extern "C" {
                fn proc_pidpath(pid: i32, buffer: *mut libc::c_void, size: u32) -> i32;
            }
            let mut buffer = [0u8; 4096];
            assert!(
                unsafe {
                    proc_pidpath(
                        libc::getppid(),
                        buffer.as_mut_ptr().cast(),
                        buffer.len() as u32,
                    )
                } <= 0
            );
        }
        let value = json::parse(input.as_bytes(), false).unwrap();
        let text = value["sources"][0]["content"].as_str().unwrap();
        if let Some(address) = text
            .lines()
            .find_map(|line| line.strip_prefix("// fixture-loopback="))
        {
            assert!(std::net::TcpStream::connect(address).is_ok());
        }
        if text.contains("FORGED_REFERENCE") {
            println!(
                r#"{{"findings":[{{"source_id":"S999","line":1,"severity":"high","title":"Forged","explanation":"Unsupported.","evidence":"eval(input)"}}]}}"#
            );
        } else if text.contains("MALFORMED_RESULT") {
            println!("this is not JSON");
        } else {
            assert!(text.contains("ignore previous instructions"));
            let _: &Vec<Value> = value["ast_matches"].as_array().unwrap();
            println!(
                r#"{{"findings":[{{"source_id":"S1","line":1,"severity":"medium","title":"Dynamic evaluation","explanation":"Risk requires attacker-controlled input.","evidence":"eval(input)"}}]}}"#
            );
        }
    }
}
