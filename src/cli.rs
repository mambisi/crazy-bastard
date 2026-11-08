use crate::{Result, invalid};
use std::{ffi::OsString, path::PathBuf, time::Duration};

pub const HELP: &str = "crazy-bastard (cb) 0.1.0\n\n\
Usage:\n  cb doctor\n  cb run --experimental-seatbelt [--input FILE] [--timeout SECONDS] -- COMMAND [ARG ...]\n  cb git [GIT ARG ...]\n\n\
Run uses a private home, no inherited credentials, no network or IPC services,\n\
and no subprocess creation. Only selected input files enter the session.\n\
Output controls are escaped. Sessions are removed on exit.\n\n\
Seatbelt is deprecated. This experimental single-process CLI backend is not a VM\n\
or a guarantee against kernel exploits or resource exhaustion. GUI applications\n\
and subprocesses are unsupported. There is no unsandboxed fallback.\n\n\
cb git suppresses hooks and fsmonitor on the host. It does not isolate filters,\n\
builds, credential helpers or arbitrary project code.";

#[derive(Debug)]
pub enum Action {
    Help,
    Doctor,
    Run(RunOptions),
    Git(Vec<OsString>),
}
#[derive(Debug)]
pub struct RunOptions {
    pub program: OsString,
    pub arguments: Vec<OsString>,
    pub inputs: Vec<PathBuf>,
    pub timeout: Duration,
}

pub fn parse(args: &[OsString]) -> Result<Action> {
    let Some(first) = args.first() else {
        return Ok(Action::Help);
    };
    if first == "help" || first == "--help" || first == "-h" {
        return Ok(Action::Help);
    }
    if first == "doctor" && args.len() == 1 {
        return Ok(Action::Doctor);
    }
    if first == "git" {
        return Ok(Action::Git(args[1..].to_vec()));
    }
    if first != "run" {
        return Err(invalid("unknown command; use cb --help"));
    }
    let mut experimental = false;
    let mut inputs = Vec::new();
    let mut timeout = Duration::from_secs(30);
    let mut index = 1;
    while index < args.len() {
        if args[index] == "--" {
            if !experimental {
                return Err(invalid(
                    "requires --experimental-seatbelt; no command was run",
                ));
            }
            let program = args
                .get(index + 1)
                .ok_or_else(|| invalid("missing command after --"))?
                .clone();
            return Ok(Action::Run(RunOptions {
                program,
                arguments: args[index + 2..].to_vec(),
                inputs,
                timeout,
            }));
        }
        if args[index] == "--experimental-seatbelt" {
            experimental = true;
            index += 1;
            continue;
        }
        if args[index] == "--input" {
            if inputs.len() >= 32 {
                return Err(invalid("at most 32 inputs are supported"));
            }
            inputs.push(PathBuf::from(
                args.get(index + 1)
                    .ok_or_else(|| invalid("--input requires a file"))?,
            ));
            index += 2;
            continue;
        }
        if args[index] == "--timeout" {
            let seconds: u64 = args
                .get(index + 1)
                .and_then(|v| v.to_str())
                .and_then(|v| v.parse().ok())
                .filter(|v| (1..=3600).contains(v))
                .ok_or_else(|| invalid("--timeout must be 1 through 3600 seconds"))?;
            timeout = Duration::from_secs(seconds);
            index += 2;
            continue;
        }
        return Err(invalid("unsupported run option; use -- before the command"));
    }
    Err(invalid("use -- followed by the command to launch"))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn args(v: &[&str]) -> Vec<OsString> {
        v.iter().map(OsString::from).collect()
    }
    #[test]
    fn runs_require_explicit_opt_in() {
        assert!(parse(&args(&["run", "--", "/usr/bin/true"])).is_err());
    }
    #[test]
    fn arguments_are_preserved_without_a_shell() {
        let Action::Run(o) = parse(&args(&[
            "run",
            "--experimental-seatbelt",
            "--",
            "/bin/echo",
            "$(bad)",
            "a b",
        ]))
        .unwrap() else {
            panic!()
        };
        assert_eq!(o.arguments, args(&["$(bad)", "a b"]));
    }
    #[test]
    fn deadlines_are_bounded() {
        for v in ["0", "3601", "-1", "oops"] {
            assert!(
                parse(&args(&[
                    "run",
                    "--experimental-seatbelt",
                    "--timeout",
                    v,
                    "--",
                    "/usr/bin/true"
                ]))
                .is_err()
            );
        }
    }
}
