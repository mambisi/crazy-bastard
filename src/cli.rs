use crate::{Result, invalid};
use std::{ffi::OsString, path::PathBuf, time::Duration};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HelpTopic {
    Overview,
    Doctor,
    Inspect,
    Run,
    Code,
    Host,
    HostCode,
}

pub fn help(topic: HelpTopic) -> String {
    let text = match topic {
        HelpTopic::Overview => {
            "crazy-bastard (cb) 0.1.0\n\nReview unfamiliar repositories and choose an explicit execution boundary.\n\nCommands:\n  cb doctor                         Report shipped capabilities without launching tools\n  cb inspect DIRECTORY              Static review (requires scanner feature)\n  cb run --experimental-seatbelt ... Single-process macOS isolation prototype\n  cb code [DIRECTORY]                Require an isolated editor workspace\n  cb host code [--monitor] [DIR]      Explicit host review; no OS isolation\n  cb host git [GIT ARG ...]          Host Git with hook suppression\n\nUse cb COMMAND --help for details.\n\nIsolated editor workspaces and approval TUI are not implemented. cb code refuses\nto launch until a verified runtime adapter exists; it never falls back to host\nreview. cb-git still dispatches directly to the host Git hook policy.\nLegacy cb scan is an alias for cb inspect; cb git moved to cb host git."
        }
        HelpTopic::Doctor => {
            "Usage: cb doctor\n\nReports compile-time features and shipped backend status. It does not execute\nGit, editors, runtime CLIs or project code, and does not certify the host."
        }
        HelpTopic::Inspect => {
            "Usage: cb inspect [--json] [--git-dir | --hooks] [--] DIRECTORY\n       cb inspect DIRECTORY --source src/app.js\n       cb inspect DIRECTORY --source src/app.js --with codex --harness-bin /absolute/native/codex\n\nPlain inspection is static: no commands or network. Requires --features scanner.\nOptional source review requires --features review and macOS Seatbelt.\nSelect up to 16 files explicitly with --source. The locked ast-grep-core 0.51.1\nparser and selected grammars are bundled, run in a confined CB worker process.\nNo ast-grep installation is needed. --ast-grep /absolute/native/binary is an\noptional external override whose version is outside Cargo.lock.\n--with codex adds advisory review using the CLI's existing private login in place.\nNo API key is required. Selected source can reach OpenAI and consume paid usage.\nThe Codex binary must be a trusted native installation outside the repository.\nPrompt injection cannot be guaranteed prevented. Other harnesses are not integrated.\nSee docs/review.md for coverage and authentication limits.\nExit 0: no findings in scope; 1: findings; 2: incomplete or invalid invocation.\nThis is not a dependency-CVE or whole-source audit. cb scan is an alias."
        }
        HelpTopic::Run => {
            "Usage: cb run --experimental-seatbelt [--input FILE] [--timeout SECONDS] -- COMMAND [ARG ...]\n\nExperimental macOS single-process containment: private home, explicit regular-file\ninputs, replaced environment, no network/Mach services or subprocess creation.\nDefault timeout: 30 seconds; range: 1..3600. Output is bounded and controls escaped.\nSeatbelt is deprecated. This is not a VM or a full development environment.\nThere is no unsandboxed fallback. GUI programs and package workflows are unsupported."
        }
        HelpTopic::Code => {
            "Usage: cb code [--] [DIRECTORY]\n\nRequires a verified isolated editor workspace. The adapter is not integrated yet;\nthis command refuses launch before opening the target or starting a host editor.\n--vm is accepted as a legacy isolation request. There is no host fallback.\nFor the separate host-review mode, explicitly use cb host code DIRECTORY.\nHost review leaves original files editable and does not isolate networking."
        }
        HelpTopic::Host => {
            "Usage:\n  cb host code [--monitor] [--] [DIRECTORY]\n  cb host git [GIT ARG ...]\n\nThese commands run on the host. The editor uses a fresh profile and Restricted\nMode defaults; the Git adapter suppresses hooks. Neither provides OS isolation."
        }
        HelpTopic::HostCode => {
            "Usage: cb host code [--monitor] [--] [DIRECTORY]\n\nOpens macOS VS Code with a private profile/home and disabled installed extensions.\nThe original folder is editable. Keep it in Restricted Mode. Quit the dedicated\nCode instance to finish; Ctrl-C stops only its owned process group.\n\n--monitor polls every 250 ms. It reports network activity and stops on selected\nexecution/file violations or observation failure. Activity may already have\noccurred; this is not network blocking or pre-execution approval.\n--vm is refused here; use cb code for isolation-required launch."
        }
    };
    let mut text = text.to_owned();
    if topic == HelpTopic::Overview {
        text.push_str(if cfg!(feature = "scanner") {
            "\nScanner feature: enabled."
        } else {
            "\nScanner feature: disabled; build with --features scanner to enable inspection."
        });
    }
    text
}

#[derive(Debug)]
pub enum Action {
    #[cfg(feature = "review")]
    AstWorker(OsString, OsString),
    Help(HelpTopic),
    Doctor,
    Run(RunOptions),
    Git(Vec<OsString>),
    Code(crate::code::Options),
    #[cfg(feature = "scanner")]
    Inspect(crate::scanner::Options),
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
        return Ok(Action::Help(HelpTopic::Overview));
    };
    if first == "help" || first == "--help" || first == "-h" {
        if args.len() != 1 {
            return Err(invalid("use cb COMMAND --help for command-specific help"));
        }
        return Ok(Action::Help(HelpTopic::Overview));
    }
    let rest = &args[1..];
    #[cfg(feature = "review")]
    if first == "__cb_ast_worker" {
        return match rest {
            [language, rule] => Ok(Action::AstWorker(language.clone(), rule.clone())),
            _ => Err(invalid("invalid internal AST worker request")),
        };
    }
    let wants_help = rest.len() == 1 && (rest[0] == "--help" || rest[0] == "-h");
    if first == "doctor" {
        return if wants_help {
            Ok(Action::Help(HelpTopic::Doctor))
        } else if rest.is_empty() {
            Ok(Action::Doctor)
        } else {
            Err(invalid("doctor takes no arguments"))
        };
    }
    if first == "host" {
        if rest.is_empty() || wants_help {
            return Ok(Action::Help(HelpTopic::Host));
        }
        if rest[0] == "git" {
            return Ok(Action::Git(rest[1..].to_vec()));
        }
        if rest[0] == "code" {
            if rest.len() == 2 && (rest[1] == "--help" || rest[1] == "-h") {
                return Ok(Action::Help(HelpTopic::HostCode));
            }
            return crate::code::Options::parse_host(&rest[1..]).map(Action::Code);
        }
        return Err(invalid("unknown host command; use cb host --help"));
    }
    if first == "git" {
        return Err(invalid(
            "host Git moved to cb host git; cb-git remains supported. No Git command was run",
        ));
    }
    if first == "code" {
        if wants_help {
            return Ok(Action::Help(HelpTopic::Code));
        }
        return crate::code::Options::parse(rest).map(Action::Code);
    }
    if first == "inspect" || first == "scan" {
        if wants_help {
            return Ok(Action::Help(HelpTopic::Inspect));
        }
        #[cfg(feature = "scanner")]
        {
            return crate::scanner::Options::parse(rest).map(Action::Inspect);
        }
        #[cfg(not(feature = "scanner"))]
        {
            return Err(invalid(
                "scanner feature is disabled; rebuild with cargo build --locked --features scanner --bin cb",
            ));
        }
    }
    if first != "run" {
        return Err(invalid("unknown command; use cb --help"));
    }
    if wants_help {
        return Ok(Action::Help(HelpTopic::Run));
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
    #[test]
    fn host_git_preserves_literal_arguments_and_the_legacy_spelling_does_not_execute() {
        let Action::Git(rest) = parse(&args(&["host", "git", "-C", "a b", "status"])).unwrap()
        else {
            panic!()
        };
        assert_eq!(rest, args(&["-C", "a b", "status"]));
        assert!(parse(&args(&["git", "status"])).is_err());
    }
    #[test]
    fn command_help_is_local_and_run_arguments_are_not_reinterpreted() {
        assert!(matches!(
            parse(&args(&["host", "code", "--help"])).unwrap(),
            Action::Help(HelpTopic::HostCode)
        ));
        let Action::Run(options) = parse(&args(&[
            "run",
            "--experimental-seatbelt",
            "--",
            "/bin/echo",
            "--help",
        ]))
        .unwrap() else {
            panic!()
        };
        assert_eq!(options.arguments, args(&["--help"]));
    }
}
