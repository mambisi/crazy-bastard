use crazy_bastard::{cli, git, runner, sandbox};
use std::ffi::OsString;

fn main() {
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();
    let git_adapter = std::env::args_os().next().is_some_and(|path| {
        std::path::Path::new(&path)
            .file_name()
            .is_some_and(|name| name == "cb-git")
    });
    let result = if git_adapter {
        git::execute(&args)
    } else {
        match cli::parse(&args) {
            Ok(cli::Action::Help) => {
                println!("{}", cli::HELP);
                Ok(0)
            }
            Ok(cli::Action::Doctor) => {
                println!("{}", sandbox::doctor());
                Ok(0)
            }
            Ok(cli::Action::Run(options)) => runner::run(&options),
            Ok(cli::Action::Git(args)) => git::execute(&args),
            Err(error) => Err(error),
        }
    };
    match result {
        Ok(code) => std::process::exit(code),
        Err(error) => {
            eprintln!("cb: {error}");
            std::process::exit(2);
        }
    }
}
