use crazy_bastard::{capabilities, cli, git, runner};
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
            #[cfg(feature = "review")]
            Ok(cli::Action::AstWorker(language, rule)) => {
                crazy_bastard::scanner::review_worker(&language, &rule)
            }
            Ok(cli::Action::Help(topic)) => {
                println!("{}", cli::help(topic));
                Ok(0)
            }
            Ok(cli::Action::Doctor) => {
                println!("{}", capabilities::doctor());
                Ok(0)
            }
            Ok(cli::Action::Run(options)) => runner::run(&options),
            Ok(cli::Action::Git(args)) => git::execute(&args),
            Ok(cli::Action::Code(options)) => crazy_bastard::code::execute(&options),
            #[cfg(feature = "scanner")]
            Ok(cli::Action::Inspect(options)) => crazy_bastard::scanner::execute(&options),
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
