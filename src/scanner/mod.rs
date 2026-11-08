//! Offline review of selected repository launch surfaces. This is not a safety verdict.
mod editor;
mod fs;
mod git;
pub mod json;
#[cfg(feature = "review")]
mod review;

#[cfg(feature = "review")]
#[doc(hidden)]
pub fn review_worker(language: &OsStr, rule: &OsStr) -> Result<i32> {
    review::worker(language, rule)
}

use crate::{Result, invalid};
use fs::Directory;
use json::{Value, object};
use std::{
    ffi::{OsStr, OsString},
    io::{self, Write},
    os::unix::ffi::OsStrExt,
    path::{Path, PathBuf},
};

const MAX_FILE: usize = 1024 * 1024;
const MAX_TOTAL: usize = 8 * 1024 * 1024;
const MAX_FILES: usize = 128;
const MAX_ENTRIES: usize = 2048;
const MAX_FINDINGS: usize = 256;
const SCOPE: &str = "Selected root only. Repository mode checks VS Code settings/tasks/launch and top-level code-workspace files; local .git config/config.worktree/hooks; package.json scripts and build.rs presence. Explicit git-dir or hooks mode checks only the selected metadata or hooks directory. No code, Git, build tools or network are executed. Includes, external Git metadata, nested projects and user/system configuration are not followed. This is not a CVE, dependency, secret or general source-code audit.";

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum ScanMode {
    #[default]
    Repository,
    GitDirectory,
    Hooks,
}
impl ScanMode {
    fn name(self) -> &'static str {
        match self {
            Self::Repository => "repository",
            Self::GitDirectory => "git-dir",
            Self::Hooks => "hooks",
        }
    }
}

#[derive(Debug)]
pub struct Options {
    pub directory: PathBuf,
    pub json: bool,
    pub mode: ScanMode,
    #[cfg(feature = "review")]
    review: Option<review::Options>,
}
impl Options {
    pub fn parse(args: &[OsString]) -> Result<Self> {
        let mut json = false;
        let mut positional = false;
        let mut directory = None;
        let mut mode = ScanMode::Repository;
        #[cfg(feature = "review")]
        let mut review = review::Options::default();
        let mut args = args.iter();
        while let Some(arg) = args.next() {
            #[cfg(feature = "review")]
            if !positional && review.option(arg, &mut args)? {
                continue;
            }
            #[cfg(not(feature = "review"))]
            if !positional
                && matches!(
                    arg.to_str(),
                    Some("--with" | "--ast-grep" | "--harness-bin" | "--source")
                )
            {
                return Err(invalid(
                    "source review requires cargo build --locked --features review --bin cb",
                ));
            }
            if !positional && arg == "--" {
                positional = true;
                continue;
            }
            if !positional && arg == "--json" && !json {
                json = true;
                continue;
            }
            if !positional && (arg == "--git-dir" || arg == "--hooks") {
                if mode != ScanMode::Repository {
                    return Err(invalid("choose at most one of --git-dir and --hooks"));
                }
                mode = if arg == "--git-dir" {
                    ScanMode::GitDirectory
                } else {
                    ScanMode::Hooks
                };
                continue;
            }
            if !positional && arg.as_bytes().starts_with(b"-") {
                return Err(invalid(
                    "unsupported scan option; use cb inspect [--json] [--git-dir | --hooks] [--] DIRECTORY",
                ));
            }
            if directory.replace(PathBuf::from(arg)).is_some() {
                return Err(invalid("inspect requires exactly one directory"));
            }
        }
        Ok(Self {
            directory: directory.ok_or_else(|| {
                invalid("inspect requires a directory; use cb inspect [--json] [--git-dir | --hooks] [--] DIRECTORY")
            })?,
            json,
            mode,
            #[cfg(feature = "review")]
            review: review.finish(mode)?,
        })
    }
}

#[derive(Debug)]
pub struct Finding {
    pub rule: &'static str,
    pub severity: &'static str,
    pub path: String,
    pub location: String,
    pub reason: &'static str,
}
#[derive(Debug)]
pub struct Issue {
    pub path: String,
    pub reason: &'static str,
}
#[derive(Debug, Default)]
pub struct Report {
    pub findings: Vec<Finding>,
    pub incomplete: Vec<Issue>,
    pub scanned_files: Vec<String>,
    bytes: usize,
    read_attempts: usize,
    findings_limited: bool,
    mode: ScanMode,
}
impl Report {
    pub fn exit_code(&self) -> i32 {
        if !self.incomplete.is_empty() {
            2
        } else if !self.findings.is_empty() {
            1
        } else {
            0
        }
    }
    pub fn to_json(&self) -> Value {
        object([
            ("schema_version", 1usize.into()),
            ("mode", self.mode.name().into()),
            (
                "status",
                match self.exit_code() {
                    0 => "no_findings_in_scope",
                    1 => "findings",
                    _ => "incomplete",
                }
                .into(),
            ),
            ("scope", SCOPE.into()),
            (
                "findings",
                self.findings
                    .iter()
                    .map(|f| {
                        object([
                            ("rule", f.rule.into()),
                            ("severity", f.severity.into()),
                            ("path", f.path.clone().into()),
                            ("location", f.location.clone().into()),
                            ("reason", f.reason.into()),
                        ])
                    })
                    .collect::<Vec<_>>()
                    .into(),
            ),
            (
                "incomplete",
                self.incomplete
                    .iter()
                    .map(|i| object([("path", i.path.clone().into()), ("reason", i.reason.into())]))
                    .collect::<Vec<_>>()
                    .into(),
            ),
            (
                "scanned_files",
                self.scanned_files
                    .iter()
                    .cloned()
                    .map(Value::from)
                    .collect::<Vec<_>>()
                    .into(),
            ),
            (
                "limits",
                object([
                    ("bytes_per_file", MAX_FILE.into()),
                    ("bytes_total", MAX_TOTAL.into()),
                    ("file_attempts", MAX_FILES.into()),
                    ("entries_per_directory", MAX_ENTRIES.into()),
                    ("findings", MAX_FINDINGS.into()),
                ]),
            ),
        ])
    }
    fn issue(&mut self, path: &Path, reason: &'static str) {
        // Bounded by the finding/file/entry budgets; retain one final limit notice.
        if self.incomplete.len() < MAX_FINDINGS {
            self.incomplete.push(Issue {
                path: safe_path(path),
                reason,
            });
        }
    }
    fn finding(
        &mut self,
        path: &Path,
        location: impl Into<String>,
        rule: &'static str,
        severity: &'static str,
        reason: &'static str,
    ) {
        if self.findings.len() >= MAX_FINDINGS {
            if !self.findings_limited {
                self.issue(
                    Path::new("."),
                    "Finding limit reached; additional findings were omitted.",
                );
                self.findings_limited = true;
            }
            return;
        }
        self.findings.push(Finding {
            rule,
            severity,
            path: safe_path(path),
            location: location.into(),
            reason,
        });
    }
    fn read(&mut self, directory: &Directory, name: &OsStr) -> Option<Vec<u8>> {
        let path = directory.path.join(name);
        if self.read_attempts >= MAX_FILES || self.bytes >= MAX_TOTAL {
            self.issue(&path, "Scan file or byte budget reached.");
            return None;
        }
        self.read_attempts += 1;
        let limit = MAX_FILE.min(MAX_TOTAL - self.bytes);
        match directory.read(name, limit) {
            Ok(Some(bytes)) => {
                self.bytes += bytes.len();
                self.scanned_files.push(safe_path(&path));
                Some(bytes)
            }
            Ok(None) => None,
            Err(_) => {
                // A failed read may already have consumed its allowance before detecting a change.
                // Charge the full allowance so failures cannot bypass the aggregate byte budget.
                self.bytes += limit;
                self.issue(&path, "Could not read a stable regular file within the byte limit; links, special files and unreadable inputs are refused.");
                None
            }
        }
    }
    fn child(&mut self, directory: &Directory, name: &str) -> Option<Directory> {
        match directory.directory(OsStr::new(name)) {
            Ok(child) => child,
            Err(_) => {
                self.issue(
                    &directory.path.join(name),
                    "Could not inspect a directory; links and unreadable directories are refused.",
                );
                None
            }
        }
    }
    fn entries(&mut self, directory: &Directory) -> Vec<OsString> {
        match directory.entries(MAX_ENTRIES) {
            Ok(names) => names,
            Err(_) => {
                self.issue(
                    &directory.path,
                    "Could not enumerate a stable directory within the entry limit.",
                );
                Vec::new()
            }
        }
    }
    fn document(&mut self, directory: &Directory, name: &OsStr, jsonc: bool) -> Option<Value> {
        let bytes = self.read(directory, name)?;
        match json::parse(&bytes, jsonc) {
            Ok(v) if v.is_object() => Some(v),
            _ => {
                self.issue(&directory.path.join(name), "Invalid or ambiguous JSON: expected an object without duplicate keys, within parser nesting limits.");
                None
            }
        }
    }
}

// Paths alone can contain terminal escape sequences, newlines or directional controls.
fn safe_path(path: &Path) -> String {
    let mut out = String::new();
    for c in path.as_os_str().to_string_lossy().chars() {
        if c.is_control() || matches!(c, '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}') {
            out.push_str(&format!("\\u{{{:x}}}", c as u32));
        } else {
            out.push(c);
        }
    }
    out
}

pub fn scan(path: &Path) -> Report {
    scan_mode(path, ScanMode::Repository)
}
pub fn scan_mode(path: &Path, mode: ScanMode) -> Report {
    let mut report = Report {
        mode,
        ..Report::default()
    };
    let (root, physical) = match Directory::root(path) {
        Ok(root) => root,
        Err(_) => {
            report.issue(
                Path::new("."),
                "Cannot open the selected root as a directory.",
            );
            return report;
        }
    };
    match mode {
        ScanMode::Repository => {
            editor::scan(&root, &mut report);
            git::scan(&root, &mut report);
            package_and_build(&root, &mut report);
        }
        ScanMode::GitDirectory => {
            if report.read(&root, OsStr::new("HEAD")).is_none() {
                report.issue(Path::new("HEAD"), "Explicit metadata directory has no readable HEAD file; verify the selected directory.");
            }
            git::metadata(&root, &mut report);
        }
        ScanMode::Hooks => git::hook_files(&root, &mut report),
    }
    if !root.same_root(&physical) {
        report.issue(Path::new("."), "Selected root was replaced while scanning.");
    }
    report
}
fn package_and_build(root: &Directory, report: &mut Report) {
    if let Some(package) = report.document(root, OsStr::new("package.json"), false) {
        let path = Path::new("package.json");
        if let Some(scripts) = package.get("scripts") {
            if let Some(scripts) = scripts.as_object() {
                for (name, value) in scripts {
                    if !value.is_string() {
                        report.issue(path, "Package scripts contain an unsupported value.");
                        continue;
                    }
                    if value.as_str().is_some_and(|s| !s.trim().is_empty()) {
                        let automatic = matches!(
                            name.as_str(),
                            "preinstall"
                                | "install"
                                | "postinstall"
                                | "prepare"
                                | "prepublish"
                                | "preprepare"
                                | "postprepare"
                        );
                        report.finding(path, "scripts", if automatic {"PACKAGE_LIFECYCLE"} else {"PACKAGE_SCRIPT"}, if automatic {"high"} else {"review"}, if automatic {"Package lifecycle scripts can run during installation or preparation; review before installing."} else {"Package scripts run project-supplied commands when invoked; review before use."});
                    }
                }
            } else {
                report.issue(path, "Package scripts must be an object.");
            }
        }
    }
    if report.read(root, OsStr::new("build.rs")).is_some() {
        report.finding(Path::new("build.rs"), "file", "RUST_BUILD_SCRIPT", "review", "A conventional Rust build script is present; Cargo may execute it during a build. Custom build paths and dependency build scripts are outside this scan.");
    }
}

pub fn execute(options: &Options) -> Result<i32> {
    let report = scan_mode(&options.directory, options.mode);
    #[cfg(feature = "review")]
    if let Some(review) = &options.review {
        return review::execute(options, review, report);
    }
    let stdout = io::stdout();
    let mut output = stdout.lock();
    if options.json {
        writeln!(output, "{}", report.to_json())?;
    } else {
        writeln!(
            output,
            "{} finding(s), {} incomplete item(s), {} file(s) read; mode {}.",
            report.findings.len(),
            report.incomplete.len(),
            report.scanned_files.len(),
            report.mode.name()
        )?;
        for f in &report.findings {
            writeln!(
                output,
                "[{}] {} {} ({})\n  {}",
                f.severity, f.rule, f.path, f.location, f.reason
            )?;
        }
        for i in &report.incomplete {
            writeln!(output, "[incomplete] {}: {}", i.path, i.reason)?;
        }
        writeln!(output, "{SCOPE}")?;
        if report.exit_code() == 0 {
            writeln!(
                output,
                "No findings in the checked surfaces; this does not establish that the project is safe."
            )?;
        }
    }
    Ok(report.exit_code())
}

#[cfg(test)]
mod tests;
