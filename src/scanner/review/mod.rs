//! Explicit source selection followed by confined AST and optional advisory review.
mod ast_worker;
mod harness;
mod process;

pub(super) fn worker(language: &OsStr, rule: &OsStr) -> Result<i32> {
    ast_worker::execute(language, rule)
}

use super::{
    Directory, Options as InspectOptions, Report, ScanMode,
    json::{self, Value, object},
    safe_path,
};
use crate::{Result, invalid, session::Session};
use std::{
    ffi::{OsStr, OsString},
    io::{self, Write},
    path::{Component, Path, PathBuf},
    time::{Duration, Instant},
};

const MAX_SOURCES: usize = 16;
const MAX_SOURCE: usize = 64 * 1024;
const MAX_BYTES: usize = 256 * 1024;
const MAX_RESULTS: usize = 64;
const LIMITATIONS: &str = "Only explicitly selected source snapshots were reviewed. AST matches are review surfaces, not confirmed vulnerabilities. Model findings are untrusted advice; prompt injection and false negatives remain possible. No fixes or permissions are granted. This is not a CVE, dependency, secret, dataflow or whole-repository audit.";

#[derive(Debug, Default)]
pub(super) struct Options {
    with: Option<String>,
    ast_grep: Option<PathBuf>,
    harness_bin: Option<PathBuf>,
    sources: Vec<PathBuf>,
}
impl Options {
    pub fn option<'a>(
        &mut self,
        arg: &OsStr,
        args: &mut impl Iterator<Item = &'a OsString>,
    ) -> Result<bool> {
        let Some(name) = arg.to_str() else {
            return Ok(false);
        };
        if !matches!(name, "--with" | "--ast-grep" | "--harness-bin" | "--source") {
            return Ok(false);
        }
        let value = args
            .next()
            .ok_or_else(|| invalid("review option needs a value"))?;
        match name {
            "--with" => {
                if value != "codex" || self.with.replace("codex".to_owned()).is_some() {
                    return Err(invalid(
                        "choose --with codex once; other harness adapters are not integrated",
                    ));
                }
            }
            "--ast-grep" => {
                if self.ast_grep.replace(PathBuf::from(value)).is_some() {
                    return Err(invalid("duplicate --ast-grep"));
                }
            }
            "--harness-bin" => {
                if self.harness_bin.replace(PathBuf::from(value)).is_some() {
                    return Err(invalid("duplicate --harness-bin"));
                }
            }
            "--source" => {
                let path = PathBuf::from(value);
                source_language(&path)?;
                if self.sources.len() == MAX_SOURCES || self.sources.contains(&path) {
                    return Err(invalid("select at most 16 distinct source files"));
                }
                self.sources.push(path);
            }
            _ => unreachable!(),
        }
        Ok(true)
    }
    pub fn finish(self, mode: ScanMode) -> Result<Option<Self>> {
        if self.with.is_none()
            && self.ast_grep.is_none()
            && self.harness_bin.is_none()
            && self.sources.is_empty()
        {
            return Ok(None);
        }
        if mode != ScanMode::Repository {
            return Err(invalid(
                "source review cannot be combined with --git-dir or --hooks",
            ));
        }
        if self.sources.is_empty() {
            return Err(invalid(
                "source review requires at least one --source relative/file; the locked built-in AST worker is used by default",
            ));
        }
        if self.with.is_some() != self.harness_bin.is_some() {
            return Err(invalid(
                "--with codex and --harness-bin /absolute/native/codex must be supplied together",
            ));
        }
        for path in self.ast_grep.iter().chain(self.harness_bin.iter()) {
            if !path.is_absolute() {
                return Err(invalid(
                    "review executables require explicit absolute paths; PATH is never searched",
                ));
            }
        }
        Ok(Some(self))
    }
}

struct Source {
    id: String,
    path: String,
    language: &'static str,
    text: String,
}
impl Source {
    fn lines(&self) -> usize {
        self.text.lines().count().max(1)
    }
    fn evidence(&self, line: usize) -> Option<&str> {
        self.text.lines().nth(line.checked_sub(1)?)
    }
    fn packet(&self) -> Value {
        object([
            ("source_id", self.id.clone().into()),
            ("path", self.path.clone().into()),
            ("language", self.language.into()),
            ("content", self.text.clone().into()),
        ])
    }
}
fn source_language(path: &Path) -> Result<&'static str> {
    if path.as_os_str().len() > 512
        || path.components().any(|c| match c {
            Component::Normal(s) => s.to_str().is_none_or(|s| {
                s.starts_with('.')
                    || matches!(s, "node_modules" | "target" | "vendor" | "dist")
                    || s.chars().any(char::is_control)
            }),
            _ => true,
        })
    {
        return Err(invalid(
            "source paths must be normal relative paths, without hidden, generated or vendor components",
        ));
    }
    match path.extension().and_then(OsStr::to_str) {
        Some("js" | "mjs" | "cjs" | "jsx") => Ok("JavaScript"),
        Some("ts" | "mts" | "cts") => Ok("TypeScript"),
        Some("tsx") => Ok("Tsx"),
        Some("py") => Ok("Python"),
        Some("rs") => Ok("Rust"),
        _ => Err(invalid(
            "source review supports JavaScript, TypeScript, TSX, Python and Rust files",
        )),
    }
}
fn collect(root: &Directory, paths: &[PathBuf]) -> Result<Vec<Source>> {
    let mut sources = Vec::new();
    let mut total = 0;
    for path in paths {
        let language = source_language(path)?;
        let mut current = None;
        let mut parts = path.components().peekable();
        while let Some(Component::Normal(name)) = parts.next() {
            let parent = current.as_ref().unwrap_or(root);
            if parts.peek().is_some() {
                current = Some(
                    parent
                        .directory(name)?
                        .ok_or_else(|| invalid("selected source directory is missing"))?,
                );
            } else {
                let bytes = parent
                    .read(name, MAX_SOURCE.min(MAX_BYTES - total))?
                    .ok_or_else(|| invalid("selected source file is missing"))?;
                total += bytes.len();
                let text = String::from_utf8(bytes)
                    .map_err(|_| invalid("selected sources must be UTF-8"))?;
                if text.contains('\0') {
                    return Err(invalid("binary source input is not supported"));
                }
                sources.push(Source {
                    id: format!("S{}", sources.len() + 1),
                    path: safe_path(path),
                    language,
                    text,
                });
            }
        }
    }
    Ok(sources)
}

fn source_root(physical: &Path) -> Result<()> {
    // Runtime and certificate paths are intentionally readable by these tools.
    // Do not call that an isolated checkout when a selected root overlaps them.
    for allowed in [
        "/System",
        "/System/Library",
        "/System/Volumes/Preboot/Cryptexes/OS",
        "/private/preboot/Cryptexes/OS",
        "/Library/Apple",
        "/usr/lib",
        "/usr/libexec",
        "/usr/share",
        "/usr/bin",
        "/usr/sbin",
        "/bin",
        "/sbin",
        "/dev",
        "/private/etc/ssl",
    ] {
        let allowed = Path::new(allowed);
        if physical.starts_with(allowed) || allowed.starts_with(physical) {
            return Err(invalid(
                "selected source root overlaps a system path already readable by the tool policy; choose a separate project directory",
            ));
        }
    }
    Ok(())
}

#[derive(Clone, Copy)]
struct Rule {
    id: &'static str,
    pattern: &'static str,
}
fn rules(language: &str) -> &'static [Rule] {
    match language {
        "JavaScript" | "TypeScript" | "Tsx" => &[
            Rule {
                id: "JS_EVAL",
                pattern: "eval($$$ARGS)",
            },
            Rule {
                id: "JS_FUNCTION",
                pattern: "new Function($$$ARGS)",
            },
            Rule {
                id: "JS_CHILD_EXEC",
                pattern: "$OBJECT.exec($$$ARGS)",
            },
            Rule {
                id: "JS_CHILD_SPAWN",
                pattern: "$OBJECT.spawn($$$ARGS)",
            },
        ],
        "Python" => &[
            Rule {
                id: "PY_EVAL",
                pattern: "eval($$$ARGS)",
            },
            Rule {
                id: "PY_EXEC",
                pattern: "exec($$$ARGS)",
            },
            Rule {
                id: "PY_PROCESS",
                pattern: "subprocess.$METHOD($$$ARGS)",
            },
        ],
        "Rust" => &[
            Rule {
                id: "RS_COMMAND",
                pattern: "Command::new($$$ARGS)",
            },
            Rule {
                id: "RS_COMMAND_QUALIFIED",
                pattern: "std::process::Command::new($$$ARGS)",
            },
        ],
        _ => &[],
    }
}

fn native_program(path: &Path, repository: &Path) -> Result<PathBuf> {
    use std::{io::Read, os::unix::fs::PermissionsExt};
    let physical = path.canonicalize()?;
    if physical.starts_with(repository) {
        return Err(invalid(
            "review executables must be trusted installations outside the selected repository",
        ));
    }
    let mut file = crate::session::open_regular_no_symlinks(&physical)?;
    if file.metadata()?.permissions().mode() & 0o111 == 0 {
        return Err(invalid("review tool is not executable"));
    }
    let mut magic = [0; 4];
    file.read_exact(&mut magic)?;
    // Only native Mach-O binaries. In particular, never run a node/shell launcher.
    if !matches!(
        magic,
        [0xcf, 0xfa, 0xed, 0xfe]
            | [0xfe, 0xed, 0xfa, 0xcf]
            | [0xca, 0xfe, 0xba, 0xbe]
            | [0xbe, 0xba, 0xfe, 0xca]
            | [0xca, 0xfe, 0xba, 0xbf]
    ) {
        return Err(invalid(
            "review tools must be native macOS binaries; point to the native CLI behind any package-manager script",
        ));
    }
    Ok(physical)
}
fn local_profile() -> String {
    crate::sandbox::PROFILE.replace(
        "(allow process-exec)",
        "(allow process-exec (subpath (param \"CB_ROOT\")))",
    )
}
fn ast(sources: &[Source], program: &Path, bundled: bool) -> Result<Vec<Value>> {
    let session = Session::create()?;
    let program = session.copy_program(program)?;
    // Only the external override needs a configuration file. The bundled worker
    // invokes the library directly and never discovers configuration or parsers.
    let config = session.root().join("work/sgconfig.yml");
    if !bundled {
        std::fs::write(&config, "ruleDirs: []\n")?;
    }
    let mut findings = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(120);
    for source in sources {
        for rule in rules(source.language) {
            let arguments: Vec<OsString> = if bundled {
                vec![
                    "__cb_ast_worker".into(),
                    source.language.into(),
                    rule.id.into(),
                ]
            } else {
                [
                    OsString::from("run"),
                    "--config".into(),
                    config.as_os_str().to_owned(),
                    "--lang".into(),
                    source.language.into(),
                    "--pattern".into(),
                    rule.pattern.into(),
                    "--stdin".into(),
                    "--json=compact".into(),
                    "--color=never".into(),
                ]
                .into()
            };
            let command = crate::runner::command_with_profile(
                session.root(),
                &program,
                &arguments,
                &local_profile(),
            )?;
            let timeout = deadline
                .saturating_duration_since(Instant::now())
                .min(Duration::from_secs(10));
            let output = process::capture(command, source.text.as_bytes(), timeout)?;
            if !matches!(output.status.code(), Some(0 | 1)) {
                return Err(invalid("ast-grep failed in confinement"));
            }
            let value = json::parse(&output.stdout, false)
                .map_err(|_| invalid("ast-grep returned invalid JSON"))?;
            let matches = value
                .as_array()
                .ok_or_else(|| invalid("ast-grep did not return an array"))?;
            if output.status.code() == Some(1) && !matches.is_empty() {
                return Err(invalid("ast-grep returned contradictory status"));
            }
            for m in matches {
                let zero_line = integer(m.pointer("/range/start/line"))?;
                let line = zero_line
                    .checked_add(1)
                    .ok_or_else(|| invalid("invalid AST line"))?;
                let evidence = source
                    .evidence(line)
                    .ok_or_else(|| invalid("AST result references a missing source line"))?;
                if findings.len() == MAX_RESULTS {
                    return Err(invalid("AST result budget exceeded"));
                }
                findings.push(object([
                    ("origin", "ast-grep".into()),
                    ("rule", rule.id.into()),
                    ("source_id", source.id.clone().into()),
                    ("line", line.into()),
                    ("severity", "review".into()),
                    (
                        "evidence",
                        evidence.chars().take(240).collect::<String>().into(),
                    ),
                ]));
            }
        }
    }
    session.close()?;
    Ok(findings)
}
fn integer(value: Option<&Value>) -> Result<usize> {
    match value {
        Some(Value::Number(n)) => n.parse().map_err(|_| invalid("expected bounded integer")),
        _ => Err(invalid("expected integer")),
    }
}

pub(super) fn execute(options: &InspectOptions, review: &Options, report: Report) -> Result<i32> {
    let mut findings = Vec::new();
    let mut errors = Vec::new();
    let mut selected = Vec::new();
    let result = (|| -> Result<()> {
        crate::sandbox::require_backend()?;
        let _signals = crate::interrupt::Guard::install()?;
        let (root, physical) = Directory::root(&options.directory)?;
        source_root(&physical)?;
        let sources = collect(&root, &review.sources)?;
        if !root.same_root(&physical) {
            return Err(invalid("selected repository root changed"));
        }
        selected = sources
            .iter()
            .map(|s| {
                object([
                    ("source_id", s.id.clone().into()),
                    ("path", s.path.clone().into()),
                    ("lines", s.lines().into()),
                    ("bytes", s.text.len().into()),
                ])
            })
            .collect();
        let program = if let Some(path) = &review.ast_grep {
            native_program(path, &physical)?
        } else {
            std::env::current_exe()?
        };
        // Probe the backend before either requested executable receives untrusted input.
        let probe = Session::create()?;
        let command = crate::runner::command_with_profile(
            probe.root(),
            Path::new("/usr/bin/true"),
            &[],
            crate::sandbox::PROFILE,
        )?;
        if !process::capture(command, &[], Duration::from_secs(5))?
            .status
            .success()
        {
            return Err(invalid("macOS rejected the sandbox probe"));
        }
        findings = ast(&sources, &program, review.ast_grep.is_none())?;
        if review.with.is_some() {
            let program = native_program(
                review
                    .harness_bin
                    .as_ref()
                    .ok_or_else(|| invalid("missing harness"))?,
                &physical,
            )?;
            eprintln!(
                "cb: Codex review sends the selected source snapshots and AST matches to your configured OpenAI account and can consume paid usage. Model output remains advisory."
            );
            let model = harness::review(&sources, &findings, &program, &physical)?;
            findings.extend(model);
        }
        Ok(())
    })();
    if let Err(error) = result {
        // Errors from our adapters contain no child diagnostics or source text.
        errors.push(crate::output::escape(error.to_string().as_bytes()));
    }
    let exit = if !errors.is_empty() {
        2
    } else if findings.is_empty() {
        report.exit_code()
    } else {
        report.exit_code().max(1)
    };
    let review_report = object([
        (
            "status",
            if errors.is_empty() {
                "completed_in_selected_scope"
            } else {
                "incomplete"
            }
            .into(),
        ),
        ("selected_files", selected.into()),
        ("findings", findings.into()),
        (
            "errors",
            errors
                .iter()
                .cloned()
                .map(Value::from)
                .collect::<Vec<_>>()
                .into(),
        ),
        ("limitations", LIMITATIONS.into()),
    ]);
    let stdout = io::stdout();
    let mut out = stdout.lock();
    // Static results are retained even if AST or model review fails.
    if options.json {
        writeln!(
            out,
            "{}",
            object([
                ("schema_version", 2usize.into()),
                ("static", report.to_json()),
                ("review", review_report)
            ])
        )?;
    } else {
        writeln!(
            out,
            "Static inspection: {} finding(s), {} incomplete item(s).",
            report.findings.len(),
            report.incomplete.len()
        )?;
        for f in &report.findings {
            writeln!(out, "[{}] {} {}: {}", f.severity, f.rule, f.path, f.reason)?;
        }
        for i in &report.incomplete {
            writeln!(out, "[incomplete] {}: {}", i.path, i.reason)?;
        }
        // JSON escaping keeps all untrusted strings inert in terminal output.
        writeln!(out, "Source review: {review_report}")?;
    }
    Ok(exit)
}

#[cfg(test)]
mod tests;
