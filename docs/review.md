# Selected source review

`review` is an optional Cargo feature that includes `scanner` and the exactly
pinned ast-grep Rust parser/grammars. The default build excludes both. Plain `cb inspect` remains the
offline launch-surface inspector even in a review-enabled build. Source review
starts the isolated bundled worker (and any requested external tool) only when
source-review options are explicitly supplied.

```sh
cargo build --locked --release --features review --bin cb
./target/release/cb inspect /path/to/repository \
  --source src/app.js --source src/lib.rs
```

Add the following options for advisory Codex review after the local AST stage:

```sh
--with codex --harness-bin /trusted/native/codex
```

Only the Codex adapter is integrated. Other names are refused; arbitrary harness
commands or repository-provided wrappers are not accepted. A future adapter must
provide equivalent isolation, authentication, configuration and output checks.

## Locked parser dependencies

No separate ast-grep executable is needed. The review feature enables these
exact optional registry dependencies, with upstream default features disabled
on ast-grep-core and its tree-sitter integration selected explicitly:

| Crate | Exact version |
| --- | --- |
| `ast-grep-core` | `=0.51.1` |
| `tree-sitter-javascript` | `=0.25.0` |
| `tree-sitter-python` | `=0.25.0` |
| `tree-sitter-rust` | `=0.24.2` |
| `tree-sitter-typescript` | `=0.23.2` |

The TypeScript grammar package supplies both TypeScript and TSX. No all-language
bundle, ast-grep CLI/config loader, dynamic grammar loader or rewrite API is
exposed. Tree-sitter and the grammar crates compile bundled C parser code during
the Rust build; they are part of the optional review trust boundary. A small fixed adapter uses ast-grep-core's Rust interfaces, which upstream
labels unstable; exact pins and rule fixtures protect against accidental drift.
Rust 1.90 or newer is required by these optional dependencies. The project's
pinned Rust 1.98.1 supports them; the default core keeps its existing declared MSRV.

Cargo.lock records exact transitive versions and registry checksums. The current
lockfile contains 45 third-party packages, including libc and build dependencies
(44 more than the default graph). Default and static-scanner builds still resolve
only libc. Pinning makes builds reproducible; dependency changes still need review.
Use `cargo build --locked --release --features review --bin cb` or
`cargo install --path . --locked --features review --bin cb`.

The parent copies its own executable into a private session and starts it under
the existing AST Seatbelt policy before providing source on stdin. Parsing stays
outside the parent process, with no network or host-home capability. The internal
worker accepts only a supported language and a fixed rule ID, bounded UTF-8 stdin,
and returns bounded match locations. It cannot accept repository rule files,
custom grammar paths, arbitrary patterns or fixes. Syntax errors produce an
incomplete result instead of treating a recovered parse tree as a complete scan.

For compatibility, `--ast-grep /absolute/native/binary` explicitly selects the
previous external executable backend instead. Its installation and version remain
outside Cargo.lock. It runs under the same AST confinement and fixed-pattern
protocol; remove the option to return to the locked bundled backend.

## Tools and login

This uses the **Codex CLI and its existing login**, not a direct model API client.
No API key is required, and inherited API keys are removed from the child
environment. CB checks only metadata for the private, current-user-owned
`auth.json` in the trusted `CODEX_HOME` or OS account's normal Codex directory.
The harness receives read-only access to that file in place. CB does not read,
copy, print or migrate its credential values. No auth write permission is granted.

Keychain-only credentials and refreshes requiring an auth-file write are not
supported. Sign in or refresh with the normal Codex CLI outside CB, then retry.
There is no automatic login flow or retry outside confinement. Existing CLI
versions must advertise the required flags; a missing flag or rejected config
stops the review. Normal user configuration and provider overrides are not
imported. The installed CLI chooses its default model; CB does not silently
substitute another provider or model.

For Codex or an explicit external AST override, supply absolute paths to trusted
native macOS binaries outside the selected repository. PATH, repository scripts, package managers and installers
are never invoked. For npm/Bun Codex installations, point to the native `codex`
binary inside the platform package rather than the JavaScript launcher.
Symlinks to installations are resolved and the native file is copied using
descriptor-based regular-file checks. This is not signature or provenance
verification: the operator must trust the installation and updates. External
tools remain supply-chain dependencies even though they are outside Cargo.lock.

## Source selection and AST coverage

Every file needs its own `--source relative/path`. There is no recursive scan,
glob expansion, automatic dependency installation or implicit whole-repository
upload. Limits are 16 distinct files, 64 KiB per file and 256 KiB combined, with
UTF-8 text required. Normal relative paths only: no parent traversal, hidden
components, `node_modules`, `target`, `vendor` or `dist`. Descendant symlinks,
special files, unreadable inputs and changing files fail the requested stage.
Static and source reads are bounded live-filesystem observations, not an atomic
repository snapshot or revision lock. Review results refer to captured content,
which may have changed on disk by the time the report is read.
Source roots overlapping the policy's readable system runtime or certificate
paths are unsupported and refused before either external tool starts. Normal
system runtime reads and filesystem metadata remain ambient capabilities.

Supported languages and trusted built-in AST patterns:

| Language | Review surfaces |
| --- | --- |
| JavaScript, TypeScript, TSX | Direct `eval`, `new Function`, object `.exec` and `.spawn` calls. |
| Python | Direct `eval`, `exec` and syntactic `subprocess` method calls. |
| Rust | `Command::new` and `std::process::Command::new`. |

These patterns deliberately identify review surfaces, including ordinary
functionality. A JavaScript regex `.exec` can match. Aliases, alternative APIs,
obfuscation and data flow can evade them. This is not dependency-CVE analysis,
import resolution, secret detection or comprehensive vulnerability coverage.
CB supplies source on stdin and chooses only fixed patterns and supported
languages. The bundled worker never loads configuration. The external override
receives a private fixed configuration. Repository `sgconfig.yml`, custom parsers,
ignore files, fixes and executable rules are not loaded. The AST stage has no
network permission.

## Prompt injection and authority

Repository strings are adversarial data. The model receives a JSON packet with
source IDs, relative paths, content and AST matches, under fixed developer
instructions. Comments, fake role markers, claimed policies, URLs and instructions
inside this packet cannot authorize work. CB does not activate repository
AGENTS.md, skills, plugins, MCP servers, hooks or rules as harness configuration.

Codex is requested to use an ephemeral read-only session, never approve tools,
ignore user configuration/rules, omit project instructions and disable shell,
apps, plugins, web search, memories, image and delegation capabilities. These
CLI settings supplement an experimental OS boundary rather than replacing it.

The bundled native worker and each external tool run in private macOS Seatbelt
sessions, with a replaced
environment, closed inherited descriptors and bounded stdin/output/deadlines.
Repository contents are provided on stdin, without mounting or granting read
access to the checkout. Fork/spawn and unrelated host-home reads are denied.
The harness may inspect its own process identity for Apple framework startup;
other-process inspection stays denied. Its only additional host file-data grant
is the Codex login file, plus system certificate files. The login is outside
the selected repository and read-only. There is no keychain or broad Unix control
socket grant. The AST profile receives none of these additional capabilities.

The harness gets outbound TCP/UDP, DNS and selected system networking/trust
services for inference. **This is not a provider-domain allowlist or network
approval broker**: IP services, including local or private-network services, can
be reached by the trusted harness. CB must trust its binary and the model service.
It never grants this networking profile to a project command. Unsupported
framework, managed-policy or CLI requirements cause a failure rather than a
less restricted retry. Seatbelt shares the host kernel and is deprecated; this
prototype is not a VM or a guarantee against OS/harness vulnerabilities.

A defensive prompt and JSON encoding cannot guarantee prevention of prompt
injection. Injection can still bias findings or suppress a useful finding.
Model responses are untrusted advice and never command, fix, trust or permission
requests. CB accepts only a bounded findings array with known source IDs,
integer one-based lines, allowed severities and exact nonempty evidence present
on the referenced snapshot line. Extra fields, duplicate keys, invented sources,
invalid evidence and malformed output fail validation. This verifies references,
not the truth or completeness of the model's conclusions. Untrusted response
strings are JSON escaped when printed; no links or commands are activated.

## Reports, disclosure and failure

`--with codex` explicitly authorizes transmitting the selected source and AST
matches to OpenAI using the existing account. It can consume paid usage. CB prints
a notice before the harness stage. Review selected files for private data before
opting in: source can contain secrets even though hidden files are excluded.
Ephemeral local mode is not a provider-side deletion or retention guarantee.

Plain inspection retains schema version 1. A requested source review uses schema
version 2 with the original report under `static` and a separate `review` object.
It includes selected-file IDs, paths, sizes, line counts, AST/model findings,
completion state, limitations and errors. Findings can contain source evidence
and model explanations, so these reports require more care before sharing than
the ordinary metadata-only inspector report. Raw child diagnostics are discarded
because they may contain source or account data.

Exit 2 means any stage is incomplete, including failed launch, limits, login,
timeout, interruption or invalid output. Otherwise, findings from any stage yield
1; no findings in the selected scope yields 0. Model output cannot remove static
findings or downgrade a static incomplete result. No result certifies safety.
The AST stage has a 120-second overall budget and 10-second child deadlines;
Codex has 300 seconds. Each output stream is capped at 1 MiB. Cleanup stops only
the owned process group while its root remains unreaped, then removes the private
session. A hard kill or OS crash can leave private temporary session data.

## Validation

Tests use synthetic source, dummy credentials and fixed local harness responses.
They exercise prompt-like source strings as data, forged references, invalid
output, file selection, symlinks, deadlines and output budgets. Native fixtures
verify login-only file access, denied auth writes, denied other-process queries,
denied subprocesses/Unix sockets, no AST networking and allowed harness IP traffic.
No live model turn is needed or run by these tests.

Bundled AST patterns are checked directly against all five supported languages
and in the native sandbox, without a separate AST installation. Native fixture
reviews also exercise the explicit external override for compatibility. The
installed native Codex CLI was checked with help and local configuration commands
only. An authenticated inference round trip, token
refresh and provider-side behavior have not been tested by these checks.

```sh
cargo test --locked --all-features \
  --test review_cli -- --ignored --test-threads=1
CB_TEST_CODEX_NATIVE=/trusted/native/codex cargo test --locked --all-features \
  --lib the_installed_native_codex_cli_help -- --ignored --test-threads=1
```

References: [Codex noninteractive CLI](https://learn.chatgpt.com/docs/non-interactive-mode),
[CLI flags](https://learn.chatgpt.com/docs/cli/reference),
[configuration](https://learn.chatgpt.com/docs/config-file/config-reference),
[authentication](https://learn.chatgpt.com/docs/auth),
[ast-grep Rust API](https://ast-grep.github.io/reference/api/#rust-api),
[ast-grep run](https://ast-grep.github.io/reference/cli/run.html),
[official ast-grep release](https://github.com/ast-grep/ast-grep/releases/tag/0.51.1),
and Chromium's [self-only process-info policy](https://chromium.googlesource.com/chromium/src/sandbox/+/35355c1deaf48465dae9a9cf661a9aa2124024ab).
