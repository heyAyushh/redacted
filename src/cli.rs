use crate::errors::{RedactError, Result};
use crate::text_utils::capitalize_first;
use std::collections::HashSet;
use std::env;

/// Binary handling mode for non-text files.
#[derive(Debug, Clone, PartialEq)]
pub enum BinaryMode {
    Skip,
    Fail,
    BestEffort,
}

/// Output format for redacted content.
#[derive(Debug, Clone, PartialEq)]
pub enum OutputFormat {
    Text,
    Json,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExceptRuleSelector {
    Detector(String),
    Literal(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExceptSubcommand {
    Add(ExceptRuleSelector),
    Remove(ExceptRuleSelector),
    List,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExceptArgs {
    pub file: Option<String>,
    pub command: Option<ExceptSubcommand>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProviderHelpTopic {
    Root,
    Enable,
    Install,
    Use,
    Current,
    List,
    Verify,
    Disable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProviderSubcommand {
    Enable { selector: String },
    Install { selector: String },
    Use { selector: String },
    Current,
    List,
    Verify { selector: Option<String>, all: bool },
    Disable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderArgs {
    pub help: Option<ProviderHelpTopic>,
    pub command: Option<ProviderSubcommand>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExternalDetectorHelpTopic {
    Root,
    Install,
    Use,
    Current,
    List,
    Verify,
    Disable,
    Default,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExternalDetectorDefaultMode {
    On,
    Off,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExternalDetectorSubcommand {
    Install { selector: String },
    Use { selector: String },
    Current,
    List,
    Verify { selector: Option<String>, all: bool },
    Disable { selector: Option<String>, all: bool },
    Default { mode: ExternalDetectorDefaultMode },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExternalDetectorArgs {
    pub help: Option<ExternalDetectorHelpTopic>,
    pub command: Option<ExternalDetectorSubcommand>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DocumentHelpTopic {
    Root,
    Enable,
    Install,
    Use,
    Current,
    List,
    Verify,
    Disable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DocumentSubcommand {
    Enable { selector: String },
    Install { selector: String },
    Use { selector: String },
    Current,
    List,
    Verify { selector: Option<String>, all: bool },
    Disable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DocumentArgs {
    pub help: Option<DocumentHelpTopic>,
    pub command: Option<DocumentSubcommand>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct BenchmarkArgs {
    pub help: bool,
    pub input: Option<String>,
    pub iterations: usize,
    pub privacy_filter: bool,
    pub document_adapter: bool,
    pub format: OutputFormat,
}

/// Parsed CLI arguments. All fields are explicit — no hidden state.
#[derive(Debug, Clone)]
pub struct CliArgs {
    pub except: Option<ExceptArgs>,
    pub provider: Option<ProviderArgs>,
    pub external_detector: Option<ExternalDetectorArgs>,
    pub document: Option<DocumentArgs>,
    pub benchmark: Option<BenchmarkArgs>,
    pub text: Option<String>,
    pub input: Option<String>,
    pub output: Option<String>,
    pub in_place: bool,
    pub recursive: bool,
    pub report_json: bool,
    pub config: Option<String>,
    pub patterns: Vec<(String, String)>,
    pub allow_patterns: Vec<String>,
    pub deny_patterns: Vec<String>,
    pub retain_detectors: Vec<String>,
    pub retain_literals: Vec<String>,
    pub except_detectors: Vec<String>,
    pub except_literals: Vec<String>,
    pub except_file: Option<String>,
    pub dry_run: bool,
    pub fail_on_find: bool,
    pub summary: bool,
    pub format: OutputFormat,
    pub replacement: Option<String>,
    pub binary: BinaryMode,
    pub max_file_size: u64,
    pub include_hidden: bool,
    pub follow_symlinks: bool,
    pub threads: Option<usize>,
    pub privacy_filter: bool,
    pub external_detectors: Option<bool>,
    pub document_adapter: bool,
    pub show_help: bool,
    pub show_version: bool,
    /// Tracks which flags were explicitly provided on the CLI,
    /// so config file values only apply to unset flags.
    pub explicit_flags: HashSet<String>,
}

impl Default for CliArgs {
    fn default() -> Self {
        Self {
            except: None,
            provider: None,
            external_detector: None,
            document: None,
            benchmark: None,
            text: None,
            input: None,
            output: None,
            in_place: false,
            recursive: true,
            report_json: false,
            config: None,
            patterns: Vec::new(),
            allow_patterns: Vec::new(),
            deny_patterns: Vec::new(),
            retain_detectors: Vec::new(),
            retain_literals: Vec::new(),
            except_detectors: Vec::new(),
            except_literals: Vec::new(),
            except_file: None,
            dry_run: false,
            fail_on_find: false,
            summary: false,
            format: OutputFormat::Text,
            replacement: None,
            binary: BinaryMode::Skip,
            max_file_size: 25 * 1024 * 1024, // 25 MiB
            include_hidden: false,
            follow_symlinks: false,
            threads: None,
            privacy_filter: false,
            external_detectors: None,
            document_adapter: false,
            show_help: false,
            show_version: false,
            explicit_flags: HashSet::new(),
        }
    }
}

const VERSION: &str = env!("CARGO_PKG_VERSION");

pub fn print_help() {
    eprintln!(
        r#"redacted {version} — Redact secrets and PII from text and files.

USAGE:
  redacted [OPTIONS]
  redacted except [--file <PATH>] <add|remove|list> [--detector <NAME> | --literal <VALUE>]
  redacted provider <enable|install|use|current|list|verify|disable> [OPTIONS]
  redacted detector <install|use|current|list|verify|disable|default> [OPTIONS]
  redacted document <enable|install|use|current|list|verify|disable> [OPTIONS]
  redacted benchmark --input <PATH> [OPTIONS]
  echo "secret text" | redacted
  redacted --text "email me at user@example.com"
  redacted --input secrets.txt
  redacted --input logs/ --output cleaned/
  redacted provider enable openai
  redacted provider enable mlx
  redacted detector install trufflehog
  redacted detector use trufflehog
  redacted document enable pdf-inspector
  redacted benchmark --input logs/ --iterations 5 --privacy-filter

INPUT (resolved in this order):
  --text <TEXT>         Literal text to redact
  --input <PATH>        File or directory to process
  (stdin)               Reads piped stdin if no --text or --input

OUTPUT:
  --output <PATH>       Write output to file/directory
  --in-place            Rewrite input file(s) atomically
  --format text|json    Output format (default: text)
  --report-json         Write structured JSON report to stderr

DETECTORS:
  --pattern <NAME=REGEX>  Add custom pattern (may be repeated)
  --allow-pattern <NAME>  Enable only this detector (may be repeated)
  --deny-pattern <NAME>   Disable this detector (may be repeated)
  --retain-detector <NAME>
                        Detect and report this detector, but keep the matched value in output
  --retain-literal <VALUE>
                        Keep this exact matched value in output (may be repeated)
  --except-detector <NAME>
                        Ignore findings from this detector during this scan (may be repeated)
  --except-literal <VALUE>
                        Ignore this exact matched value during this scan (may be repeated)
  --except-file <PATH>   Load persisted retain rules from file
  --replacement <STRING>  Custom replacement (default: [REDACTED:<TYPE>])

PRIVACY FILTER:
  --privacy-filter      Run the active privacy-filter provider as an extra detection pass
  redacted provider ... Manage install, activation, and verification for provider bundles
                        Provider mode is optional and outside the hardened core scan path

EXTERNAL DETECTORS:
  --detectors           Run active external detector engines for --input scans
  --no-detectors        Disable external detector engines for this scan
  redacted detector ... Manage external detector engines such as TruffleHog
                        External detectors are optional and outside the hardened core scan path

DOCUMENT ADAPTER:
  --document-adapter    Use the active document adapter for supported non-text inputs (PDF)
  redacted document ... Manage install, activation, and verification for document adapters

TRAVERSAL:
  --recursive           Recurse into directories (default: on)
  --include-hidden      Process hidden files/dirs
  --no-follow-symlinks  Do not follow symlinks (default: on)
  --binary skip|fail|best-effort
                        Binary file handling (default: skip)
  --max-file-size <BYTES>
                        Max file size in bytes (default: 26214400)

MODES:
  --dry-run             Show what would be redacted without writing
  --fail-on-find        Exit non-zero if any findings detected
  --summary             Print summary to stderr
  --config <PATH>       TOML configuration file

BENCHMARK:
  redacted benchmark    Run repeated dry-run scans and report timings

OTHER:
  --threads <N>         Worker threads for directory mode
  --help                Show this help
  --version             Show version

EXIT CODES:
  0   Success
  1   Operational error
  2   Usage error
  3   Findings detected (with --fail-on-find)

EXAMPLES:
  echo "token=sk_live_abc123" | redacted
  redacted --text "email me at user@example.com"
  redacted --input secrets.txt --output redacted.txt
  redacted --input logs/ --output cleaned/ --summary
  redacted --input .env --fail-on-find --dry-run
  redacted --input repo/ --output repo-clean/ --report-json
  redacted --text "user@example.com" --retain-detector EMAIL
  redacted --text "ref PROJ-1234" --pattern PROJECT_ID=PROJ-\d+ --retain-detector PROJECT_ID
  redacted --text "Alice was born on 1990-01-02" --privacy-filter
  redacted provider enable openai
  redacted detector install trufflehog
  redacted detector use trufflehog
  redacted --detectors --input repo/
  redacted document enable pdf-inspector
  redacted --input report.pdf --document-adapter
  redacted benchmark --input logs/ --iterations 5 --privacy-filter --document-adapter
  redacted provider list
  redacted detector list
  redacted document list
  redacted except add --detector EMAIL
  redacted except list"#,
        version = VERSION,
    );
}

pub fn print_provider_help(topic: ProviderHelpTopic) {
    let text = match topic {
        ProviderHelpTopic::Root => {
            r#"redacted provider — manage privacy-filter providers.

USAGE:
  redacted provider enable <provider-or-target>
  redacted provider install <provider-or-target>
  redacted provider use <provider-or-target>
  redacted provider current
  redacted provider list
  redacted provider verify [<provider-or-target> | --all]
  redacted provider disable

OVERVIEW:
  Provider aliases are human-friendly shortcuts such as `openai` and `mlx`.
  Exact targets are persistent IDs such as `openai/privacy-filter-v1`
  and `openai/privacy-filter-v1-mlx`.
  Aliases always resolve to a pinned exact target and the command prints
  the resolved target before it changes local state.
  Provider mode is optional and lower-trust than the hardened Rust-only core scan path.
  `openai` is the supported OPF token-span path.
  `mlx` is an experimental local MLX runtime for the converted OpenAI Privacy Filter.

EXAMPLES:
  redacted provider enable openai
  redacted provider enable mlx
  redacted provider install openai/privacy-filter-v1
  redacted provider install openai/privacy-filter-v1-mlx
  redacted provider use openai
  redacted provider current
  redacted provider list
  redacted provider verify --all
  redacted provider disable

NEXT STEP:
  Once a provider is enabled, run scans with:
    redacted --privacy-filter --input logs/"#
        }
        ProviderHelpTopic::Enable => {
            r#"redacted provider enable — install if needed, verify, and activate a provider.

USAGE:
  redacted provider enable <provider-or-target>

EXAMPLES:
  redacted provider enable openai
  redacted provider enable openai/privacy-filter-v1
  redacted provider enable mlx
  redacted provider enable openai/privacy-filter-v1-mlx

BEHAVIOR:
  - Resolves aliases such as `openai` and `mlx` to pinned exact targets.
  - Installs the bundle if it is missing.
  - Verifies the installed bundle if no verification stamp is present.
  - Marks the resolved exact target as active.
  - OpenAI Privacy Filter is a token-span detector, not a generative extractor."#
        }
        ProviderHelpTopic::Install => {
            r#"redacted provider install — download and verify a provider bundle without activating it.

USAGE:
  redacted provider install <provider-or-target>

EXAMPLES:
  redacted provider install openai
  redacted provider install openai/privacy-filter-v1
  redacted provider install mlx
  redacted provider install openai/privacy-filter-v1-mlx"#
        }
        ProviderHelpTopic::Use => {
            r#"redacted provider use — switch the active provider to an installed, verified bundle.

USAGE:
  redacted provider use <provider-or-target>

EXAMPLES:
  redacted provider use openai
  redacted provider use openai/privacy-filter-v1
  redacted provider use mlx
  redacted provider use openai/privacy-filter-v1-mlx

NOTE:
  `use` does not download anything. Use `enable` for easy onboarding or
  `install` first if you want a separate install step."#
        }
        ProviderHelpTopic::Current => {
            r#"redacted provider current — show the active provider target.

USAGE:
  redacted provider current"#
        }
        ProviderHelpTopic::List => {
            r#"redacted provider list — show aliases, exact targets, license metadata, and local install state.

USAGE:
  redacted provider list"#
        }
        ProviderHelpTopic::Verify => {
            r#"redacted provider verify — re-hash installed provider artifacts.

USAGE:
  redacted provider verify [<provider-or-target> | --all]

EXAMPLES:
  redacted provider verify
  redacted provider verify openai
  redacted provider verify openai/privacy-filter-v1
  redacted provider verify mlx
  redacted provider verify openai/privacy-filter-v1-mlx
  redacted provider verify --all

DEFAULT:
  Without a selector or `--all`, the active provider is verified."#
        }
        ProviderHelpTopic::Disable => {
            r#"redacted provider disable — clear the active provider selection.

USAGE:
  redacted provider disable"#
        }
    };
    eprintln!("{}", text);
}

pub fn print_external_detector_help(topic: ExternalDetectorHelpTopic) {
    let text = match topic {
        ExternalDetectorHelpTopic::Root => {
            r#"redacted detector — manage optional external detector engines.

USAGE:
  redacted detector install <detector-or-target>
  redacted detector use <detector-or-target>
  redacted detector current
  redacted detector list
  redacted detector verify [<detector-or-target> | --all]
  redacted detector disable [<detector-or-target> | --all]
  redacted detector default <on|off>

OVERVIEW:
  Native detectors always run. External detectors are extra lower-trust engines
  such as TruffleHog, selected explicitly and kept outside the Rust-only core.
  The first built-in external detector target is:
    trufflehog -> trufflehog/secrets-v1

EXAMPLES:
  redacted detector install trufflehog
  redacted detector use trufflehog
  redacted detector default on
  redacted detector current
  redacted detector list
  redacted detector verify --all
  redacted detector disable trufflehog

NEXT STEP:
  Once a detector is active, run scans with:
    redacted --detectors --input repo/
  Or persist the default with:
    redacted detector default on"#
        }
        ExternalDetectorHelpTopic::Install => {
            r#"redacted detector install — bind a local external detector executable.

USAGE:
  redacted detector install <detector-or-target>

EXAMPLES:
  redacted detector install trufflehog
  redacted detector install trufflehog/secrets-v1

BEHAVIOR:
  `install` does not download TruffleHog. It verifies that the local
  `trufflehog` executable exists, records its path, and pins its SHA-256."#
        }
        ExternalDetectorHelpTopic::Use => {
            r#"redacted detector use — add an installed detector engine to the active set.

USAGE:
  redacted detector use <detector-or-target>

EXAMPLES:
  redacted detector use trufflehog
  redacted detector use trufflehog/secrets-v1"#
        }
        ExternalDetectorHelpTopic::Current => {
            r#"redacted detector current — show active external detector engines and default mode.

USAGE:
  redacted detector current"#
        }
        ExternalDetectorHelpTopic::List => {
            r#"redacted detector list — show external detector aliases, targets, license metadata, and install state.

USAGE:
  redacted detector list"#
        }
        ExternalDetectorHelpTopic::Verify => {
            r#"redacted detector verify — re-check installed external detector metadata.

USAGE:
  redacted detector verify [<detector-or-target> | --all]

EXAMPLES:
  redacted detector verify
  redacted detector verify trufflehog
  redacted detector verify trufflehog/secrets-v1
  redacted detector verify --all"#
        }
        ExternalDetectorHelpTopic::Disable => {
            r#"redacted detector disable — remove external detector engines from the active set.

USAGE:
  redacted detector disable [<detector-or-target> | --all]

EXAMPLES:
  redacted detector disable trufflehog
  redacted detector disable --all"#
        }
        ExternalDetectorHelpTopic::Default => {
            r#"redacted detector default — control whether active external detectors run by default.

USAGE:
  redacted detector default <on|off>

EXAMPLES:
  redacted detector default on
  redacted detector default off

OVERRIDES:
  --detectors forces external detectors on for a scan.
  --no-detectors forces them off for a scan."#
        }
    };
    eprintln!("{}", text);
}

pub fn print_version() {
    eprintln!("redacted {}", VERSION);
}

pub fn print_document_help(topic: DocumentHelpTopic) {
    let text = match topic {
        DocumentHelpTopic::Root => {
            r#"redacted document — manage optional document adapters.

USAGE:
  redacted document enable <adapter-or-target>
  redacted document install <adapter-or-target>
  redacted document use <adapter-or-target>
  redacted document current
  redacted document list
  redacted document verify [<adapter-or-target> | --all]
  redacted document disable

OVERVIEW:
  Document adapters are optional and off by default.
  They convert supported non-text files into text before scanning.
  Current built-in alias:
    pdf-inspector -> pdf-inspector/local-v1

EXAMPLES:
  redacted document enable pdf-inspector
  redacted document use pdf-inspector/local-v1
  redacted document list
  redacted --input report.pdf --document-adapter"#
        }
        DocumentHelpTopic::Enable => {
            r#"redacted document enable — install if needed, verify, and activate an adapter.

USAGE:
  redacted document enable <adapter-or-target>

EXAMPLES:
  redacted document enable pdf-inspector
  redacted document enable pdf-inspector/local-v1"#
        }
        DocumentHelpTopic::Install => {
            r#"redacted document install — install and verify an adapter without activating it.

USAGE:
  redacted document install <adapter-or-target>

EXAMPLES:
  redacted document install pdf-inspector
  redacted document install pdf-inspector/local-v1"#
        }
        DocumentHelpTopic::Use => {
            r#"redacted document use — switch active adapter to an installed, verified target.

USAGE:
  redacted document use <adapter-or-target>

EXAMPLES:
  redacted document use pdf-inspector
  redacted document use pdf-inspector/local-v1"#
        }
        DocumentHelpTopic::Current => {
            r#"redacted document current — show the active document adapter target.

USAGE:
  redacted document current"#
        }
        DocumentHelpTopic::List => {
            r#"redacted document list — show aliases, exact targets, license metadata, and local install state.

USAGE:
  redacted document list"#
        }
        DocumentHelpTopic::Verify => {
            r#"redacted document verify — verify installed adapter assets and runtime prerequisites.

USAGE:
  redacted document verify [<adapter-or-target> | --all]

EXAMPLES:
  redacted document verify
  redacted document verify pdf-inspector
  redacted document verify pdf-inspector/local-v1
  redacted document verify --all"#
        }
        DocumentHelpTopic::Disable => {
            r#"redacted document disable — clear the active document adapter target.

USAGE:
  redacted document disable"#
        }
    };
    eprintln!("{}", text);
}

pub fn print_benchmark_help() {
    eprintln!(
        r#"redacted benchmark — run repeated dry-run scans and report timings.

USAGE:
  redacted benchmark --input <PATH> [--iterations <N>] [--privacy-filter] [--document-adapter] [--format text|json]

EXAMPLES:
  redacted benchmark --input logs/
  redacted benchmark --input logs/ --iterations 5 --privacy-filter
  redacted benchmark --input report.pdf --document-adapter
  redacted benchmark --input corpus/ --iterations 10 --privacy-filter --document-adapter --format json"#
    );
}

/// Hand-rolled argument parser. No external dependencies.
/// Fails fast with actionable error messages.
pub fn parse_args() -> Result<CliArgs> {
    let raw: Vec<String> = env::args().collect();
    parse_args_from(&raw[1..])
}

pub fn parse_args_from(args: &[String]) -> Result<CliArgs> {
    if matches!(args.first().map(String::as_str), Some("except")) {
        return parse_except_args(&args[1..]);
    }
    if matches!(args.first().map(String::as_str), Some("provider")) {
        return parse_provider_args(&args[1..]);
    }
    if matches!(args.first().map(String::as_str), Some("detector")) {
        return parse_external_detector_args(&args[1..]);
    }
    if matches!(args.first().map(String::as_str), Some("document")) {
        return parse_document_args(&args[1..]);
    }
    if matches!(args.first().map(String::as_str), Some("benchmark")) {
        return parse_benchmark_args(&args[1..]);
    }

    let mut cli = CliArgs::default();
    let mut i = 0;

    while i < args.len() {
        let arg = &args[i];
        match arg.as_str() {
            "--help" | "-h" => {
                cli.show_help = true;
                return Ok(cli);
            }
            "--version" | "-V" => {
                cli.show_version = true;
                return Ok(cli);
            }
            "--text" => {
                i += 1;
                cli.text = Some(require_value(args, i, "--text")?);
            }
            "--input" => {
                i += 1;
                cli.input = Some(require_value(args, i, "--input")?);
            }
            "--output" => {
                i += 1;
                cli.output = Some(require_value(args, i, "--output")?);
            }
            "--in-place" => cli.in_place = true,
            "--recursive" => cli.recursive = true,
            "--report-json" => cli.report_json = true,
            "--config" => {
                i += 1;
                cli.config = Some(require_value(args, i, "--config")?);
            }
            "--pattern" => {
                i += 1;
                let val = require_value(args, i, "--pattern")?;
                let (name, pat) = parse_pattern_value(&val)?;
                cli.patterns.push((name, pat));
            }
            "--allow-pattern" => {
                i += 1;
                cli.allow_patterns
                    .push(require_value(args, i, "--allow-pattern")?);
            }
            "--deny-pattern" => {
                i += 1;
                cli.deny_patterns
                    .push(require_value(args, i, "--deny-pattern")?);
            }
            "--retain-detector" => {
                i += 1;
                cli.retain_detectors
                    .push(require_value(args, i, "--retain-detector")?);
            }
            "--retain-literal" => {
                i += 1;
                cli.retain_literals
                    .push(require_value(args, i, "--retain-literal")?);
            }
            "--except-detector" => {
                i += 1;
                cli.except_detectors
                    .push(require_value(args, i, "--except-detector")?);
            }
            "--except-literal" => {
                i += 1;
                cli.except_literals
                    .push(require_value(args, i, "--except-literal")?);
            }
            "--except-file" => {
                i += 1;
                cli.except_file = Some(require_value(args, i, "--except-file")?);
            }
            "--dry-run" => cli.dry_run = true,
            "--fail-on-find" => cli.fail_on_find = true,
            "--summary" => cli.summary = true,
            "--format" => {
                i += 1;
                let val = require_value(args, i, "--format")?;
                cli.format = match val.as_str() {
                    "text" => OutputFormat::Text,
                    "json" => OutputFormat::Json,
                    other => {
                        return Err(RedactError::Usage(format!(
                            "Unknown format '{}'. Expected: text, json\n  redacted --format text",
                            other
                        )));
                    }
                };
            }
            "--replacement" => {
                i += 1;
                cli.replacement = Some(require_value(args, i, "--replacement")?);
            }
            "--binary" => {
                i += 1;
                let val = require_value(args, i, "--binary")?;
                cli.binary = match val.as_str() {
                    "skip" => BinaryMode::Skip,
                    "fail" => BinaryMode::Fail,
                    "best-effort" => BinaryMode::BestEffort,
                    other => {
                        return Err(RedactError::Usage(format!(
                            "Unknown binary mode '{}'. Expected: skip, fail, best-effort\n  redacted --binary skip",
                            other
                        )));
                    }
                };
                cli.explicit_flags.insert("binary".into());
            }
            "--max-file-size" => {
                i += 1;
                let val = require_value(args, i, "--max-file-size")?;
                cli.max_file_size = val.parse::<u64>().map_err(|_| {
                    RedactError::Usage(format!(
                        "Invalid max-file-size '{}'. Expected a number in bytes.\n  redacted --max-file-size 26214400",
                        val
                    ))
                })?;
                cli.explicit_flags.insert("max_file_size".into());
            }
            "--include-hidden" => {
                cli.include_hidden = true;
                cli.explicit_flags.insert("include_hidden".into());
            }
            "--no-follow-symlinks" => {
                cli.follow_symlinks = false;
                cli.explicit_flags.insert("follow_symlinks".into());
            }
            "--follow-symlinks" => {
                cli.follow_symlinks = true;
                cli.explicit_flags.insert("follow_symlinks".into());
            }
            "--threads" => {
                i += 1;
                let val = require_value(args, i, "--threads")?;
                cli.threads = Some(val.parse::<usize>().map_err(|_| {
                    RedactError::Usage(format!(
                        "Invalid threads '{}'. Expected a positive integer.\n  redacted --threads 4",
                        val
                    ))
                })?);
            }
            "--privacy-filter" => cli.privacy_filter = true,
            "--detectors" => cli.external_detectors = Some(true),
            "--no-detectors" => cli.external_detectors = Some(false),
            "--document-adapter" => cli.document_adapter = true,
            other => {
                return Err(RedactError::Usage(format!(
                    "Unknown argument '{}'\n  redacted --help",
                    other
                )));
            }
        }
        i += 1;
    }

    Ok(cli)
}

fn parse_except_args(args: &[String]) -> Result<CliArgs> {
    let mut cli = CliArgs::default();
    let mut except = ExceptArgs {
        file: None,
        command: None,
    };
    let mut i = 0;

    while i < args.len() {
        match args[i].as_str() {
            "--help" | "-h" => {
                cli.show_help = true;
                return Ok(cli);
            }
            "--file" => {
                i += 1;
                except.file = Some(require_value(args, i, "--file")?);
            }
            "list" => {
                except.command = Some(ExceptSubcommand::List);
            }
            "add" => {
                except.command = Some(ExceptSubcommand::Add(parse_except_selector(args, &mut i)?));
            }
            "remove" => {
                except.command = Some(ExceptSubcommand::Remove(parse_except_selector(
                    args, &mut i,
                )?));
            }
            other => {
                return Err(RedactError::Usage(format!(
                    "Unknown except argument '{}'\n  redacted except list\n  redacted except add --detector EMAIL",
                    other
                )));
            }
        }
        i += 1;
    }

    if except.command.is_none() {
        return Err(RedactError::Usage(
            "Missing except command.\n  redacted except list\n  redacted except add --detector EMAIL".into(),
        ));
    }

    cli.except = Some(except);
    Ok(cli)
}

fn parse_provider_args(args: &[String]) -> Result<CliArgs> {
    let mut cli = CliArgs::default();
    let provider = if args.is_empty() {
        ProviderArgs {
            help: Some(ProviderHelpTopic::Root),
            command: None,
        }
    } else {
        parse_provider_command(args)?
    };
    cli.provider = Some(provider);
    Ok(cli)
}

fn parse_external_detector_args(args: &[String]) -> Result<CliArgs> {
    let mut cli = CliArgs::default();
    let detector = if args.is_empty() {
        ExternalDetectorArgs {
            help: Some(ExternalDetectorHelpTopic::Root),
            command: None,
        }
    } else {
        parse_external_detector_command(args)?
    };
    cli.external_detector = Some(detector);
    Ok(cli)
}

fn parse_document_args(args: &[String]) -> Result<CliArgs> {
    let mut cli = CliArgs::default();
    let document = if args.is_empty() {
        DocumentArgs {
            help: Some(DocumentHelpTopic::Root),
            command: None,
        }
    } else {
        parse_document_command(args)?
    };
    cli.document = Some(document);
    Ok(cli)
}

fn parse_benchmark_args(args: &[String]) -> Result<CliArgs> {
    let mut cli = CliArgs::default();
    let mut benchmark = BenchmarkArgs {
        help: false,
        input: None,
        iterations: 3,
        privacy_filter: false,
        document_adapter: false,
        format: OutputFormat::Text,
    };
    let mut i = 0;

    while i < args.len() {
        match args[i].as_str() {
            "--help" | "-h" => {
                benchmark.help = true;
                break;
            }
            "--input" => {
                i += 1;
                benchmark.input = Some(require_value(args, i, "--input")?);
            }
            "--iterations" => {
                i += 1;
                let value = require_value(args, i, "--iterations")?;
                benchmark.iterations = value.parse::<usize>().map_err(|_| {
                    RedactError::Usage(format!(
                        "Invalid iterations '{}'. Expected a positive integer.\n  redacted benchmark --input logs/ --iterations 5",
                        value
                    ))
                })?;
                if benchmark.iterations == 0 {
                    return Err(RedactError::Usage(
                        "Benchmark iterations must be at least 1.\n  redacted benchmark --input logs/ --iterations 1".into(),
                    ));
                }
            }
            "--privacy-filter" => benchmark.privacy_filter = true,
            "--document-adapter" => benchmark.document_adapter = true,
            "--format" => {
                i += 1;
                let value = require_value(args, i, "--format")?;
                benchmark.format = match value.as_str() {
                    "text" => OutputFormat::Text,
                    "json" => OutputFormat::Json,
                    other => {
                        return Err(RedactError::Usage(format!(
                            "Unknown benchmark format '{}'. Expected: text, json\n  redacted benchmark --input logs/ --format text",
                            other
                        )));
                    }
                };
            }
            other => {
                return Err(RedactError::Usage(format!(
                    "Unknown benchmark argument '{}'\n  redacted benchmark --help",
                    other
                )));
            }
        }
        i += 1;
    }

    if !benchmark.help && benchmark.input.is_none() {
        return Err(RedactError::Usage(
            "Benchmark requires --input <PATH>.\n  redacted benchmark --input logs/ --iterations 3"
                .into(),
        ));
    }

    cli.benchmark = Some(benchmark);
    Ok(cli)
}

fn parse_provider_command(args: &[String]) -> Result<ProviderArgs> {
    let parsed = parse_managed_command(args, &PROVIDER_COMMAND_SPEC)?;
    Ok(ProviderArgs {
        help: parsed.help.map(provider_help_topic_from_managed),
        command: parsed.command.map(provider_subcommand_from_managed),
    })
}

fn parse_document_command(args: &[String]) -> Result<DocumentArgs> {
    let parsed = parse_managed_command(args, &DOCUMENT_COMMAND_SPEC)?;
    Ok(DocumentArgs {
        help: parsed.help.map(document_help_topic_from_managed),
        command: parsed.command.map(document_subcommand_from_managed),
    })
}

fn parse_external_detector_command(args: &[String]) -> Result<ExternalDetectorArgs> {
    let first = args[0].as_str();
    if first == "--help" || first == "-h" {
        return Ok(ExternalDetectorArgs {
            help: Some(ExternalDetectorHelpTopic::Root),
            command: None,
        });
    }

    let has_help_flag = args
        .iter()
        .skip(1)
        .any(|arg| arg == "--help" || arg == "-h");
    if has_help_flag {
        return Ok(ExternalDetectorArgs {
            help: Some(external_detector_topic_from_name(first)?),
            command: None,
        });
    }

    let command = match first {
        "install" => ExternalDetectorSubcommand::Install {
            selector: parse_external_detector_selector(args, "install")?,
        },
        "use" => ExternalDetectorSubcommand::Use {
            selector: parse_external_detector_selector(args, "use")?,
        },
        "current" => {
            reject_extra_args(args, 1, "detector", "current")?;
            ExternalDetectorSubcommand::Current
        }
        "list" => {
            reject_extra_args(args, 1, "detector", "list")?;
            ExternalDetectorSubcommand::List
        }
        "verify" => parse_external_detector_verify(args)?,
        "disable" => parse_external_detector_disable(args)?,
        "default" => parse_external_detector_default(args)?,
        other => {
            return Err(RedactError::Usage(format!(
                "Unknown detector command '{}'\n  redacted detector --help",
                other
            )));
        }
    };

    Ok(ExternalDetectorArgs {
        help: None,
        command: Some(command),
    })
}

fn external_detector_topic_from_name(name: &str) -> Result<ExternalDetectorHelpTopic> {
    match name {
        "install" => Ok(ExternalDetectorHelpTopic::Install),
        "use" => Ok(ExternalDetectorHelpTopic::Use),
        "current" => Ok(ExternalDetectorHelpTopic::Current),
        "list" => Ok(ExternalDetectorHelpTopic::List),
        "verify" => Ok(ExternalDetectorHelpTopic::Verify),
        "disable" => Ok(ExternalDetectorHelpTopic::Disable),
        "default" => Ok(ExternalDetectorHelpTopic::Default),
        other => Err(RedactError::Usage(format!(
            "Unknown detector command '{}'\n  redacted detector --help",
            other
        ))),
    }
}

fn parse_external_detector_selector(args: &[String], command: &str) -> Result<String> {
    if args.len() != 2 {
        return Err(RedactError::Usage(format!(
            "Detector command '{}' requires <detector-or-target>.\n  redacted detector {} trufflehog",
            command, command
        )));
    }
    Ok(args[1].clone())
}

fn parse_external_detector_verify(args: &[String]) -> Result<ExternalDetectorSubcommand> {
    let mut selector: Option<String> = None;
    let mut all = false;
    let mut index = 1;

    while index < args.len() {
        match args[index].as_str() {
            "--all" => all = true,
            value => {
                if selector.is_some() || all {
                    return Err(RedactError::Usage(
                        "Detector verify accepts one selector or --all.\n  redacted detector verify trufflehog\n  redacted detector verify --all".into(),
                    ));
                }
                selector = Some(value.to_string());
            }
        }
        index += 1;
    }

    Ok(ExternalDetectorSubcommand::Verify { selector, all })
}

fn parse_external_detector_disable(args: &[String]) -> Result<ExternalDetectorSubcommand> {
    let mut selector: Option<String> = None;
    let mut all = false;
    let mut index = 1;

    while index < args.len() {
        match args[index].as_str() {
            "--all" => all = true,
            value => {
                if selector.is_some() || all {
                    return Err(RedactError::Usage(
                        "Detector disable accepts one selector or --all.\n  redacted detector disable trufflehog\n  redacted detector disable --all".into(),
                    ));
                }
                selector = Some(value.to_string());
            }
        }
        index += 1;
    }

    Ok(ExternalDetectorSubcommand::Disable { selector, all })
}

fn parse_external_detector_default(args: &[String]) -> Result<ExternalDetectorSubcommand> {
    if args.len() != 2 {
        return Err(RedactError::Usage(
            "Detector default requires on or off.\n  redacted detector default on\n  redacted detector default off".into(),
        ));
    }
    let mode = match args[1].as_str() {
        "on" => ExternalDetectorDefaultMode::On,
        "off" => ExternalDetectorDefaultMode::Off,
        other => {
            return Err(RedactError::Usage(format!(
                "Unknown detector default '{}'. Expected: on, off\n  redacted detector default on",
                other
            )));
        }
    };
    Ok(ExternalDetectorSubcommand::Default { mode })
}

struct ManagedCommandSpec {
    family: &'static str,
    selector_name: &'static str,
    example_selector: &'static str,
}

const PROVIDER_COMMAND_SPEC: ManagedCommandSpec = ManagedCommandSpec {
    family: "provider",
    selector_name: "provider-or-target",
    example_selector: "openai",
};

const DOCUMENT_COMMAND_SPEC: ManagedCommandSpec = ManagedCommandSpec {
    family: "document",
    selector_name: "adapter-or-target",
    example_selector: "pdf-inspector",
};

enum ManagedHelpTopic {
    Root,
    Enable,
    Install,
    Use,
    Current,
    List,
    Verify,
    Disable,
}

enum ManagedSubcommand {
    Enable { selector: String },
    Install { selector: String },
    Use { selector: String },
    Current,
    List,
    Verify { selector: Option<String>, all: bool },
    Disable,
}

struct ManagedArgs {
    help: Option<ManagedHelpTopic>,
    command: Option<ManagedSubcommand>,
}

fn parse_managed_command(args: &[String], spec: &ManagedCommandSpec) -> Result<ManagedArgs> {
    let first = args[0].as_str();
    if first == "--help" || first == "-h" {
        return Ok(ManagedArgs {
            help: Some(ManagedHelpTopic::Root),
            command: None,
        });
    }

    let topic = managed_topic_from_name(first, spec)?;
    let has_help_flag = args
        .iter()
        .skip(1)
        .any(|arg| arg == "--help" || arg == "-h");
    if has_help_flag {
        return Ok(ManagedArgs {
            help: Some(topic),
            command: None,
        });
    }

    let command = match first {
        "enable" => ManagedSubcommand::Enable {
            selector: parse_managed_selector(args, "enable", spec)?,
        },
        "install" => ManagedSubcommand::Install {
            selector: parse_managed_selector(args, "install", spec)?,
        },
        "use" => ManagedSubcommand::Use {
            selector: parse_managed_selector(args, "use", spec)?,
        },
        "current" => {
            reject_extra_args(args, 1, spec.family, "current")?;
            ManagedSubcommand::Current
        }
        "list" => {
            reject_extra_args(args, 1, spec.family, "list")?;
            ManagedSubcommand::List
        }
        "verify" => parse_managed_verify(args, spec)?,
        "disable" => {
            reject_extra_args(args, 1, spec.family, "disable")?;
            ManagedSubcommand::Disable
        }
        other => {
            return Err(RedactError::Usage(format!(
                "Unknown {} command '{}'\n  redacted {} --help",
                spec.family, other, spec.family
            )));
        }
    };

    Ok(ManagedArgs {
        help: None,
        command: Some(command),
    })
}

fn parse_managed_verify(args: &[String], spec: &ManagedCommandSpec) -> Result<ManagedSubcommand> {
    let mut selector: Option<String> = None;
    let mut all = false;
    let mut index = 1;

    while index < args.len() {
        match args[index].as_str() {
            "--all" => all = true,
            value => {
                if selector.is_some() || all {
                    let display_family = capitalize_first(spec.family);
                    return Err(RedactError::Usage(format!(
                        "{} verify accepts one selector or --all.\n  redacted {} verify {}\n  redacted {} verify --all",
                        display_family, spec.family, spec.example_selector, spec.family
                    )));
                }
                selector = Some(value.to_string());
            }
        }
        index += 1;
    }

    Ok(ManagedSubcommand::Verify { selector, all })
}

fn managed_topic_from_name(name: &str, spec: &ManagedCommandSpec) -> Result<ManagedHelpTopic> {
    match name {
        "enable" => Ok(ManagedHelpTopic::Enable),
        "install" => Ok(ManagedHelpTopic::Install),
        "use" => Ok(ManagedHelpTopic::Use),
        "current" => Ok(ManagedHelpTopic::Current),
        "list" => Ok(ManagedHelpTopic::List),
        "verify" => Ok(ManagedHelpTopic::Verify),
        "disable" => Ok(ManagedHelpTopic::Disable),
        other => Err(RedactError::Usage(format!(
            "Unknown {} command '{}'\n  redacted {} --help",
            spec.family, other, spec.family
        ))),
    }
}

fn parse_managed_selector(
    args: &[String],
    command: &str,
    spec: &ManagedCommandSpec,
) -> Result<String> {
    if args.len() != 2 {
        let display_family = capitalize_first(spec.family);
        return Err(RedactError::Usage(format!(
            "{} command '{}' requires <{}>.\n  redacted {} {} {}",
            display_family,
            command,
            spec.selector_name,
            spec.family,
            command,
            spec.example_selector
        )));
    }
    Ok(args[1].clone())
}

fn provider_help_topic_from_managed(topic: ManagedHelpTopic) -> ProviderHelpTopic {
    match topic {
        ManagedHelpTopic::Root => ProviderHelpTopic::Root,
        ManagedHelpTopic::Enable => ProviderHelpTopic::Enable,
        ManagedHelpTopic::Install => ProviderHelpTopic::Install,
        ManagedHelpTopic::Use => ProviderHelpTopic::Use,
        ManagedHelpTopic::Current => ProviderHelpTopic::Current,
        ManagedHelpTopic::List => ProviderHelpTopic::List,
        ManagedHelpTopic::Verify => ProviderHelpTopic::Verify,
        ManagedHelpTopic::Disable => ProviderHelpTopic::Disable,
    }
}

fn document_help_topic_from_managed(topic: ManagedHelpTopic) -> DocumentHelpTopic {
    match topic {
        ManagedHelpTopic::Root => DocumentHelpTopic::Root,
        ManagedHelpTopic::Enable => DocumentHelpTopic::Enable,
        ManagedHelpTopic::Install => DocumentHelpTopic::Install,
        ManagedHelpTopic::Use => DocumentHelpTopic::Use,
        ManagedHelpTopic::Current => DocumentHelpTopic::Current,
        ManagedHelpTopic::List => DocumentHelpTopic::List,
        ManagedHelpTopic::Verify => DocumentHelpTopic::Verify,
        ManagedHelpTopic::Disable => DocumentHelpTopic::Disable,
    }
}

fn provider_subcommand_from_managed(command: ManagedSubcommand) -> ProviderSubcommand {
    match command {
        ManagedSubcommand::Enable { selector } => ProviderSubcommand::Enable { selector },
        ManagedSubcommand::Install { selector } => ProviderSubcommand::Install { selector },
        ManagedSubcommand::Use { selector } => ProviderSubcommand::Use { selector },
        ManagedSubcommand::Current => ProviderSubcommand::Current,
        ManagedSubcommand::List => ProviderSubcommand::List,
        ManagedSubcommand::Verify { selector, all } => ProviderSubcommand::Verify { selector, all },
        ManagedSubcommand::Disable => ProviderSubcommand::Disable,
    }
}

fn document_subcommand_from_managed(command: ManagedSubcommand) -> DocumentSubcommand {
    match command {
        ManagedSubcommand::Enable { selector } => DocumentSubcommand::Enable { selector },
        ManagedSubcommand::Install { selector } => DocumentSubcommand::Install { selector },
        ManagedSubcommand::Use { selector } => DocumentSubcommand::Use { selector },
        ManagedSubcommand::Current => DocumentSubcommand::Current,
        ManagedSubcommand::List => DocumentSubcommand::List,
        ManagedSubcommand::Verify { selector, all } => DocumentSubcommand::Verify { selector, all },
        ManagedSubcommand::Disable => DocumentSubcommand::Disable,
    }
}

fn reject_extra_args(
    args: &[String],
    allowed_len: usize,
    family: &str,
    command: &str,
) -> Result<()> {
    if args.len() > allowed_len {
        let display_family = capitalize_first(family);
        return Err(RedactError::Usage(format!(
            "{} command '{}' does not accept extra arguments.\n  redacted {} {}",
            display_family, command, family, command
        )));
    }
    Ok(())
}

fn parse_except_selector(args: &[String], i: &mut usize) -> Result<ExceptRuleSelector> {
    *i += 1;
    if *i >= args.len() {
        return Err(RedactError::Usage(
            "Except command requires --detector <NAME> or --literal <VALUE>.".into(),
        ));
    }

    match args[*i].as_str() {
        "--detector" => {
            *i += 1;
            Ok(ExceptRuleSelector::Detector(require_value(
                args,
                *i,
                "--detector",
            )?))
        }
        "--literal" => {
            *i += 1;
            Ok(ExceptRuleSelector::Literal(require_value(
                args,
                *i,
                "--literal",
            )?))
        }
        other => Err(RedactError::Usage(format!(
            "Unknown except selector '{}'\n  redacted except add --detector EMAIL",
            other
        ))),
    }
}

fn require_value(args: &[String], i: usize, flag: &str) -> Result<String> {
    if i >= args.len() {
        return Err(RedactError::Usage(format!(
            "Flag '{}' requires a value.\n  redacted {} <VALUE>",
            flag, flag
        )));
    }
    Ok(args[i].clone())
}

fn parse_pattern_value(val: &str) -> Result<(String, String)> {
    if let Some(idx) = val.find('=') {
        let name = val[..idx].to_string();
        let pat = val[idx + 1..].to_string();
        if name.is_empty() || pat.is_empty() {
            return Err(RedactError::Usage(
                "Pattern must be NAME=REGEX, both non-empty.\n  redacted --pattern MY_SECRET=sk_[a-zA-Z0-9]+".into(),
            ));
        }
        Ok((name, pat))
    } else {
        Err(RedactError::Usage(format!(
            "Pattern '{}' must be in NAME=REGEX format.\n  redacted --pattern MY_SECRET=sk_[a-zA-Z0-9]+",
            val
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(s: &[&str]) -> Vec<String> {
        s.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn parse_help() {
        let cli = parse_args_from(&args(&["--help"])).unwrap();
        assert!(cli.show_help);
    }

    #[test]
    fn parse_version() {
        let cli = parse_args_from(&args(&["--version"])).unwrap();
        assert!(cli.show_version);
    }

    #[test]
    fn parse_text_input() {
        let cli = parse_args_from(&args(&["--text", "hello"])).unwrap();
        assert_eq!(cli.text, Some("hello".into()));
    }

    #[test]
    fn parse_file_input() {
        let cli = parse_args_from(&args(&["--input", "f.txt", "--output", "o.txt"])).unwrap();
        assert_eq!(cli.input, Some("f.txt".into()));
        assert_eq!(cli.output, Some("o.txt".into()));
    }

    #[test]
    fn parse_pattern() {
        let cli = parse_args_from(&args(&["--pattern", "KEY=sk_[a-z]+"])).unwrap();
        assert_eq!(cli.patterns, vec![("KEY".into(), "sk_[a-z]+".into())]);
    }

    #[test]
    fn parse_retain_and_except_flags() {
        let cli = parse_args_from(&args(&[
            "--retain-detector",
            "EMAIL",
            "--retain-literal",
            "user@example.com",
            "--except-detector",
            "PHONE",
            "--except-literal",
            "noreply@example.com",
        ]))
        .unwrap();
        assert_eq!(cli.retain_detectors, vec!["EMAIL"]);
        assert_eq!(cli.retain_literals, vec!["user@example.com"]);
        assert_eq!(cli.except_detectors, vec!["PHONE"]);
        assert_eq!(cli.except_literals, vec!["noreply@example.com"]);
    }

    #[test]
    fn parse_except_subcommand() {
        let cli = parse_args_from(&args(&["except", "add", "--detector", "EMAIL"])).unwrap();
        assert_eq!(
            cli.except,
            Some(ExceptArgs {
                file: None,
                command: Some(ExceptSubcommand::Add(ExceptRuleSelector::Detector(
                    "EMAIL".into()
                ))),
            })
        );
    }

    #[test]
    fn parse_provider_root_help() {
        let cli = parse_args_from(&args(&["provider"])).unwrap();
        assert_eq!(
            cli.provider,
            Some(ProviderArgs {
                help: Some(ProviderHelpTopic::Root),
                command: None,
            })
        );
    }

    #[test]
    fn parse_provider_enable_alias() {
        let cli = parse_args_from(&args(&["provider", "enable", "openai"])).unwrap();
        assert_eq!(
            cli.provider,
            Some(ProviderArgs {
                help: None,
                command: Some(ProviderSubcommand::Enable {
                    selector: "openai".into(),
                }),
            })
        );
    }

    #[test]
    fn parse_provider_rejects_extra_arguments() {
        let error =
            parse_args_from(&args(&["provider", "enable", "openai", "--extra"])).unwrap_err();
        assert!(error.to_string().contains("requires <provider-or-target>"));
    }

    #[test]
    fn parse_provider_verify_all() {
        let cli = parse_args_from(&args(&["provider", "verify", "--all"])).unwrap();
        assert_eq!(
            cli.provider,
            Some(ProviderArgs {
                help: None,
                command: Some(ProviderSubcommand::Verify {
                    selector: None,
                    all: true,
                }),
            })
        );
    }

    #[test]
    fn parse_provider_subcommand_help() {
        let cli = parse_args_from(&args(&["provider", "use", "--help"])).unwrap();
        assert_eq!(
            cli.provider,
            Some(ProviderArgs {
                help: Some(ProviderHelpTopic::Use),
                command: None,
            })
        );
    }

    #[test]
    fn parse_privacy_filter_flag() {
        let cli = parse_args_from(&args(&["--text", "hello", "--privacy-filter"])).unwrap();
        assert!(cli.privacy_filter);
    }

    #[test]
    fn parse_external_detector_root_help() {
        let cli = parse_args_from(&args(&["detector"])).unwrap();
        assert_eq!(
            cli.external_detector,
            Some(ExternalDetectorArgs {
                help: Some(ExternalDetectorHelpTopic::Root),
                command: None,
            })
        );
    }

    #[test]
    fn parse_external_detector_install_alias() {
        let cli = parse_args_from(&args(&["detector", "install", "trufflehog"])).unwrap();
        assert_eq!(
            cli.external_detector,
            Some(ExternalDetectorArgs {
                help: None,
                command: Some(ExternalDetectorSubcommand::Install {
                    selector: "trufflehog".into(),
                }),
            })
        );
    }

    #[test]
    fn parse_external_detector_default_on() {
        let cli = parse_args_from(&args(&["detector", "default", "on"])).unwrap();
        assert_eq!(
            cli.external_detector,
            Some(ExternalDetectorArgs {
                help: None,
                command: Some(ExternalDetectorSubcommand::Default {
                    mode: ExternalDetectorDefaultMode::On,
                }),
            })
        );
    }

    #[test]
    fn parse_external_detector_disable_selector() {
        let cli = parse_args_from(&args(&["detector", "disable", "trufflehog"])).unwrap();
        assert_eq!(
            cli.external_detector,
            Some(ExternalDetectorArgs {
                help: None,
                command: Some(ExternalDetectorSubcommand::Disable {
                    selector: Some("trufflehog".into()),
                    all: false,
                }),
            })
        );
    }

    #[test]
    fn parse_external_detector_verify_all() {
        let cli = parse_args_from(&args(&["detector", "verify", "--all"])).unwrap();
        assert_eq!(
            cli.external_detector,
            Some(ExternalDetectorArgs {
                help: None,
                command: Some(ExternalDetectorSubcommand::Verify {
                    selector: None,
                    all: true,
                }),
            })
        );
    }

    #[test]
    fn parse_external_detectors_scan_flags() {
        let cli = parse_args_from(&args(&["--input", "repo", "--detectors"])).unwrap();
        assert_eq!(cli.external_detectors, Some(true));

        let cli = parse_args_from(&args(&["--input", "repo", "--no-detectors"])).unwrap();
        assert_eq!(cli.external_detectors, Some(false));
    }

    #[test]
    fn parse_document_root_help() {
        let cli = parse_args_from(&args(&["document"])).unwrap();
        assert_eq!(
            cli.document,
            Some(DocumentArgs {
                help: Some(DocumentHelpTopic::Root),
                command: None,
            })
        );
    }

    #[test]
    fn parse_document_enable_alias() {
        let cli = parse_args_from(&args(&["document", "enable", "pdf-inspector"])).unwrap();
        assert_eq!(
            cli.document,
            Some(DocumentArgs {
                help: None,
                command: Some(DocumentSubcommand::Enable {
                    selector: "pdf-inspector".into(),
                }),
            })
        );
    }

    #[test]
    fn parse_document_verify_all() {
        let cli = parse_args_from(&args(&["document", "verify", "--all"])).unwrap();
        assert_eq!(
            cli.document,
            Some(DocumentArgs {
                help: None,
                command: Some(DocumentSubcommand::Verify {
                    selector: None,
                    all: true,
                }),
            })
        );
    }

    #[test]
    fn parse_document_current_rejects_extra_arguments_with_document_help() {
        let error = parse_args_from(&args(&["document", "current", "--extra"])).unwrap_err();
        let message = error.to_string();
        assert!(message.contains("Document command 'current'"));
        assert!(message.contains("redacted document current"));
        assert!(!message.contains("redacted provider current"));
    }

    #[test]
    fn parse_document_subcommand_help() {
        let cli = parse_args_from(&args(&["document", "use", "--help"])).unwrap();
        assert_eq!(
            cli.document,
            Some(DocumentArgs {
                help: Some(DocumentHelpTopic::Use),
                command: None,
            })
        );
    }

    #[test]
    fn parse_benchmark_command() {
        let cli = parse_args_from(&args(&[
            "benchmark",
            "--input",
            "logs",
            "--iterations",
            "5",
            "--privacy-filter",
            "--document-adapter",
            "--format",
            "json",
        ]))
        .unwrap();
        assert_eq!(
            cli.benchmark,
            Some(BenchmarkArgs {
                help: false,
                input: Some("logs".into()),
                iterations: 5,
                privacy_filter: true,
                document_adapter: true,
                format: OutputFormat::Json,
            })
        );
    }

    #[test]
    fn parse_document_adapter_flag() {
        let cli = parse_args_from(&args(&["--input", "doc.pdf", "--document-adapter"])).unwrap();
        assert!(cli.document_adapter);
    }

    #[test]
    fn parse_binary_mode() {
        let cli = parse_args_from(&args(&["--binary", "best-effort"])).unwrap();
        assert_eq!(cli.binary, BinaryMode::BestEffort);
    }

    #[test]
    fn missing_value_errors() {
        let result = parse_args_from(&args(&["--text"]));
        assert!(result.is_err());
    }

    #[test]
    fn unknown_arg_errors() {
        let result = parse_args_from(&args(&["--banana"]));
        assert!(result.is_err());
    }

    #[test]
    fn defaults_are_sane() {
        let cli = CliArgs::default();
        assert!(cli.recursive);
        assert!(!cli.follow_symlinks);
        assert!(!cli.include_hidden);
        assert_eq!(cli.binary, BinaryMode::Skip);
        assert_eq!(cli.max_file_size, 25 * 1024 * 1024);
        assert!(!cli.privacy_filter);
    }
}
