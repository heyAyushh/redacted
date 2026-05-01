use crate::errors::{RedactError, Result};
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

/// Parsed CLI arguments. All fields are explicit — no hidden state.
#[derive(Debug, Clone)]
pub struct CliArgs {
    pub except: Option<ExceptArgs>,
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
  echo "secret text" | redacted
  redacted --text "email me at user@example.com"
  redacted --input secrets.txt
  redacted --input logs/ --output cleaned/

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
  redacted except add --detector EMAIL
  redacted except list"#,
        version = VERSION,
    );
}

pub fn print_version() {
    eprintln!("redacted {}", VERSION);
}

/// Hand-rolled argument parser. No external dependencies.
/// Fails fast with actionable error messages per cli-for-agent skill.
pub fn parse_args() -> Result<CliArgs> {
    let raw: Vec<String> = env::args().collect();
    parse_args_from(&raw[1..])
}

pub fn parse_args_from(args: &[String]) -> Result<CliArgs> {
    if matches!(args.first().map(String::as_str), Some("except")) {
        return parse_except_args(&args[1..]);
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
    }
}
