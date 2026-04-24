mod cli;
mod config;
mod detector;
mod errors;
mod except;
mod io_safe;
mod policy;
mod redact;
mod report;
mod traverse;

use cli::{BinaryMode, OutputFormat};
use config::Config;
use detector::DetectorRegistry;
use errors::{RedactError, EXIT_FINDINGS, EXIT_SUCCESS};
use policy::{FindingAction, FindingDecision};
use report::{FileResult, FileStatus, FindingReport, Summary};
use std::path::Path;
use std::process;

fn main() {
    let code = match run() {
        Ok(code) => code,
        Err(e) => {
            eprintln!("Error: {}", e);
            e.exit_code()
        }
    };
    process::exit(code);
}

fn run() -> errors::Result<i32> {
    let cli_args = cli::parse_args()?;

    if let Some(ref except_args) = cli_args.except {
        return except::run_except_command(except_args);
    }

    if cli_args.show_help {
        cli::print_help();
        return Ok(EXIT_SUCCESS);
    }
    if cli_args.show_version {
        cli::print_version();
        return Ok(EXIT_SUCCESS);
    }

    let config = Config::from_cli(&cli_args)?;
    let except_rules =
        if let Some(path) = except::resolve_scan_except_path(config.except_file.as_deref())? {
            except::load_rules(&path)?
        } else {
            Vec::new()
        };

    // Build detector registry
    let registry = DetectorRegistry::build_default(
        &config.allow_patterns,
        &config.deny_patterns,
        &config.patterns,
    );

    // Determine input source (priority: text > input > stdin)
    if let Some(ref text) = config.text {
        return process_text(text, &config, &registry, &except_rules);
    }

    if let Some(ref input_path) = config.input {
        let path = Path::new(input_path);
        if !path.exists() {
            return Err(RedactError::Usage(format!(
                "Input path '{}' does not exist.\n  redacted --input <PATH>",
                input_path
            )));
        }

        if path.is_file() {
            return process_single_file(path, &config, &registry, &except_rules);
        } else if path.is_dir() {
            return process_directory(path, &config, &registry, &except_rules);
        } else {
            return Err(RedactError::Usage(format!(
                "Input '{}' is neither a file nor a directory.",
                input_path
            )));
        }
    }

    // stdin fallback
    if io_safe::stdin_is_piped() {
        let text = io_safe::read_stdin()?;
        return process_text(&text, &config, &registry, &except_rules);
    }

    Err(RedactError::Usage(
        "No input provided. Use --text, --input, or pipe stdin.\n\n  \
         echo \"secret text\" | redacted\n  \
         redacted --text \"my secret text\"\n  \
         redacted --input <PATH>\n  \
         redacted --help"
            .into(),
    ))
}

fn decide_findings(
    text: &str,
    config: &Config,
    registry: &DetectorRegistry,
    except_rules: &[except::ExceptRule],
) -> Vec<FindingDecision> {
    policy::decide_findings(
        text,
        registry.detect_all(text),
        &config.retain_detectors,
        &config.retain_literals,
        &config.except_detectors,
        &config.except_literals,
        except_rules,
    )
}

fn redacted_findings(decisions: &[FindingDecision]) -> Vec<detector::Finding> {
    decisions
        .iter()
        .filter(|d| d.action == FindingAction::Redact)
        .map(|d| d.finding.clone())
        .collect()
}

fn reportable_findings(decisions: &[FindingDecision]) -> Vec<&FindingDecision> {
    decisions
        .iter()
        .filter(|d| d.action != FindingAction::Ignore)
        .collect()
}

fn action_name(action: FindingAction) -> &'static str {
    match action {
        FindingAction::Redact => "redacted",
        FindingAction::Retain => "retained",
        FindingAction::Ignore => "ignored",
    }
}

fn process_text(
    text: &str,
    config: &Config,
    registry: &DetectorRegistry,
    except_rules: &[except::ExceptRule],
) -> errors::Result<i32> {
    let decisions = decide_findings(text, config, registry, except_rules);
    let reportable = reportable_findings(&decisions);
    let redactions = redacted_findings(&decisions);
    let finding_count = reportable.len();

    let reports: Vec<FindingReport> = reportable
        .iter()
        .map(|decision| {
            report::finding_to_report(&decision.finding, text, action_name(decision.action))
        })
        .collect();

    let redacted = if config.dry_run {
        text.to_string()
    } else {
        redact::apply_redactions(text, &redactions, config.replacement.as_deref())
    };

    // Build result for reporting
    let file_result = FileResult {
        path: "<stdin/text>".into(),
        findings_count: finding_count,
        findings: reports,
        status: FileStatus::Processed,
    };

    let results = vec![file_result];
    let summary = Summary::from_results(&results);

    // Output
    if config.format == OutputFormat::Json {
        let mut buf = Vec::new();
        report::write_json_report(&results, &summary, &mut buf).map_err(RedactError::Io)?;
        let json = String::from_utf8(buf).unwrap_or_default();
        if let Some(ref out_path) = config.output {
            io_safe::atomic_write(Path::new(out_path), &json)?;
        } else {
            io_safe::write_stdout(&json)?;
        }
    } else if config.report_json {
        // Redacted text to stdout or output file, JSON report to stderr
        if let Some(ref out_path) = config.output {
            if !config.dry_run {
                io_safe::atomic_write(Path::new(out_path), &redacted)?;
            }
        } else {
            io_safe::write_stdout(&redacted)?;
        }
        let mut buf = Vec::new();
        report::write_json_report(&results, &summary, &mut buf).map_err(RedactError::Io)?;
        let json = String::from_utf8(buf).unwrap_or_default();
        eprint!("{}", json);
    } else if let Some(ref out_path) = config.output {
        if !config.dry_run {
            io_safe::atomic_write(Path::new(out_path), &redacted)?;
        }
    } else {
        io_safe::write_stdout(&redacted)?;
    }

    if config.summary || config.dry_run {
        report::print_summary(&summary);
    }

    if config.fail_on_find && finding_count > 0 {
        Ok(EXIT_FINDINGS)
    } else {
        Ok(EXIT_SUCCESS)
    }
}

fn read_file_with_mode(path: &Path, config: &Config) -> errors::Result<String> {
    match config.binary {
        BinaryMode::BestEffort => io_safe::read_file_best_effort(path, config.max_file_size),
        _ => io_safe::read_file(path, config.max_file_size),
    }
}

fn process_single_file(
    path: &Path,
    config: &Config,
    registry: &DetectorRegistry,
    except_rules: &[except::ExceptRule],
) -> errors::Result<i32> {
    let text = match read_file_with_mode(path, config) {
        Ok(t) => t,
        Err(e) => {
            // If binary and skip mode, report and succeed
            if matches!(config.binary, BinaryMode::Skip) {
                let msg = e.to_string();
                if msg.contains("binary") {
                    let results = vec![FileResult {
                        path: path.display().to_string(),
                        findings_count: 0,
                        findings: vec![],
                        status: FileStatus::Skipped("Binary file".into()),
                    }];
                    let summary = Summary::from_results(&results);
                    if config.summary {
                        report::print_summary(&summary);
                    }
                    return Ok(EXIT_SUCCESS);
                }
            }
            return Err(e);
        }
    };

    let decisions = decide_findings(&text, config, registry, except_rules);
    let reportable = reportable_findings(&decisions);
    let redactions = redacted_findings(&decisions);
    let finding_count = reportable.len();
    let reports: Vec<FindingReport> = reportable
        .iter()
        .map(|decision| {
            report::finding_to_report(&decision.finding, &text, action_name(decision.action))
        })
        .collect();

    let redacted = if config.dry_run {
        text.clone()
    } else {
        redact::apply_redactions(&text, &redactions, config.replacement.as_deref())
    };

    let file_result = FileResult {
        path: path.display().to_string(),
        findings_count: finding_count,
        findings: reports,
        status: FileStatus::Processed,
    };

    let results = vec![file_result];
    let summary = Summary::from_results(&results);

    if config.format == OutputFormat::Json {
        let mut buf = Vec::new();
        report::write_json_report(&results, &summary, &mut buf).map_err(RedactError::Io)?;
        let json = String::from_utf8(buf).unwrap_or_default();
        if let Some(ref out_path) = config.output {
            io_safe::atomic_write(Path::new(out_path), &json)?;
        } else {
            io_safe::write_stdout(&json)?;
        }
    } else {
        if !config.dry_run {
            if config.in_place {
                io_safe::atomic_write(path, &redacted)?;
            } else if let Some(ref out_path) = config.output {
                io_safe::atomic_write(Path::new(out_path), &redacted)?;
            } else {
                io_safe::write_stdout(&redacted)?;
            }
        }
        if config.report_json {
            let mut buf = Vec::new();
            report::write_json_report(&results, &summary, &mut buf).map_err(RedactError::Io)?;
            let json = String::from_utf8(buf).unwrap_or_default();
            eprint!("{}", json);
        }
    }

    if config.summary || config.dry_run {
        report::print_summary(&summary);
    }

    if config.fail_on_find && finding_count > 0 {
        Ok(EXIT_FINDINGS)
    } else {
        Ok(EXIT_SUCCESS)
    }
}

fn process_directory(
    dir_path: &Path,
    config: &Config,
    registry: &DetectorRegistry,
    except_rules: &[except::ExceptRule],
) -> errors::Result<i32> {
    // Directory mode requires --output, --in-place, --dry-run, --summary, or --report-json
    if config.output.is_none()
        && !config.in_place
        && !config.dry_run
        && !config.summary
        && !config.report_json
    {
        return Err(RedactError::Usage(
            "Directory input requires --output <DIR>, --in-place, --dry-run, --summary, or --report-json.\n  \
             redacted --input logs/ --output cleaned/\n  \
             redacted --input logs/ --in-place\n  \
             redacted --input logs/ --dry-run"
                .into(),
        ));
    }

    let traverse_config = traverse::TraverseConfig {
        include_hidden: config.include_hidden,
        follow_symlinks: config.follow_symlinks,
        max_file_size: config.max_file_size,
        ..Default::default()
    };

    let entries = traverse::collect_files(dir_path, &traverse_config)?;

    let mut results: Vec<FileResult> = Vec::new();
    let mut total_findings = 0;

    for entry in entries {
        match entry {
            traverse::FileEntry::Eligible { path, relative } => {
                let text = match read_file_with_mode(&path, config) {
                    Ok(t) => t,
                    Err(e) => {
                        let msg = e.to_string();
                        let is_binary = msg.contains("binary");
                        if is_binary && matches!(config.binary, BinaryMode::Skip) {
                            results.push(FileResult {
                                path: path.display().to_string(),
                                findings_count: 0,
                                findings: vec![],
                                status: FileStatus::Skipped("Binary file".into()),
                            });
                            continue;
                        }
                        if is_binary && matches!(config.binary, BinaryMode::Fail) {
                            results.push(FileResult {
                                path: path.display().to_string(),
                                findings_count: 0,
                                findings: vec![],
                                status: FileStatus::Error("Binary file".into()),
                            });
                            continue;
                        }
                        results.push(FileResult {
                            path: path.display().to_string(),
                            findings_count: 0,
                            findings: vec![],
                            status: FileStatus::Error(msg),
                        });
                        continue;
                    }
                };

                let decisions = decide_findings(&text, config, registry, except_rules);
                let reportable = reportable_findings(&decisions);
                let redactions = redacted_findings(&decisions);
                let finding_count = reportable.len();
                total_findings += finding_count;

                let reports: Vec<FindingReport> = reportable
                    .iter()
                    .map(|decision| {
                        report::finding_to_report(
                            &decision.finding,
                            &text,
                            action_name(decision.action),
                        )
                    })
                    .collect();

                // Write redacted output if not dry-run
                if !config.dry_run {
                    if let Some(ref out_dir) = config.output {
                        let redacted = redact::apply_redactions(
                            &text,
                            &redactions,
                            config.replacement.as_deref(),
                        );
                        let out_path = Path::new(out_dir).join(&relative);
                        io_safe::atomic_write(&out_path, &redacted)?;
                    } else if config.in_place {
                        let redacted = redact::apply_redactions(
                            &text,
                            &redactions,
                            config.replacement.as_deref(),
                        );
                        io_safe::atomic_write(&path, &redacted)?;
                    }
                }

                results.push(FileResult {
                    path: relative.display().to_string(),
                    findings_count: finding_count,
                    findings: reports,
                    status: FileStatus::Processed,
                });
            }
            traverse::FileEntry::Skipped { path, reason } => {
                results.push(FileResult {
                    path: path.display().to_string(),
                    findings_count: 0,
                    findings: vec![],
                    status: FileStatus::Skipped(reason),
                });
            }
        }
    }

    let summary = Summary::from_results(&results);

    if config.report_json || config.format == OutputFormat::Json {
        let mut buf = Vec::new();
        report::write_json_report(&results, &summary, &mut buf).map_err(RedactError::Io)?;
        let json = String::from_utf8(buf).unwrap_or_default();
        if config.format == OutputFormat::Json {
            io_safe::write_stdout(&json)?;
        } else {
            eprint!("{}", json);
        }
    }

    if config.summary || config.dry_run {
        report::print_summary(&summary);
    }

    // Always print minimal summary to stderr for directory mode
    if !config.summary && !config.dry_run && !config.report_json {
        eprintln!(
            "Processed {} files, {} findings, {} skipped",
            summary.files_processed, summary.total_findings, summary.files_skipped
        );
    }

    if config.fail_on_find && total_findings > 0 {
        Ok(EXIT_FINDINGS)
    } else {
        Ok(EXIT_SUCCESS)
    }
}
