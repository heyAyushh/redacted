use crate::cli::{
    print_external_detector_help, ExternalDetectorArgs, ExternalDetectorDefaultMode,
    ExternalDetectorHelpTopic, ExternalDetectorSubcommand,
};
use crate::detector::{Confidence, Finding};
use crate::errors::{RedactError, Result, EXIT_SUCCESS};
use crate::extension::{
    format_registry_fields, write_notice_if_needed, ExtensionDistribution, ExtensionKind,
    ExtensionLicenseMetadata,
};
use crate::io_safe;
use crate::{app_paths, app_paths::yes_or_no};
use std::collections::{HashMap, HashSet};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

const EXTERNAL_DETECTOR_SCHEMA_VERSION: u32 = 1;
const ACTIVE_DETECTORS_STATE_FILE: &str = "active-detectors.state";
const DEFAULT_DETECTORS_STATE_FILE: &str = "external-detectors-default.state";
const VERIFIED_DETECTOR_STATE_FILE: &str = "verified.state";
const DETECTOR_BUNDLE_MANIFEST_FILE: &str = "bundle.state";
const DETECTOR_BUNDLES_DIR: &str = "external-detectors";
const TRUFFLEHOG_ALIAS: &str = "trufflehog";
const TRUFFLEHOG_TARGET: &str = "trufflehog/secrets-v1";
const TRUFFLEHOG_ADAPTER: &str = "trufflehog-filesystem";
const TRUFFLEHOG_EXECUTABLE: &str = "trufflehog";
const TRUFFLEHOG_DETECTOR_NAME: &str = "TRUFFLEHOG_SECRET";
const TRUFFLEHOG_CATEGORY: &str = "secret";
const TRUFFLEHOG_STDERR_LIMIT: usize = 2048;
const TRUFFLEHOG_FILESYSTEM_KEY: &str = "Filesystem";
const TRUFFLEHOG_FILE_FIELD: &str = "file";
const UTF16_HIGH_SURROGATE_START: u32 = 0xD800;
const UTF16_HIGH_SURROGATE_END: u32 = 0xDBFF;
const UTF16_LOW_SURROGATE_START: u32 = 0xDC00;
const UTF16_LOW_SURROGATE_END: u32 = 0xDFFF;
const UTF16_SUPPLEMENTARY_OFFSET: u32 = 0x10000;
const JSON_TOP_LEVEL_OBJECT_DEPTH: usize = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ExternalDetectorCatalogEntry {
    target: &'static str,
    provider: &'static str,
    model: &'static str,
    aliases: &'static [&'static str],
    adapter: &'static str,
    executable_name: &'static str,
    detector_name: &'static str,
    category: &'static str,
    license: ExtensionLicenseMetadata,
}

const TRUFFLEHOG_ENTRY: ExternalDetectorCatalogEntry = ExternalDetectorCatalogEntry {
    target: TRUFFLEHOG_TARGET,
    provider: "trufflehog",
    model: "secrets-v1",
    aliases: &[TRUFFLEHOG_ALIAS],
    adapter: TRUFFLEHOG_ADAPTER,
    executable_name: TRUFFLEHOG_EXECUTABLE,
    detector_name: TRUFFLEHOG_DETECTOR_NAME,
    category: TRUFFLEHOG_CATEGORY,
    license: ExtensionLicenseMetadata {
        target: TRUFFLEHOG_TARGET,
        kind: ExtensionKind::Detector,
        source_url: "https://github.com/trufflesecurity/trufflehog/tree/main",
        license: "AGPL-3.0",
        distribution: ExtensionDistribution::ExternalBinary,
        bundled: false,
        network_default: false,
        notice: "TruffleHog is AGPL-3.0 and is used only as a local external binary; it is not vendored or linked into the MIT core.",
    },
};

const EXTERNAL_DETECTOR_CATALOG: [ExternalDetectorCatalogEntry; 1] = [TRUFFLEHOG_ENTRY];

#[derive(Debug, Clone)]
struct BundleManifest {
    schema_version: u32,
    target: String,
    adapter: String,
    executable_path: PathBuf,
    executable_sha256: String,
}

#[derive(Debug, Clone)]
struct ExternalDetectorRuntime {
    entry: &'static ExternalDetectorCatalogEntry,
    manifest: BundleManifest,
}

#[derive(Debug, Clone)]
pub struct ExternalDetectorSession {
    runtimes: Vec<ExternalDetectorRuntime>,
}

#[derive(Debug, Clone)]
pub struct ExternalDetectorDirectoryScan {
    secrets_by_path: HashMap<PathBuf, Vec<ExternalDetectorSecret>>,
}

#[derive(Debug, Clone)]
struct ExternalDetectorSecret {
    detector_name: &'static str,
    category: &'static str,
    raw: String,
}

#[derive(Debug, Clone)]
struct TruffleHogSecret {
    raw: String,
    path: Option<PathBuf>,
}

#[derive(Debug)]
struct InstallOutcome {
    installed_now: bool,
    bundle_root: PathBuf,
}

pub fn run_detector_command(args: &ExternalDetectorArgs) -> Result<i32> {
    if let Some(topic) = args.help.clone() {
        print_external_detector_help(topic);
        return Ok(EXIT_SUCCESS);
    }

    match args.command.as_ref() {
        Some(ExternalDetectorSubcommand::Install { selector }) => {
            let entry = resolve_catalog_entry(selector)?;
            write_notice_if_needed(entry.license)?;
            let outcome = install_target(entry)?;
            io_safe::write_stdout(&format!(
                "resolved target: {}\ninstalled: {}\nverified: yes\npath: {}\n",
                entry.target,
                if outcome.installed_now {
                    "yes"
                } else {
                    "already"
                },
                outcome.bundle_root.display()
            ))?;
        }
        Some(ExternalDetectorSubcommand::Use { selector }) => {
            let entry = resolve_catalog_entry(selector)?;
            write_notice_if_needed(entry.license)?;
            let bundle = bundle_root_for_entry(entry)?;
            ensure_ready_bundle(entry, &bundle)?;
            add_active_target(entry.target)?;
            io_safe::write_stdout(&format!(
                "resolved target: {}\nactive: yes\npath: {}\n",
                entry.target,
                bundle.display()
            ))?;
        }
        Some(ExternalDetectorSubcommand::Current) => {
            io_safe::write_stdout(&format_current_state()?)?;
        }
        Some(ExternalDetectorSubcommand::List) => {
            io_safe::write_stdout(&format_detector_list()?)?;
        }
        Some(ExternalDetectorSubcommand::Verify { selector, all }) => {
            if *all {
                verify_all_installed()?;
            } else {
                let entry = match selector.as_deref() {
                    Some(value) => resolve_catalog_entry(value)?,
                    None => {
                        let active = load_active_targets()?;
                        let target = active.first().ok_or_else(|| {
                            RedactError::Usage(
                                "No active external detector is configured.\n  redacted detector use trufflehog".into(),
                            )
                        })?;
                        find_catalog_entry_by_target(target).ok_or_else(|| {
                            RedactError::Usage(format!(
                                "Active external detector '{}' is not supported by this build.\n  redacted detector list",
                                target
                            ))
                        })?
                    }
                };
                let bundle = bundle_root_for_entry(entry)?;
                verify_bundle(entry, &bundle)?;
                io_safe::write_stdout(&format!(
                    "verified target: {}\npath: {}\n",
                    entry.target,
                    bundle.display()
                ))?;
            }
        }
        Some(ExternalDetectorSubcommand::Disable { selector, all }) => {
            if *all || selector.is_none() {
                let active = load_active_targets()?;
                clear_active_targets()?;
                if active.is_empty() {
                    io_safe::write_stdout("External detectors already disabled.\n")?;
                } else {
                    io_safe::write_stdout("disabled detectors: all\n")?;
                }
            } else if let Some(value) = selector.as_deref() {
                let entry = resolve_catalog_entry(value)?;
                let removed = remove_active_target(entry.target)?;
                io_safe::write_stdout(&format!(
                    "resolved target: {}\nactive: {}\n",
                    entry.target,
                    if removed {
                        "disabled"
                    } else {
                        "already disabled"
                    }
                ))?;
            }
        }
        Some(ExternalDetectorSubcommand::Default { mode }) => {
            let enabled = matches!(mode, ExternalDetectorDefaultMode::On);
            save_default_enabled(enabled)?;
            io_safe::write_stdout(&format!(
                "external detectors default: {}\n",
                if enabled { "on" } else { "off" }
            ))?;
        }
        None => {
            print_external_detector_help(ExternalDetectorHelpTopic::Root);
        }
    }

    Ok(EXIT_SUCCESS)
}

pub fn default_enabled() -> Result<bool> {
    let path = default_state_path()?;
    if !path.exists() {
        return Ok(false);
    }
    let values = app_paths::parse_key_value_file(&path, "external detector default")?;
    let enabled = values.get("enabled").map(String::as_str).unwrap_or("false");
    Ok(enabled == "true")
}

pub fn active_detectors_enabled(override_value: Option<bool>) -> Result<bool> {
    match override_value {
        Some(value) => Ok(value),
        None => default_enabled(),
    }
}

pub fn scan_enabled(
    override_value: Option<bool>,
    allow: &[String],
    deny: &[String],
) -> Result<bool> {
    if override_value == Some(true) {
        return Ok(true);
    }
    if !active_detectors_enabled(override_value)? {
        return Ok(false);
    }
    Ok(load_active_entries()?
        .iter()
        .any(|entry| detector_allowed(entry, allow, deny)))
}

pub fn start_scan_session() -> Result<ExternalDetectorSession> {
    let entries = load_active_entries()?;
    if entries.is_empty() {
        return Err(RedactError::Usage(
            "No active external detectors configured.\n  redacted detector install trufflehog\n  redacted detector use trufflehog".into(),
        ));
    }
    let mut runtimes = Vec::new();
    for entry in entries {
        let bundle = bundle_root_for_entry(entry)?;
        let manifest = ensure_ready_bundle(entry, &bundle)?;
        runtimes.push(ExternalDetectorRuntime { entry, manifest });
    }
    Ok(ExternalDetectorSession { runtimes })
}

pub fn detect_path_with_session(
    session: &ExternalDetectorSession,
    path: &Path,
    text: &str,
) -> Result<Vec<Finding>> {
    let mut findings = Vec::new();
    for runtime in &session.runtimes {
        match runtime.entry.adapter {
            TRUFFLEHOG_ADAPTER => {
                for secret in run_trufflehog(runtime.entry, &runtime.manifest, &[path])? {
                    findings.extend(find_secret_spans(
                        text,
                        &secret.raw,
                        runtime.entry.detector_name,
                        runtime.entry.category,
                    ));
                }
            }
            other => {
                return Err(RedactError::Detection(format!(
                    "External detector '{}' uses unsupported adapter '{}'.",
                    runtime.entry.target, other
                )));
            }
        }
    }
    Ok(findings)
}

pub fn detect_directory_with_session(
    session: &ExternalDetectorSession,
    scan_root: &Path,
    paths: &[PathBuf],
) -> Result<ExternalDetectorDirectoryScan> {
    let mut secrets_by_path: HashMap<PathBuf, Vec<ExternalDetectorSecret>> = HashMap::new();
    if paths.is_empty() {
        return Ok(ExternalDetectorDirectoryScan { secrets_by_path });
    }
    for runtime in &session.runtimes {
        match runtime.entry.adapter {
            TRUFFLEHOG_ADAPTER => {
                for secret in run_trufflehog(runtime.entry, &runtime.manifest, paths)? {
                    if let Some(path) = secret.path {
                        secrets_by_path
                            .entry(normalize_reported_path(scan_root, &path))
                            .or_default()
                            .push(ExternalDetectorSecret {
                                detector_name: runtime.entry.detector_name,
                                category: runtime.entry.category,
                                raw: secret.raw,
                            });
                    }
                }
            }
            other => {
                return Err(RedactError::Detection(format!(
                    "External detector '{}' uses unsupported adapter '{}'.",
                    runtime.entry.target, other
                )));
            }
        }
    }
    Ok(ExternalDetectorDirectoryScan { secrets_by_path })
}

pub fn detect_path_from_directory_scan(
    scan: &ExternalDetectorDirectoryScan,
    path: &Path,
    text: &str,
) -> Vec<Finding> {
    scan.secrets_by_path
        .get(path)
        .map(|secrets| {
            secrets
                .iter()
                .flat_map(|secret| {
                    find_secret_spans(text, &secret.raw, secret.detector_name, secret.category)
                })
                .collect()
        })
        .unwrap_or_default()
}

fn detector_allowed(
    entry: &ExternalDetectorCatalogEntry,
    allow: &[String],
    deny: &[String],
) -> bool {
    let detector_name = entry.detector_name;
    (allow.is_empty() || allow.iter().any(|name| name == detector_name))
        && !deny.iter().any(|name| name == detector_name)
}

pub fn findings_allowed(
    session: &ExternalDetectorSession,
    allow: &[String],
    deny: &[String],
) -> bool {
    session
        .runtimes
        .iter()
        .any(|runtime| detector_allowed(runtime.entry, allow, deny))
}

fn run_trufflehog(
    entry: &ExternalDetectorCatalogEntry,
    manifest: &BundleManifest,
    paths: &[impl AsRef<Path>],
) -> Result<Vec<TruffleHogSecret>> {
    let mut command = Command::new(&manifest.executable_path);
    command.arg("filesystem");
    for path in paths {
        command.arg(path.as_ref());
    }
    let output = command
        .arg("--json")
        .arg("--no-verification")
        .arg("--no-update")
        .arg("--no-color")
        .output()
        .map_err(|error| {
            RedactError::Detection(format!(
                "Failed to run external detector '{}': {}",
                entry.target, error
            ))
        })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(RedactError::Detection(format!(
            "External detector '{}' failed with exit code {}. Stderr is hidden to avoid leaking scanned text. Set REDACTED_DETECTOR_DEBUG=1 to show a truncated excerpt.{}",
            entry.target,
            output.status.code().unwrap_or(-1),
            debug_stderr_suffix(&stderr)
        )));
    }

    let stdout = String::from_utf8(output.stdout).map_err(|_| {
        RedactError::Detection(format!(
            "External detector '{}' returned non-UTF-8 JSON output.",
            entry.target
        ))
    })?;

    let mut secrets = Vec::new();
    for line in stdout.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Some(raw) = trufflehog_raw_secret(trimmed)? {
            secrets.push(TruffleHogSecret {
                raw,
                path: trufflehog_source_path(trimmed)?,
            });
        }
    }
    Ok(secrets)
}

fn debug_stderr_suffix(stderr: &str) -> String {
    if env::var("REDACTED_DETECTOR_DEBUG").ok().as_deref() != Some("1") {
        return String::new();
    }
    let mut output = String::from("\nTruncated stderr:\n");
    append_truncated(&mut output, stderr, TRUFFLEHOG_STDERR_LIMIT);
    output
}

fn append_truncated(output: &mut String, text: &str, limit_bytes: usize) {
    if output.len() >= limit_bytes {
        return;
    }
    let remaining = limit_bytes - output.len();
    if text.len() <= remaining {
        output.push_str(text);
        return;
    }
    let mut end = remaining;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    output.push_str(&text[..end]);
    output.push_str("\n...[truncated]");
}

fn trufflehog_raw_secret(line: &str) -> Result<Option<String>> {
    if let Some(value) = json_string_field(line, "RawV2")? {
        if !value.is_empty() {
            return Ok(Some(value));
        }
    }
    if let Some(value) = json_string_field(line, "Raw")? {
        if !value.is_empty() {
            return Ok(Some(value));
        }
    }
    Ok(None)
}

fn trufflehog_source_path(line: &str) -> Result<Option<PathBuf>> {
    Ok(
        json_string_field_in_object(line, TRUFFLEHOG_FILESYSTEM_KEY, TRUFFLEHOG_FILE_FIELD)?
            .filter(|path| !path.is_empty())
            .map(PathBuf::from),
    )
}

fn normalize_reported_path(scan_root: &Path, reported: &Path) -> PathBuf {
    if reported.is_absolute() {
        reported.to_path_buf()
    } else {
        scan_root.join(reported)
    }
}

fn find_secret_spans(
    text: &str,
    secret: &str,
    detector_name: &'static str,
    category: &'static str,
) -> Vec<Finding> {
    if secret.is_empty() {
        return Vec::new();
    }
    let mut findings = Vec::new();
    let mut offset = 0;
    while let Some(relative_start) = text[offset..].find(secret) {
        let start = offset + relative_start;
        let end = start + secret.len();
        findings.push(Finding {
            detector_name,
            category,
            start,
            end,
            confidence: Confidence::High,
            matched_len: end - start,
        });
        offset = end;
    }
    findings
}

fn json_string_field_in_object(
    line: &str,
    object_key: &str,
    field: &str,
) -> Result<Option<String>> {
    let bytes = line.as_bytes();
    let mut index = 0;

    while index < bytes.len() {
        match bytes[index] {
            b'"' => {
                let (key, next_index) = parse_json_string_with_end(line, index)?;
                let mut value_index = next_index;
                skip_json_ws(bytes, &mut value_index);
                if key == object_key && bytes.get(value_index) == Some(&b':') {
                    value_index += 1;
                    skip_json_ws(bytes, &mut value_index);
                    if bytes.get(value_index) == Some(&b'{') {
                        let end = json_container_end(line, value_index)?;
                        return json_string_field(&line[value_index..end], field);
                    }
                }
                index = next_index;
            }
            byte if byte < 0x20 && !matches!(byte, b'\n' | b'\r' | b'\t') => {
                return Err(RedactError::Detection(
                    "External detector JSON has an unescaped control character.".into(),
                ));
            }
            _ => {
                index += 1;
            }
        }
    }
    Ok(None)
}

fn json_container_end(line: &str, start: usize) -> Result<usize> {
    let bytes = line.as_bytes();
    let open = *bytes.get(start).ok_or_else(|| {
        RedactError::Detection("External detector JSON has missing container.".into())
    })?;
    match open {
        b'{' | b'[' => {}
        _ => {
            return Err(RedactError::Detection(
                "External detector JSON has invalid container.".into(),
            ));
        }
    };
    let mut depth = 0usize;
    let mut index = start;
    while index < bytes.len() {
        match bytes[index] {
            b'"' => {
                let (_, next_index) = parse_json_string_with_end(line, index)?;
                index = next_index;
            }
            b'{' | b'[' => {
                depth += 1;
                index += 1;
            }
            b'}' | b']' => {
                depth = depth.checked_sub(1).ok_or_else(|| {
                    RedactError::Detection("External detector JSON has unbalanced nesting.".into())
                })?;
                index += 1;
                if depth == 0 {
                    return Ok(index);
                }
            }
            _ => {
                index += 1;
            }
        }
    }
    Err(RedactError::Detection(
        "External detector JSON has unterminated container.".into(),
    ))
}

fn json_string_field(line: &str, field: &str) -> Result<Option<String>> {
    let bytes = line.as_bytes();
    let mut index = 0;
    let mut depth = 0usize;

    while index < bytes.len() {
        match bytes[index] {
            b'{' | b'[' => {
                depth += 1;
                index += 1;
            }
            b'}' | b']' => {
                depth = depth.checked_sub(1).ok_or_else(|| {
                    RedactError::Detection("External detector JSON has unbalanced nesting.".into())
                })?;
                index += 1;
            }
            b'"' => {
                let (key, next_index) = parse_json_string_with_end(line, index)?;
                let mut value_index = next_index;
                skip_json_ws(bytes, &mut value_index);
                if depth == JSON_TOP_LEVEL_OBJECT_DEPTH
                    && key == field
                    && bytes.get(value_index) == Some(&b':')
                {
                    value_index += 1;
                    skip_json_ws(bytes, &mut value_index);
                    return parse_json_string_value(line, field, value_index);
                }
                index = next_index;
            }
            byte if byte < 0x20 && !matches!(byte, b'\n' | b'\r' | b'\t') => {
                return Err(RedactError::Detection(
                    "External detector JSON has an unescaped control character.".into(),
                ));
            }
            _ => {
                index += 1;
            }
        }
    }
    Ok(None)
}

fn parse_json_string_value(line: &str, field: &str, index: usize) -> Result<Option<String>> {
    let bytes = line.as_bytes();
    if bytes.get(index) == Some(&b'n')
        && bytes.get(index..index + 4).map(|value| value == b"null") == Some(true)
    {
        return Ok(None);
    }
    if bytes.get(index) != Some(&b'"') {
        return Err(RedactError::Detection(format!(
            "External detector JSON field '{}' is not a string.",
            field
        )));
    }
    parse_json_string(line, index).map(Some)
}

fn parse_json_string(line: &str, quote_index: usize) -> Result<String> {
    parse_json_string_with_end(line, quote_index).map(|(value, _)| value)
}

fn parse_json_string_with_end(line: &str, quote_index: usize) -> Result<(String, usize)> {
    let bytes = line.as_bytes();
    let mut index = quote_index + 1;
    let mut output = String::new();
    let mut segment_start = index;

    while index < bytes.len() {
        match bytes[index] {
            b'"' => {
                output.push_str(&line[segment_start..index]);
                return Ok((output, index + 1));
            }
            b'\\' => {
                output.push_str(&line[segment_start..index]);
                index += 1;
                let escaped = bytes.get(index).copied().ok_or_else(|| {
                    RedactError::Detection("External detector JSON has invalid escape.".into())
                })?;
                match escaped {
                    b'"' => output.push('"'),
                    b'\\' => output.push('\\'),
                    b'/' => output.push('/'),
                    b'b' => output.push('\u{0008}'),
                    b'f' => output.push('\u{000c}'),
                    b'n' => output.push('\n'),
                    b'r' => output.push('\r'),
                    b't' => output.push('\t'),
                    b'u' => {
                        let value = parse_json_hex4(bytes, index + 1)?;
                        let scalar = if is_high_surrogate(value) {
                            let low_escape_index = index + 5;
                            if bytes.get(low_escape_index) != Some(&b'\\')
                                || bytes.get(low_escape_index + 1) != Some(&b'u')
                            {
                                return Err(RedactError::Detection(
                                    "External detector JSON has invalid unicode surrogate pair."
                                        .into(),
                                ));
                            }
                            let low = parse_json_hex4(bytes, low_escape_index + 2)?;
                            if !is_low_surrogate(low) {
                                return Err(RedactError::Detection(
                                    "External detector JSON has invalid unicode surrogate pair."
                                        .into(),
                                ));
                            }
                            index += 10;
                            UTF16_SUPPLEMENTARY_OFFSET
                                + (((value - UTF16_HIGH_SURROGATE_START) << 10)
                                    | (low - UTF16_LOW_SURROGATE_START))
                        } else if is_low_surrogate(value) {
                            return Err(RedactError::Detection(
                                "External detector JSON has unexpected low unicode surrogate."
                                    .into(),
                            ));
                        } else {
                            index += 4;
                            value
                        };
                        output.push(char::from_u32(scalar).ok_or_else(|| {
                            RedactError::Detection(
                                "External detector JSON has invalid unicode escape.".into(),
                            )
                        })?);
                    }
                    _ => {
                        return Err(RedactError::Detection(
                            "External detector JSON has invalid escape.".into(),
                        ));
                    }
                }
                index += 1;
                segment_start = index;
            }
            byte if byte < 0x20 => {
                return Err(RedactError::Detection(
                    "External detector JSON has an unescaped control character.".into(),
                ));
            }
            _ => {
                index += 1;
            }
        }
    }

    Err(RedactError::Detection(
        "External detector JSON has an unterminated string.".into(),
    ))
}

fn skip_json_ws(bytes: &[u8], index: &mut usize) {
    while matches!(bytes.get(*index), Some(b' ' | b'\n' | b'\r' | b'\t')) {
        *index += 1;
    }
}

fn is_high_surrogate(value: u32) -> bool {
    (UTF16_HIGH_SURROGATE_START..=UTF16_HIGH_SURROGATE_END).contains(&value)
}

fn is_low_surrogate(value: u32) -> bool {
    (UTF16_LOW_SURROGATE_START..=UTF16_LOW_SURROGATE_END).contains(&value)
}

fn parse_json_hex4(bytes: &[u8], start: usize) -> Result<u32> {
    let mut value = 0u32;
    for offset in 0..4 {
        let byte = *bytes.get(start + offset).ok_or_else(|| {
            RedactError::Detection("External detector JSON has short unicode escape.".into())
        })?;
        value = value * 16
            + match byte {
                b'0'..=b'9' => (byte - b'0') as u32,
                b'a'..=b'f' => (byte - b'a' + 10) as u32,
                b'A'..=b'F' => (byte - b'A' + 10) as u32,
                _ => {
                    return Err(RedactError::Detection(
                        "External detector JSON has invalid unicode escape.".into(),
                    ));
                }
            };
    }
    Ok(value)
}

fn install_target(entry: &ExternalDetectorCatalogEntry) -> Result<InstallOutcome> {
    let bundle = bundle_root_for_entry(entry)?;
    let installed_now = !is_bundle_installed(entry, &bundle)?;
    if installed_now {
        fs::create_dir_all(&bundle).map_err(|error| {
            RedactError::Config(format!(
                "Cannot create external detector directory '{}': {}",
                bundle.display(),
                error
            ))
        })?;
    }
    let executable = find_executable_in_path(entry.executable_name)?;
    let executable_sha256 = crate::provider::sha256_hex_of_path(&executable)?;
    let manifest = BundleManifest {
        schema_version: EXTERNAL_DETECTOR_SCHEMA_VERSION,
        target: entry.target.to_string(),
        adapter: entry.adapter.to_string(),
        executable_path: executable,
        executable_sha256,
    };
    write_bundle_manifest(&bundle.join(DETECTOR_BUNDLE_MANIFEST_FILE), &manifest)?;
    verify_bundle(entry, &bundle)?;
    Ok(InstallOutcome {
        installed_now,
        bundle_root: bundle,
    })
}

fn verify_all_installed() -> Result<()> {
    let mut verified_targets = Vec::new();
    for entry in &EXTERNAL_DETECTOR_CATALOG {
        let bundle = bundle_root_for_entry(entry)?;
        if is_bundle_installed(entry, &bundle)? {
            verify_bundle(entry, &bundle)?;
            verified_targets.push(entry.target);
        }
    }
    if verified_targets.is_empty() {
        io_safe::write_stdout("No installed external detectors found.\n")?;
    } else {
        let mut output = String::from("Verified external detectors:\n");
        for target in verified_targets {
            output.push_str("- ");
            output.push_str(target);
            output.push('\n');
        }
        io_safe::write_stdout(&output)?;
    }
    Ok(())
}

fn ensure_ready_bundle(
    entry: &ExternalDetectorCatalogEntry,
    bundle: &Path,
) -> Result<BundleManifest> {
    if !is_bundle_installed(entry, bundle)? {
        return Err(RedactError::Usage(format!(
            "External detector '{}' is not installed.\n  redacted detector install {}",
            entry.target, entry.provider
        )));
    }
    let manifest = read_bundle_manifest(&bundle.join(DETECTOR_BUNDLE_MANIFEST_FILE))?;
    if manifest.target != entry.target || manifest.adapter != entry.adapter {
        return Err(RedactError::Config(format!(
            "External detector '{}' metadata does not match the catalog.",
            entry.target
        )));
    }
    if !bundle.join(VERIFIED_DETECTOR_STATE_FILE).exists() {
        return Err(RedactError::Usage(format!(
            "External detector '{}' has not been verified yet.\n  redacted detector verify {}",
            entry.target, entry.provider
        )));
    }
    verify_manifest_executable(entry, &manifest)?;
    Ok(manifest)
}

fn verify_bundle(entry: &ExternalDetectorCatalogEntry, bundle: &Path) -> Result<()> {
    let manifest_path = bundle.join(DETECTOR_BUNDLE_MANIFEST_FILE);
    let manifest = read_bundle_manifest(&manifest_path)?;
    if manifest.schema_version != EXTERNAL_DETECTOR_SCHEMA_VERSION
        || manifest.target != entry.target
        || manifest.adapter != entry.adapter
    {
        return Err(RedactError::Config(format!(
            "External detector '{}' has invalid metadata.",
            entry.target
        )));
    }
    verify_manifest_executable(entry, &manifest)?;
    let verified_path = bundle.join(VERIFIED_DETECTOR_STATE_FILE);
    let verified_content = format!(
        "schema_version={}\ntarget={}\nverified_unix_seconds={}\n",
        EXTERNAL_DETECTOR_SCHEMA_VERSION,
        entry.target,
        app_paths::unix_timestamp_now()?
    );
    io_safe::atomic_write(&verified_path, &verified_content).map_err(|error| {
        RedactError::Config(format!(
            "Cannot write external detector verification state '{}': {}",
            verified_path.display(),
            error
        ))
    })?;
    Ok(())
}

fn verify_manifest_executable(
    entry: &ExternalDetectorCatalogEntry,
    manifest: &BundleManifest,
) -> Result<()> {
    ensure_manifest_executable_present(entry, manifest)?;
    let actual_sha256 = crate::provider::sha256_hex_of_path(&manifest.executable_path)?;
    if actual_sha256 != manifest.executable_sha256 {
        return Err(RedactError::Config(format!(
            "External detector '{}' failed executable integrity verification.",
            entry.target
        )));
    }
    Ok(())
}

fn ensure_manifest_executable_present(
    entry: &ExternalDetectorCatalogEntry,
    manifest: &BundleManifest,
) -> Result<()> {
    if !manifest.executable_path.is_file() {
        return Err(RedactError::Config(format!(
            "External detector '{}' executable '{}' is missing.",
            entry.target,
            manifest.executable_path.display()
        )));
    }
    Ok(())
}

fn find_executable_in_path(name: &str) -> Result<PathBuf> {
    app_paths::find_executable_in_path(name).ok_or_else(|| RedactError::Usage(format!(
        "Cannot find '{}' in PATH.\nInstall TruffleHog first, then run:\n  redacted detector install trufflehog",
        name
    )))
}

fn write_bundle_manifest(path: &Path, manifest: &BundleManifest) -> Result<()> {
    let content = format!(
        "schema_version={}\ntarget={}\nadapter={}\nexecutable_path={}\nexecutable_sha256={}\n",
        manifest.schema_version,
        manifest.target,
        manifest.adapter,
        manifest.executable_path.display(),
        manifest.executable_sha256
    );
    io_safe::atomic_write(path, &content).map_err(|error| {
        RedactError::Config(format!(
            "Cannot write external detector metadata '{}': {}",
            path.display(),
            error
        ))
    })
}

fn read_bundle_manifest(path: &Path) -> Result<BundleManifest> {
    let values = app_paths::parse_key_value_file(path, "external detector")?;
    Ok(BundleManifest {
        schema_version: app_paths::parse_required_u32(
            &values,
            "schema_version",
            path,
            "external detector",
        )?,
        target: app_paths::parse_required_value(&values, "target", path, "external detector")?,
        adapter: app_paths::parse_required_value(&values, "adapter", path, "external detector")?,
        executable_path: PathBuf::from(app_paths::parse_required_value(
            &values,
            "executable_path",
            path,
            "external detector",
        )?),
        executable_sha256: app_paths::parse_required_value(
            &values,
            "executable_sha256",
            path,
            "external detector",
        )?,
    })
}

fn format_current_state() -> Result<String> {
    let default = default_enabled()?;
    let active = load_active_targets()?;
    let mut output = format!(
        "external detectors default: {}\n",
        if default { "on" } else { "off" }
    );
    if active.is_empty() {
        output.push_str(
            "No active external detectors configured.\nSet one up with:\n  redacted detector install trufflehog\n  redacted detector use trufflehog\n",
        );
    } else {
        output.push_str("active detectors:\n");
        for target in active {
            output.push_str("- ");
            output.push_str(&target);
            output.push('\n');
        }
    }
    Ok(output)
}

fn format_detector_list() -> Result<String> {
    let active = load_active_targets()?;
    let mut output = String::from("External detectors:\n");
    for entry in &EXTERNAL_DETECTOR_CATALOG {
        let bundle = bundle_root_for_entry(entry)?;
        let installed = is_bundle_installed(entry, &bundle)?;
        let verified = installed && bundle.join(VERIFIED_DETECTOR_STATE_FILE).exists();
        let active = active.iter().any(|target| target == entry.target);
        output.push_str(&format!(
            "- {}  aliases={}  adapter={}  installed={}  verified={}  active={}  {}\n",
            entry.target,
            entry.aliases.join(","),
            entry.adapter,
            yes_or_no(installed),
            yes_or_no(verified),
            yes_or_no(active),
            format_registry_fields(entry.license)
        ));
    }
    Ok(output)
}

fn load_active_entries() -> Result<Vec<&'static ExternalDetectorCatalogEntry>> {
    let mut entries = Vec::new();
    for target in load_active_targets()? {
        let entry = find_catalog_entry_by_target(&target).ok_or_else(|| {
            RedactError::Usage(format!(
                "Active external detector '{}' is not supported by this build.\n  redacted detector list",
                target
            ))
        })?;
        entries.push(entry);
    }
    Ok(entries)
}

fn load_active_targets() -> Result<Vec<String>> {
    let path = active_state_path()?;
    if !path.exists() {
        return Ok(Vec::new());
    }
    let content = fs::read_to_string(&path).map_err(|error| {
        RedactError::Config(format!(
            "Cannot read active external detectors '{}': {}",
            path.display(),
            error
        ))
    })?;
    let mut targets = Vec::new();
    let mut seen = HashSet::new();
    for raw_line in content.lines() {
        let line = raw_line.trim();
        if let Some(target) = line.strip_prefix("target=") {
            if !target.is_empty() && seen.insert(target.to_string()) {
                targets.push(target.to_string());
            }
        }
    }
    Ok(targets)
}

fn add_active_target(target: &str) -> Result<()> {
    let mut active = load_active_targets()?;
    if !active.iter().any(|existing| existing == target) {
        active.push(target.to_string());
    }
    save_active_targets(&active)
}

fn remove_active_target(target: &str) -> Result<bool> {
    let mut active = load_active_targets()?;
    let original_len = active.len();
    active.retain(|existing| existing != target);
    save_active_targets(&active)?;
    Ok(active.len() != original_len)
}

fn clear_active_targets() -> Result<()> {
    let path = active_state_path()?;
    if !path.exists() {
        return Ok(());
    }
    fs::remove_file(&path).map_err(|error| {
        RedactError::Config(format!(
            "Cannot remove active external detectors '{}': {}",
            path.display(),
            error
        ))
    })
}

fn save_active_targets(targets: &[String]) -> Result<()> {
    if targets.is_empty() {
        return clear_active_targets();
    }
    let path = active_state_path()?;
    let parent = path.parent().ok_or_else(|| {
        RedactError::Config(format!(
            "Cannot determine parent for active external detector state '{}'.",
            path.display()
        ))
    })?;
    fs::create_dir_all(parent).map_err(|error| {
        RedactError::Config(format!(
            "Cannot create config directory '{}': {}",
            parent.display(),
            error
        ))
    })?;
    let mut content = format!("schema_version={}\n", EXTERNAL_DETECTOR_SCHEMA_VERSION);
    for target in targets {
        content.push_str("target=");
        content.push_str(target);
        content.push('\n');
    }
    io_safe::atomic_write(&path, &content).map_err(|error| {
        RedactError::Config(format!(
            "Cannot write active external detectors '{}': {}",
            path.display(),
            error
        ))
    })
}

fn save_default_enabled(enabled: bool) -> Result<()> {
    let path = default_state_path()?;
    let parent = path.parent().ok_or_else(|| {
        RedactError::Config(format!(
            "Cannot determine parent for external detector default '{}'.",
            path.display()
        ))
    })?;
    fs::create_dir_all(parent).map_err(|error| {
        RedactError::Config(format!(
            "Cannot create config directory '{}': {}",
            parent.display(),
            error
        ))
    })?;
    let content = format!(
        "schema_version={}\nenabled={}\n",
        EXTERNAL_DETECTOR_SCHEMA_VERSION,
        if enabled { "true" } else { "false" }
    );
    io_safe::atomic_write(&path, &content).map_err(|error| {
        RedactError::Config(format!(
            "Cannot write external detector default '{}': {}",
            path.display(),
            error
        ))
    })
}

fn is_bundle_installed(entry: &ExternalDetectorCatalogEntry, bundle: &Path) -> Result<bool> {
    if !bundle.exists() {
        return Ok(false);
    }
    let manifest_path = bundle.join(DETECTOR_BUNDLE_MANIFEST_FILE);
    if !manifest_path.exists() {
        return Ok(false);
    }
    let manifest = read_bundle_manifest(&manifest_path)?;
    Ok(manifest.target == entry.target && manifest.adapter == entry.adapter)
}

fn resolve_catalog_entry(selector: &str) -> Result<&'static ExternalDetectorCatalogEntry> {
    if let Some(entry) = find_catalog_entry_by_target(selector) {
        return Ok(entry);
    }
    let matches: Vec<&ExternalDetectorCatalogEntry> = EXTERNAL_DETECTOR_CATALOG
        .iter()
        .filter(|entry| entry.aliases.iter().any(|alias| alias == &selector))
        .collect();
    if matches.len() == 1 {
        return Ok(matches[0]);
    }
    if matches.is_empty() {
        return Err(RedactError::Usage(format!(
            "Unknown external detector '{}'.\n  redacted detector list",
            selector
        )));
    }
    Err(RedactError::Usage(format!(
        "External detector alias '{}' is ambiguous.\n  redacted detector list",
        selector
    )))
}

fn find_catalog_entry_by_target(target: &str) -> Option<&'static ExternalDetectorCatalogEntry> {
    EXTERNAL_DETECTOR_CATALOG
        .iter()
        .find(|entry| entry.target == target)
}

fn bundle_root_for_entry(entry: &ExternalDetectorCatalogEntry) -> Result<PathBuf> {
    Ok(detectors_root()?.join(entry.provider).join(entry.model))
}

fn detectors_root() -> Result<PathBuf> {
    Ok(app_paths::data_root()?.join(DETECTOR_BUNDLES_DIR))
}

fn active_state_path() -> Result<PathBuf> {
    Ok(app_paths::config_root()?.join(ACTIVE_DETECTORS_STATE_FILE))
}

fn default_state_path() -> Result<PathBuf> {
    Ok(app_paths::config_root()?.join(DEFAULT_DETECTORS_STATE_FILE))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_string_field_reads_escaped_value() {
        let line = r#"{"DetectorName":"x","Raw":"sk_live_\u0031\nnext"}"#;
        assert_eq!(
            json_string_field(line, "Raw").unwrap(),
            Some("sk_live_1\nnext".to_string())
        );
    }

    #[test]
    fn json_string_field_reads_surrogate_pairs() {
        let line = r#"{"Raw":"token-\uD83D\uDE00"}"#;
        assert_eq!(
            json_string_field(line, "Raw").unwrap(),
            Some("token-😀".to_string())
        );
    }

    #[test]
    fn json_string_field_ignores_nested_keys() {
        let line = r#"{"SourceMetadata":{"Data":{"Raw":"nested"}},"Raw":"top-level"}"#;
        assert_eq!(
            json_string_field(line, "Raw").unwrap(),
            Some("top-level".to_string())
        );
    }

    #[test]
    fn json_string_field_rejects_unpaired_surrogate() {
        let line = r#"{"Raw":"token-\uD83D"}"#;
        let error = json_string_field(line, "Raw").unwrap_err();
        assert!(error.to_string().contains("invalid unicode surrogate pair"));
    }

    #[test]
    fn secret_spans_use_byte_offsets() {
        let text = "é token abc token abc";
        let findings =
            find_secret_spans(text, "token", TRUFFLEHOG_DETECTOR_NAME, TRUFFLEHOG_CATEGORY);
        assert_eq!(findings.len(), 2);
        assert_eq!((findings[0].start, findings[0].end), (3, 8));
        assert_eq!((findings[1].start, findings[1].end), (13, 18));
    }

    #[test]
    fn trufflehog_source_path_reads_filesystem_metadata() {
        let line =
            r#"{"SourceMetadata":{"Data":{"Filesystem":{"file":"repo/a.txt"}}},"Raw":"secret"}"#;
        assert_eq!(
            trufflehog_source_path(line).unwrap(),
            Some(PathBuf::from("repo/a.txt"))
        );
    }

    #[test]
    fn trufflehog_source_path_ignores_missing_filesystem_metadata() {
        let line = r#"{"SourceMetadata":{"Data":{"Git":{"file":"repo/a.txt"}}},"Raw":"secret"}"#;
        assert_eq!(trufflehog_source_path(line).unwrap(), None);
    }
}
