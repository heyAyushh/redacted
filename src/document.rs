use crate::cli::{print_document_help, DocumentArgs, DocumentHelpTopic, DocumentSubcommand};
use crate::errors::{RedactError, Result, EXIT_SUCCESS};
use crate::io_safe;
use crate::{app_paths, app_paths::yes_or_no};
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

const DOCUMENT_SCHEMA_VERSION: u32 = 1;
const ACTIVE_DOCUMENT_STATE_FILE: &str = "active-document-adapter.state";
const VERIFIED_DOCUMENT_STATE_FILE: &str = "verified.state";
const DOCUMENT_BUNDLE_MANIFEST_FILE: &str = "bundle.state";
const DOCUMENT_BUNDLES_DIR: &str = "document-adapters";
const DOCUMENT_RUNNER_DIR: &str = "runner";

const PDF_INSPECTOR_ALIAS: &str = "pdf-inspector";
const PDF_INSPECTOR_TARGET: &str = "pdf-inspector/local-v1";
const PDF_INSPECTOR_ADAPTER: &str = "pdftotext-local";
const PDF_INSPECTOR_RUNNER_NAME: &str = "pdf_inspector_runner.py";

const PDF_INSPECTOR_RUNNER_SCRIPT: &str = r#"#!/usr/bin/env python3
import argparse
import pathlib
import subprocess
import sys


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", required=True)
    parser.add_argument("--input", required=True)
    args = parser.parse_args()

    input_path = pathlib.Path(args.input)
    if not input_path.is_file():
        sys.stderr.write("input is not a file\n")
        return 2

    # pdftotext writes extracted text to stdout when output path is '-'
    command = [
        "pdftotext",
        "-q",
        "-enc",
        "UTF-8",
        str(input_path),
        "-",
    ]
    completed = subprocess.run(command, capture_output=True)
    if completed.returncode != 0:
        sys.stderr.write("pdftotext failed\n")
        return 3
    sys.stdout.buffer.write(completed.stdout)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
"#;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DocumentCatalogEntry {
    target: &'static str,
    provider: &'static str,
    model: &'static str,
    aliases: &'static [&'static str],
    adapter: &'static str,
    runner_name: &'static str,
}

const PDF_INSPECTOR_ENTRY: DocumentCatalogEntry = DocumentCatalogEntry {
    target: PDF_INSPECTOR_TARGET,
    provider: "pdf-inspector",
    model: "local-v1",
    aliases: &[PDF_INSPECTOR_ALIAS],
    adapter: PDF_INSPECTOR_ADAPTER,
    runner_name: PDF_INSPECTOR_RUNNER_NAME,
};

const DOCUMENT_CATALOG: [DocumentCatalogEntry; 1] = [PDF_INSPECTOR_ENTRY];

#[derive(Debug)]
pub struct DocumentSession {
    entry: &'static DocumentCatalogEntry,
    runner_path: PathBuf,
}

#[derive(Debug)]
struct BundleManifest {
    schema_version: u32,
    target: String,
    adapter: String,
    runner_rel: String,
}

#[derive(Debug)]
struct VerifiedState {
    schema_version: u32,
    target: String,
    verified_unix_seconds: u64,
}

#[derive(Debug)]
struct ActiveDocumentState {
    target: String,
}

#[derive(Debug)]
struct InstallOutcome {
    installed_now: bool,
    bundle_root: PathBuf,
}

pub fn run_document_command(args: &DocumentArgs) -> Result<i32> {
    if let Some(topic) = args.help.clone() {
        print_document_help(topic);
        return Ok(EXIT_SUCCESS);
    }

    match args.command.as_ref() {
        Some(DocumentSubcommand::Enable { selector }) => {
            let entry = resolve_catalog_entry(selector)?;
            let bundle = bundle_root_for_entry(entry)?;
            let installed_now = if is_bundle_installed(entry, &bundle)? {
                if !has_verified_state(&bundle)? {
                    verify_bundle(entry, &bundle)?;
                }
                false
            } else {
                install_target(entry)?.installed_now
            };
            ensure_ready_bundle(entry, &bundle)?;
            activate_target(entry)?;
            let output = format!(
                "resolved target: {}\ninstalled: {}\nverified: yes\nactive: yes\npath: {}\n",
                entry.target,
                if installed_now { "yes" } else { "already" },
                bundle.display()
            );
            io_safe::write_stdout(&output)?;
        }
        Some(DocumentSubcommand::Install { selector }) => {
            let entry = resolve_catalog_entry(selector)?;
            let outcome = install_target(entry)?;
            let output = format!(
                "resolved target: {}\ninstalled: {}\nverified: yes\npath: {}\n",
                entry.target,
                if outcome.installed_now {
                    "yes"
                } else {
                    "already"
                },
                outcome.bundle_root.display()
            );
            io_safe::write_stdout(&output)?;
        }
        Some(DocumentSubcommand::Use { selector }) => {
            let entry = resolve_catalog_entry(selector)?;
            let bundle = bundle_root_for_entry(entry)?;
            ensure_ready_bundle(entry, &bundle)?;
            activate_target(entry)?;
            let output = format!(
                "resolved target: {}\nactive: yes\npath: {}\n",
                entry.target,
                bundle.display()
            );
            io_safe::write_stdout(&output)?;
        }
        Some(DocumentSubcommand::Current) => {
            if let Some(state) = load_active_state()? {
                if let Some(entry) = find_catalog_entry_by_target(&state.target) {
                    let output = format!(
                        "active target: {}\nadapter: {}\nsupport: supported\n",
                        entry.target, entry.adapter
                    );
                    io_safe::write_stdout(&output)?;
                } else {
                    io_safe::write_stdout(&format!("active target: {}\n", state.target))?;
                }
            } else {
                io_safe::write_stdout(
                    "No active document adapter configured.\nSet one up with:\n  redacted document enable pdf-inspector\n",
                )?;
            }
        }
        Some(DocumentSubcommand::List) => {
            io_safe::write_stdout(&format_document_list()?)?;
        }
        Some(DocumentSubcommand::Verify { selector, all }) => {
            if *all {
                let mut verified_targets = Vec::new();
                for entry in &DOCUMENT_CATALOG {
                    let bundle = bundle_root_for_entry(entry)?;
                    if is_bundle_installed(entry, &bundle)? {
                        verify_bundle(entry, &bundle)?;
                        verified_targets.push(entry.target);
                    }
                }
                if verified_targets.is_empty() {
                    io_safe::write_stdout("No installed document adapters found.\n")?;
                } else {
                    let mut output = String::from("Verified document adapters:\n");
                    for target in verified_targets {
                        output.push_str("- ");
                        output.push_str(target);
                        output.push('\n');
                    }
                    io_safe::write_stdout(&output)?;
                }
            } else {
                let entry = match selector.as_deref() {
                    Some(value) => resolve_catalog_entry(value)?,
                    None => {
                        let active = load_active_state()?.ok_or_else(|| {
                            RedactError::Usage(
                                "No active document adapter is configured.\n  redacted document enable pdf-inspector".into(),
                            )
                        })?;
                        find_catalog_entry_by_target(&active.target).ok_or_else(|| {
                            RedactError::Usage(format!(
                                "Active document adapter '{}' is not supported by this build.\n  redacted document list",
                                active.target
                            ))
                        })?
                    }
                };
                let bundle = bundle_root_for_entry(entry)?;
                verify_bundle(entry, &bundle)?;
                let output = format!(
                    "verified target: {}\npath: {}\n",
                    entry.target,
                    bundle.display()
                );
                io_safe::write_stdout(&output)?;
            }
        }
        Some(DocumentSubcommand::Disable) => {
            if let Some(state) = load_active_state()? {
                clear_active_state()?;
                io_safe::write_stdout(&format!("disabled adapter: {}\n", state.target))?;
            } else {
                io_safe::write_stdout("Document adapter already disabled.\n")?;
            }
        }
        None => {
            print_document_help(DocumentHelpTopic::Root);
        }
    }

    Ok(EXIT_SUCCESS)
}

pub fn start_active_session() -> Result<DocumentSession> {
    let active = load_active_state()?.ok_or_else(|| {
        RedactError::Usage(
            "No active document adapter is configured.\n  redacted document enable pdf-inspector\n  redacted document list".into(),
        )
    })?;
    let entry = find_catalog_entry_by_target(&active.target).ok_or_else(|| {
        RedactError::Usage(format!(
            "Active document adapter '{}' is not supported by this build.\n  redacted document list",
            active.target
        ))
    })?;
    let bundle = bundle_root_for_entry(entry)?;
    ensure_ready_bundle(entry, &bundle)?;
    let manifest = load_bundle_manifest(&bundle_manifest_path(&bundle))?;
    Ok(DocumentSession {
        entry,
        runner_path: bundle.join(manifest.runner_rel),
    })
}

pub fn supports_path(path: &Path) -> bool {
    path.extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| ext.eq_ignore_ascii_case("pdf"))
        .unwrap_or(false)
}

pub fn extract_with_session(session: &mut DocumentSession, path: &Path) -> Result<String> {
    if !supports_path(path) {
        return Err(RedactError::Usage(format!(
            "Document adapter '{}' does not support '{}'.",
            session.entry.target,
            path.display()
        )));
    }
    let output = Command::new(&session.runner_path)
        .arg("--target")
        .arg(session.entry.target)
        .arg("--input")
        .arg(path)
        .output()
        .map_err(|error| {
            RedactError::Detection(format!(
                "Failed to run document adapter '{}': {}",
                session.entry.target, error
            ))
        })?;

    if !output.status.success() {
        return Err(RedactError::Detection(format!(
            "Document adapter '{}' failed on '{}'.",
            session.entry.target,
            path.display()
        )));
    }

    String::from_utf8(output.stdout).map_err(|_| {
        RedactError::Detection(format!(
            "Document adapter '{}' returned invalid UTF-8 output.",
            session.entry.target
        ))
    })
}

fn install_target(entry: &'static DocumentCatalogEntry) -> Result<InstallOutcome> {
    let bundle_root = bundle_root_for_entry(entry)?;
    if is_bundle_installed(entry, &bundle_root)? {
        if !has_verified_state(&bundle_root)? {
            verify_bundle(entry, &bundle_root)?;
        }
        return Ok(InstallOutcome {
            installed_now: false,
            bundle_root,
        });
    }

    let adapters_root = adapters_root()?;
    fs::create_dir_all(&adapters_root).map_err(|error| {
        RedactError::Config(format!(
            "Cannot create document adapter directory '{}': {}",
            adapters_root.display(),
            error
        ))
    })?;

    let temp_bundle = temp_bundle_path(entry)?;
    if temp_bundle.exists() {
        fs::remove_dir_all(&temp_bundle).map_err(|error| {
            RedactError::Config(format!(
                "Cannot clear temporary document adapter directory '{}': {}",
                temp_bundle.display(),
                error
            ))
        })?;
    }
    fs::create_dir_all(&temp_bundle).map_err(|error| {
        RedactError::Config(format!(
            "Cannot create temporary document adapter directory '{}': {}",
            temp_bundle.display(),
            error
        ))
    })?;

    let install_result = match entry.target {
        PDF_INSPECTOR_TARGET => install_pdf_inspector_bundle(entry, &temp_bundle),
        _ => Err(RedactError::Usage(format!(
            "Unknown document adapter target '{}'.",
            entry.target
        ))),
    };

    if let Err(error) = install_result {
        let _ = fs::remove_dir_all(&temp_bundle);
        return Err(error);
    }

    let parent = bundle_root.parent().ok_or_else(|| {
        RedactError::Config(format!(
            "Cannot determine document adapter parent for '{}'.",
            bundle_root.display()
        ))
    })?;
    fs::create_dir_all(parent).map_err(|error| {
        RedactError::Config(format!(
            "Cannot create document adapter parent '{}': {}",
            parent.display(),
            error
        ))
    })?;
    fs::rename(&temp_bundle, &bundle_root).map_err(|error| {
        let _ = fs::remove_dir_all(&temp_bundle);
        RedactError::Config(format!(
            "Cannot move document adapter into place '{}': {}",
            bundle_root.display(),
            error
        ))
    })?;

    verify_bundle(entry, &bundle_root)?;

    Ok(InstallOutcome {
        installed_now: true,
        bundle_root,
    })
}

fn install_pdf_inspector_bundle(entry: &DocumentCatalogEntry, temp_bundle: &Path) -> Result<()> {
    let runner_dir = temp_bundle.join(DOCUMENT_RUNNER_DIR);
    fs::create_dir_all(&runner_dir).map_err(|error| {
        RedactError::Config(format!(
            "Cannot create runner directory '{}': {}",
            runner_dir.display(),
            error
        ))
    })?;
    let runner_path = runner_dir.join(entry.runner_name);
    io_safe::atomic_write(&runner_path, PDF_INSPECTOR_RUNNER_SCRIPT)?;
    #[cfg(unix)]
    {
        fs::set_permissions(&runner_path, fs::Permissions::from_mode(0o755)).map_err(|error| {
            RedactError::Config(format!(
                "Cannot mark document runner executable '{}': {}",
                runner_path.display(),
                error
            ))
        })?;
    }

    let manifest = BundleManifest {
        schema_version: DOCUMENT_SCHEMA_VERSION,
        target: entry.target.to_string(),
        adapter: entry.adapter.to_string(),
        runner_rel: Path::new(DOCUMENT_RUNNER_DIR)
            .join(entry.runner_name)
            .to_string_lossy()
            .into_owned(),
    };
    save_bundle_manifest(temp_bundle, &manifest)?;
    Ok(())
}

fn verify_bundle(entry: &'static DocumentCatalogEntry, bundle_root: &Path) -> Result<()> {
    if !bundle_root.exists() {
        return Err(RedactError::Usage(format!(
            "Document adapter '{}' is not installed.\n  redacted document install {}",
            entry.target, entry.target
        )));
    }
    let manifest = load_bundle_manifest(&bundle_manifest_path(bundle_root))?;
    if manifest.schema_version != DOCUMENT_SCHEMA_VERSION
        || manifest.target != entry.target
        || manifest.adapter != entry.adapter
    {
        return Err(RedactError::Config(format!(
            "Document adapter '{}' has invalid metadata.",
            entry.target
        )));
    }
    let runner_path = bundle_root.join(&manifest.runner_rel);
    if !runner_path.is_file() {
        return Err(RedactError::Config(format!(
            "Document adapter '{}' is missing runner '{}'.",
            entry.target,
            runner_path.display()
        )));
    }
    let runner_bytes = fs::read(&runner_path).map_err(|error| {
        RedactError::Config(format!(
            "Cannot read document runner '{}': {}",
            runner_path.display(),
            error
        ))
    })?;
    if runner_bytes != PDF_INSPECTOR_RUNNER_SCRIPT.as_bytes() {
        return Err(RedactError::Config(format!(
            "Document adapter '{}' failed integrity verification.",
            entry.target
        )));
    }
    ensure_pdftotext_available()?;
    save_verified_state(
        bundle_root,
        &VerifiedState {
            schema_version: DOCUMENT_SCHEMA_VERSION,
            target: entry.target.into(),
            verified_unix_seconds: app_paths::unix_timestamp_now()?,
        },
    )?;
    Ok(())
}

fn ensure_ready_bundle(entry: &'static DocumentCatalogEntry, bundle_root: &Path) -> Result<()> {
    if !is_bundle_installed(entry, bundle_root)? {
        return Err(RedactError::Usage(format!(
            "Document adapter '{}' is not installed.\n  redacted document enable {}",
            entry.target, entry.provider
        )));
    }
    if !has_verified_state(bundle_root)? {
        return Err(RedactError::Usage(format!(
            "Document adapter '{}' has not been verified yet.\n  redacted document verify {}",
            entry.target, entry.provider
        )));
    }
    let manifest = load_bundle_manifest(&bundle_manifest_path(bundle_root))?;
    if manifest.target != entry.target || manifest.adapter != entry.adapter {
        return Err(RedactError::Config(format!(
            "Document adapter '{}' metadata does not match the catalog.",
            entry.target
        )));
    }
    let runner_path = bundle_root.join(&manifest.runner_rel);
    if !runner_path.exists() {
        return Err(RedactError::Config(format!(
            "Document adapter '{}' is missing runner '{}'.",
            entry.target,
            runner_path.display()
        )));
    }
    ensure_pdftotext_available()?;
    Ok(())
}

fn ensure_pdftotext_available() -> Result<()> {
    match Command::new("pdftotext").arg("-v").output() {
        Ok(_) => Ok(()),
        Err(error) => Err(RedactError::Usage(format!(
            "Document adapter '{}' requires 'pdftotext' in PATH.\nInstall poppler, then run:\n  redacted document verify {}\nUnderlying error: {}",
            PDF_INSPECTOR_TARGET, PDF_INSPECTOR_ALIAS, error
        ))),
    }
}

fn format_document_list() -> Result<String> {
    let active_target = load_active_state()?.map(|state| state.target);
    let mut output = String::new();
    output.push_str("Aliases:\n");
    for entry in &DOCUMENT_CATALOG {
        for alias in entry.aliases {
            output.push_str(&format!("- {} -> {}\n", alias, entry.target));
        }
    }
    output.push_str("Targets:\n");
    for entry in &DOCUMENT_CATALOG {
        let bundle = bundle_root_for_entry(entry)?;
        let installed = is_bundle_installed(entry, &bundle)?;
        let verified = if installed {
            has_verified_state(&bundle)?
        } else {
            false
        };
        let active = active_target
            .as_ref()
            .map(|target| target == entry.target)
            .unwrap_or(false);
        output.push_str(&format!(
            "- {}  adapter={}  support=supported  installed={}  verified={}  active={}\n",
            entry.target,
            entry.adapter,
            yes_or_no(installed),
            yes_or_no(verified),
            yes_or_no(active),
        ));
    }
    Ok(output)
}

fn resolve_catalog_entry(selector: &str) -> Result<&'static DocumentCatalogEntry> {
    if selector.contains('/') {
        return find_catalog_entry_by_target(selector).ok_or_else(|| {
            RedactError::Usage(format!(
                "Unknown document adapter target '{}'.\n  redacted document list",
                selector
            ))
        });
    }

    let matches: Vec<_> = DOCUMENT_CATALOG
        .iter()
        .filter(|entry| entry.aliases.iter().any(|alias| alias == &selector))
        .collect();
    match matches.as_slice() {
        [] => Err(RedactError::Usage(format!(
            "Unknown document adapter alias '{}'.\n  redacted document list",
            selector
        ))),
        [entry] => Ok(entry),
        _ => Err(RedactError::Usage(format!(
            "Document adapter alias '{}' is ambiguous.\n  redacted document list",
            selector
        ))),
    }
}

fn find_catalog_entry_by_target(target: &str) -> Option<&'static DocumentCatalogEntry> {
    DOCUMENT_CATALOG.iter().find(|entry| entry.target == target)
}

fn activate_target(entry: &DocumentCatalogEntry) -> Result<()> {
    let config_dir = app_paths::config_root()?;
    fs::create_dir_all(&config_dir).map_err(|error| {
        RedactError::Config(format!(
            "Cannot create document config directory '{}': {}",
            config_dir.display(),
            error
        ))
    })?;
    save_active_state(&ActiveDocumentState {
        target: entry.target.into(),
    })
}

fn clear_active_state() -> Result<()> {
    let path = active_state_path()?;
    if path.exists() {
        fs::remove_file(&path).map_err(|error| {
            RedactError::Config(format!(
                "Cannot remove active document adapter state '{}': {}",
                path.display(),
                error
            ))
        })?;
    }
    Ok(())
}

fn save_active_state(state: &ActiveDocumentState) -> Result<()> {
    let path = active_state_path()?;
    let content = format!("target={}\n", state.target);
    io_safe::atomic_write(&path, &content)?;
    Ok(())
}

fn load_active_state() -> Result<Option<ActiveDocumentState>> {
    let path = active_state_path()?;
    if !path.exists() {
        return Ok(None);
    }
    let values = app_paths::parse_key_value_file(&path, "document")?;
    let target = app_paths::parse_required_value(&values, "target", &path, "document")?;
    Ok(Some(ActiveDocumentState { target }))
}

fn save_bundle_manifest(bundle_root: &Path, manifest: &BundleManifest) -> Result<()> {
    let path = bundle_manifest_path(bundle_root);
    let mut content = String::new();
    content.push_str(&format!("schema_version={}\n", manifest.schema_version));
    content.push_str(&format!("target={}\n", manifest.target));
    content.push_str(&format!("adapter={}\n", manifest.adapter));
    content.push_str(&format!("runner_rel={}\n", manifest.runner_rel));
    io_safe::atomic_write(&path, &content)?;
    Ok(())
}

fn load_bundle_manifest(path: &Path) -> Result<BundleManifest> {
    let values = app_paths::parse_key_value_file(path, "document")?;
    let schema_version =
        app_paths::parse_required_u32(&values, "schema_version", path, "document")?;
    Ok(BundleManifest {
        schema_version,
        target: app_paths::parse_required_value(&values, "target", path, "document")?,
        adapter: app_paths::parse_required_value(&values, "adapter", path, "document")?,
        runner_rel: app_paths::parse_required_value(&values, "runner_rel", path, "document")?,
    })
}

fn save_verified_state(bundle_root: &Path, state: &VerifiedState) -> Result<()> {
    let path = verified_state_path(bundle_root);
    let mut content = String::new();
    content.push_str(&format!("schema_version={}\n", state.schema_version));
    content.push_str(&format!("target={}\n", state.target));
    content.push_str(&format!(
        "verified_unix_seconds={}\n",
        state.verified_unix_seconds
    ));
    io_safe::atomic_write(&path, &content)?;
    Ok(())
}

fn has_verified_state(bundle_root: &Path) -> Result<bool> {
    let path = verified_state_path(bundle_root);
    if !path.exists() {
        return Ok(false);
    }
    let values = app_paths::parse_key_value_file(&path, "document")?;
    let schema_version =
        app_paths::parse_required_u32(&values, "schema_version", &path, "document")?;
    let target = app_paths::parse_required_value(&values, "target", &path, "document")?;
    Ok(
        schema_version == DOCUMENT_SCHEMA_VERSION
            && find_catalog_entry_by_target(&target).is_some(),
    )
}

fn is_bundle_installed(entry: &DocumentCatalogEntry, bundle_root: &Path) -> Result<bool> {
    if !bundle_root.exists() {
        return Ok(false);
    }
    let manifest_path = bundle_manifest_path(bundle_root);
    if !manifest_path.exists() {
        return Ok(false);
    }
    let manifest = load_bundle_manifest(&manifest_path)?;
    Ok(manifest.target == entry.target && manifest.adapter == entry.adapter)
}

fn active_state_path() -> Result<PathBuf> {
    Ok(app_paths::config_root()?.join(ACTIVE_DOCUMENT_STATE_FILE))
}

fn bundle_manifest_path(bundle_root: &Path) -> PathBuf {
    bundle_root.join(DOCUMENT_BUNDLE_MANIFEST_FILE)
}

fn verified_state_path(bundle_root: &Path) -> PathBuf {
    bundle_root.join(VERIFIED_DOCUMENT_STATE_FILE)
}

fn bundle_root_for_entry(entry: &DocumentCatalogEntry) -> Result<PathBuf> {
    Ok(adapters_root()?.join(entry.provider).join(entry.model))
}

fn temp_bundle_path(entry: &DocumentCatalogEntry) -> Result<PathBuf> {
    let now = app_paths::unix_timestamp_now()?;
    Ok(adapters_root()?.join(format!(".tmp-{}-{}-{}", entry.provider, entry.model, now)))
}

fn adapters_root() -> Result<PathBuf> {
    Ok(app_paths::data_root()?.join(DOCUMENT_BUNDLES_DIR))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_document_alias() {
        let entry = resolve_catalog_entry("pdf-inspector").unwrap();
        assert_eq!(entry.target, PDF_INSPECTOR_TARGET);
    }

    #[test]
    fn supports_pdf_extension() {
        assert!(supports_path(Path::new("report.pdf")));
        assert!(supports_path(Path::new("report.PDF")));
        assert!(!supports_path(Path::new("report.txt")));
    }
}
