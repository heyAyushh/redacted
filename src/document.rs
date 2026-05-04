use crate::cli::{print_document_help, DocumentArgs, DocumentHelpTopic, DocumentSubcommand};
use crate::errors::{RedactError, Result, EXIT_SUCCESS};
use crate::extension::{
    format_registry_fields, write_notice_if_needed, ExtensionDistribution, ExtensionKind,
    ExtensionLicenseMetadata,
};
use crate::io_safe;
use crate::{app_paths, app_paths::yes_or_no};
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Component, Path, PathBuf};
use std::process::Command;

const DOCUMENT_SCHEMA_VERSION: u32 = 1;
const ACTIVE_DOCUMENT_STATE_FILE: &str = "active-document-adapter.state";
const VERIFIED_DOCUMENT_STATE_FILE: &str = "verified.state";
const DOCUMENT_BUNDLE_MANIFEST_FILE: &str = "bundle.state";
const DOCUMENT_BUNDLES_DIR: &str = "document-adapters";
const DOCUMENT_RUNNER_DIR: &str = "runner";

const PDF_ADAPTER_ALIAS: &str = "pdf";
const PDF_ADAPTER_TARGET: &str = "poppler/pdftotext-v1";
const PDF_ADAPTER_NAME: &str = "pdftotext-local";
const PDF_ADAPTER_RUNNER_NAME: &str = "pdftotext_runner.py";
const FIRECRAWL_PDF_ALIAS: &str = "firecrawl-pdf";
const FIRECRAWL_PDF_TARGET: &str = "firecrawl/pdf-inspector-v1";
const FIRECRAWL_PDF_ADAPTER: &str = "firecrawl-pdf-inspector-local";
const FIRECRAWL_PDF_RUNNER_NAME: &str = "firecrawl_pdf_inspector_runner.py";
const FIRECRAWL_PDF_EXECUTABLE: &str = "pdf2md";

const PDF_ADAPTER_RUNNER_SCRIPT: &str = r#"#!/usr/bin/env python3
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

const FIRECRAWL_PDF_RUNNER_SCRIPT: &str = r#"#!/usr/bin/env python3
import argparse
import pathlib
import subprocess
import sys


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", required=True)
    parser.add_argument("--input", required=True)
    parser.add_argument("--executable", required=True)
    args = parser.parse_args()

    input_path = pathlib.Path(args.input)
    if not input_path.is_file():
        sys.stderr.write("input is not a file\n")
        return 2

    # Firecrawl pdf-inspector's pdf2md emits clean markdown with --raw.
    command = [args.executable, str(input_path), "--raw"]
    completed = subprocess.run(command, capture_output=True)
    if completed.returncode != 0:
        sys.stderr.write("pdf2md failed\n")
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
    executable_name: Option<&'static str>,
    license: ExtensionLicenseMetadata,
}

const PDF_ADAPTER_ENTRY: DocumentCatalogEntry = DocumentCatalogEntry {
    target: PDF_ADAPTER_TARGET,
    provider: "poppler",
    model: "pdftotext-v1",
    aliases: &[PDF_ADAPTER_ALIAS],
    adapter: PDF_ADAPTER_NAME,
    runner_name: PDF_ADAPTER_RUNNER_NAME,
    executable_name: None,
    license: ExtensionLicenseMetadata {
        target: PDF_ADAPTER_TARGET,
        kind: ExtensionKind::Document,
        source_url: "https://poppler.freedesktop.org/",
        license: "GPL-2.0-or-later",
        distribution: ExtensionDistribution::ExternalBinary,
        bundled: false,
        network_default: false,
        notice: "PDF document adapter calls the local Poppler pdftotext executable, which is GPL licensed and remains outside the MIT core.",
    },
};

const FIRECRAWL_PDF_ENTRY: DocumentCatalogEntry = DocumentCatalogEntry {
    target: FIRECRAWL_PDF_TARGET,
    provider: "firecrawl",
    model: "pdf-inspector-v1",
    aliases: &[FIRECRAWL_PDF_ALIAS],
    adapter: FIRECRAWL_PDF_ADAPTER,
    runner_name: FIRECRAWL_PDF_RUNNER_NAME,
    executable_name: Some(FIRECRAWL_PDF_EXECUTABLE),
    license: ExtensionLicenseMetadata {
        target: FIRECRAWL_PDF_TARGET,
        kind: ExtensionKind::Document,
        source_url: "https://github.com/firecrawl/pdf-inspector",
        license: "MIT",
        distribution: ExtensionDistribution::ExternalBinary,
        bundled: false,
        network_default: false,
        notice: "Firecrawl PDF Inspector is MIT and runs only as a local external pdf2md binary; it is not linked or vendored into the core.",
    },
};

const DOCUMENT_CATALOG: [DocumentCatalogEntry; 2] = [PDF_ADAPTER_ENTRY, FIRECRAWL_PDF_ENTRY];

#[derive(Debug)]
pub struct DocumentSession {
    entry: &'static DocumentCatalogEntry,
    runner_path: PathBuf,
    executable_path: Option<PathBuf>,
}

#[derive(Debug)]
struct BundleManifest {
    schema_version: u32,
    target: String,
    adapter: String,
    runner_rel: String,
    executable_path: Option<PathBuf>,
    executable_sha256: Option<String>,
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
            write_notice_if_needed(entry.license)?;
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
            write_notice_if_needed(entry.license)?;
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
            write_notice_if_needed(entry.license)?;
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
                    "No active document adapter configured.\nSet one up with:\n  redacted document enable pdf\n",
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
                                "No active document adapter is configured.\n  redacted document enable pdf".into(),
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
            "No active document adapter is configured.\n  redacted document enable pdf\n  redacted document list".into(),
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
    let runner_path = bundle_child_path(&bundle, &manifest.runner_rel, "runner_rel")?;
    Ok(DocumentSession {
        entry,
        runner_path,
        executable_path: manifest.executable_path,
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
    let mut command = Command::new(&session.runner_path);
    command
        .arg("--target")
        .arg(session.entry.target)
        .arg("--input")
        .arg(path);
    if let Some(executable_path) = session.executable_path.as_ref() {
        command.arg("--executable").arg(executable_path);
    }
    let output = command.output().map_err(|error| {
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
        PDF_ADAPTER_TARGET => install_pdf_adapter_bundle(entry, &temp_bundle),
        FIRECRAWL_PDF_TARGET => install_firecrawl_pdf_bundle(entry, &temp_bundle),
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

fn install_pdf_adapter_bundle(entry: &DocumentCatalogEntry, temp_bundle: &Path) -> Result<()> {
    let runner_dir = temp_bundle.join(DOCUMENT_RUNNER_DIR);
    fs::create_dir_all(&runner_dir).map_err(|error| {
        RedactError::Config(format!(
            "Cannot create runner directory '{}': {}",
            runner_dir.display(),
            error
        ))
    })?;
    let runner_path = runner_dir.join(entry.runner_name);
    io_safe::atomic_write(&runner_path, PDF_ADAPTER_RUNNER_SCRIPT)?;
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
        executable_path: None,
        executable_sha256: None,
    };
    save_bundle_manifest(temp_bundle, &manifest)?;
    Ok(())
}

fn install_firecrawl_pdf_bundle(entry: &DocumentCatalogEntry, temp_bundle: &Path) -> Result<()> {
    let executable_name = entry.executable_name.ok_or_else(|| {
        RedactError::Config(format!(
            "Document adapter '{}' is missing executable metadata.",
            entry.target
        ))
    })?;
    let executable = find_executable_in_path(executable_name)?;
    let executable_sha256 = crate::provider::sha256_hex_of_path(&executable)?;
    let runner_dir = temp_bundle.join(DOCUMENT_RUNNER_DIR);
    fs::create_dir_all(&runner_dir).map_err(|error| {
        RedactError::Config(format!(
            "Cannot create runner directory '{}': {}",
            runner_dir.display(),
            error
        ))
    })?;
    let runner_path = runner_dir.join(entry.runner_name);
    io_safe::atomic_write(&runner_path, FIRECRAWL_PDF_RUNNER_SCRIPT)?;
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
        executable_path: Some(executable),
        executable_sha256: Some(executable_sha256),
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
    let runner_path = bundle_child_path(bundle_root, &manifest.runner_rel, "runner_rel")?;
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
    if runner_bytes != runner_script_for_entry(entry).as_bytes() {
        return Err(RedactError::Config(format!(
            "Document adapter '{}' failed integrity verification.",
            entry.target
        )));
    }
    ensure_document_runtime_available(entry, &manifest)?;
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
    let runner_path = bundle_child_path(bundle_root, &manifest.runner_rel, "runner_rel")?;
    if !runner_path.exists() {
        return Err(RedactError::Config(format!(
            "Document adapter '{}' is missing runner '{}'.",
            entry.target,
            runner_path.display()
        )));
    }
    ensure_document_runtime_available(entry, &manifest)?;
    Ok(())
}

fn bundle_child_path(bundle_root: &Path, rel: &str, field: &str) -> Result<PathBuf> {
    let rel_path = Path::new(rel);
    if rel.is_empty() || rel_path.is_absolute() {
        return Err(RedactError::Config(format!(
            "Document adapter manifest field '{}' must be a relative bundle path.",
            field
        )));
    }
    for component in rel_path.components() {
        match component {
            Component::Normal(_) | Component::CurDir => {}
            _ => {
                return Err(RedactError::Config(format!(
                    "Document adapter manifest field '{}' cannot escape the bundle.",
                    field
                )));
            }
        }
    }
    Ok(bundle_root.join(rel_path))
}

fn runner_script_for_entry(entry: &DocumentCatalogEntry) -> &'static str {
    match entry.target {
        PDF_ADAPTER_TARGET => PDF_ADAPTER_RUNNER_SCRIPT,
        FIRECRAWL_PDF_TARGET => FIRECRAWL_PDF_RUNNER_SCRIPT,
        _ => "",
    }
}

fn ensure_document_runtime_available(
    entry: &DocumentCatalogEntry,
    manifest: &BundleManifest,
) -> Result<()> {
    ensure_command_available(
        entry,
        "python3",
        &["--version"],
        "Install Python 3, then run",
    )?;
    match entry.target {
        PDF_ADAPTER_TARGET => {
            ensure_command_available(entry, "pdftotext", &["-v"], "Install poppler, then run")
        }
        FIRECRAWL_PDF_TARGET => verify_manifest_executable(entry, manifest),
        _ => Err(RedactError::Config(format!(
            "Document adapter '{}' has no runtime verifier.",
            entry.target
        ))),
    }
}

fn ensure_command_available(
    entry: &DocumentCatalogEntry,
    command: &str,
    args: &[&str],
    guidance: &str,
) -> Result<()> {
    match Command::new(command).args(args).output() {
        Ok(_) => Ok(()),
        Err(error) => Err(RedactError::Usage(format!(
            "Document adapter '{}' requires '{}' in PATH.\n{}:\n  redacted document verify {}\nUnderlying error: {}",
            entry.target,
            command,
            guidance,
            entry.aliases.first().copied().unwrap_or(entry.target),
            error
        ))),
    }
}

fn verify_manifest_executable(
    entry: &DocumentCatalogEntry,
    manifest: &BundleManifest,
) -> Result<()> {
    let executable_path = manifest.executable_path.as_ref().ok_or_else(|| {
        RedactError::Config(format!(
            "Document adapter '{}' is missing executable path metadata.",
            entry.target
        ))
    })?;
    let expected_sha256 = manifest.executable_sha256.as_ref().ok_or_else(|| {
        RedactError::Config(format!(
            "Document adapter '{}' is missing executable hash metadata.",
            entry.target
        ))
    })?;
    if !executable_path.is_file() {
        return Err(RedactError::Config(format!(
            "Document adapter '{}' executable '{}' is missing.",
            entry.target,
            executable_path.display()
        )));
    }
    let actual_sha256 = crate::provider::sha256_hex_of_path(executable_path)?;
    if &actual_sha256 != expected_sha256 {
        return Err(RedactError::Config(format!(
            "Document adapter '{}' failed executable integrity verification.",
            entry.target
        )));
    }
    Ok(())
}

fn find_executable_in_path(name: &str) -> Result<PathBuf> {
    app_paths::find_executable_in_path(name).ok_or_else(|| RedactError::Usage(format!(
        "Cannot find '{}' in PATH.\nInstall Firecrawl PDF Inspector's pdf2md CLI, then run:\n  redacted document install firecrawl-pdf",
        name
    )))
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
            "- {}  adapter={}  support=supported  installed={}  verified={}  active={}  {}\n",
            entry.target,
            entry.adapter,
            yes_or_no(installed),
            yes_or_no(verified),
            yes_or_no(active),
            format_registry_fields(entry.license),
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
    if let Some(executable_path) = manifest.executable_path.as_ref() {
        content.push_str(&format!("executable_path={}\n", executable_path.display()));
    }
    if let Some(executable_sha256) = manifest.executable_sha256.as_ref() {
        content.push_str(&format!("executable_sha256={}\n", executable_sha256));
    }
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
        executable_path: values.get("executable_path").map(PathBuf::from),
        executable_sha256: values.get("executable_sha256").cloned(),
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
        let entry = resolve_catalog_entry("pdf").unwrap();
        assert_eq!(entry.target, PDF_ADAPTER_TARGET);
    }

    #[test]
    fn supports_pdf_extension() {
        assert!(supports_path(Path::new("report.pdf")));
        assert!(supports_path(Path::new("report.PDF")));
        assert!(!supports_path(Path::new("report.txt")));
    }

    #[test]
    fn bundle_child_path_rejects_paths_outside_bundle() {
        let root = Path::new("/tmp/redacted-document-bundle");
        assert!(bundle_child_path(root, "../runner", "runner_rel").is_err());
        assert!(bundle_child_path(root, "/tmp/runner", "runner_rel").is_err());
        assert!(bundle_child_path(root, "runner/provider.py", "runner_rel").is_ok());
    }
}
