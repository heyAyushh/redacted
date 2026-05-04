use crate::{app_paths::yes_or_no, errors::Result, io_safe};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExtensionKind {
    Provider,
    Detector,
    Document,
}

impl ExtensionKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Provider => "provider",
            Self::Detector => "detector",
            Self::Document => "document",
        }
    }
}

#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExtensionDistribution {
    DownloadedArtifact,
    ExternalBinary,
    VendoredSource,
    LinkedLibrary,
}

impl ExtensionDistribution {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DownloadedArtifact => "downloaded-artifact",
            Self::ExternalBinary => "external-binary",
            Self::VendoredSource => "vendored-source",
            Self::LinkedLibrary => "linked-library",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExtensionLicenseMetadata {
    pub target: &'static str,
    pub kind: ExtensionKind,
    pub source_url: &'static str,
    pub license: &'static str,
    pub distribution: ExtensionDistribution,
    pub bundled: bool,
    pub network_default: bool,
    pub notice: &'static str,
}

impl ExtensionLicenseMetadata {
    pub fn requires_notice(self) -> bool {
        !self.license.eq_ignore_ascii_case("MIT") || self.license_is_unknown()
    }

    pub fn license_is_unknown(self) -> bool {
        self.license.eq_ignore_ascii_case("unknown")
            || self.license.eq_ignore_ascii_case("unknown-license")
    }
}

pub fn format_registry_fields(metadata: ExtensionLicenseMetadata) -> String {
    format!(
        "kind={}  source={}  license={}  distribution={}  bundled={}  network_default={}",
        metadata.kind.as_str(),
        metadata.source_url,
        metadata.license,
        metadata.distribution.as_str(),
        yes_or_no(metadata.bundled),
        yes_or_no(metadata.network_default),
    )
}

pub fn append_notice(output: &mut String, metadata: ExtensionLicenseMetadata) {
    output.push_str("notice: ");
    output.push_str(metadata.notice);
    output.push('\n');
    output.push_str("extension: ");
    output.push_str(metadata.target);
    output.push_str("  ");
    output.push_str(&format_registry_fields(metadata));
    output.push('\n');
}

pub fn write_notice_if_needed(metadata: ExtensionLicenseMetadata) -> Result<()> {
    if metadata.requires_notice() {
        let mut output = String::new();
        append_notice(&mut output, metadata);
        io_safe::write_stdout(&output)?;
    }
    Ok(())
}
