use crate::cli::{print_provider_help, ProviderArgs, ProviderHelpTopic, ProviderSubcommand};
use crate::detector::{Confidence, Finding};
use crate::errors::{RedactError, Result, EXIT_SUCCESS};
use crate::io_safe;
use crate::{app_paths, app_paths::yes_or_no, json::json_escape};
use std::collections::HashMap;
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Component, Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

const PROVIDER_SCHEMA_VERSION: u32 = 1;
const PROVIDER_REQUEST_SCHEMA_VERSION: u32 = 1;
const ACTIVE_PROVIDER_STATE_FILE: &str = "active-provider.state";
const VERIFIED_PROVIDER_STATE_FILE: &str = "verified.state";
const PROVIDER_BUNDLE_MANIFEST_FILE: &str = "bundle.state";
const PROVIDER_BUNDLES_DIR: &str = "providers";
const PROVIDER_RUNNER_DIR: &str = "runner";
const PROVIDER_MODEL_DIR: &str = "model";
const OPENAI_PROVIDER_ALIAS: &str = "openai";
const MLX_PROVIDER_ALIAS: &str = "mlx";
const OPENAI_PRIVACY_TARGET: &str = "openai/privacy-filter-v1";
const OPENAI_PRIVACY_MLX_TARGET: &str = "openai/privacy-filter-v1-mlx";
const OPENAI_RUNNER_SCRIPT_NAME: &str = "openai_privacy_runner.py";
const MLX_RUNNER_SCRIPT_NAME: &str = "mlx_privacy_runner.py";
const MLX_EMBEDDINGS_PACKAGE: &str = "mlx-embeddings==0.1.0";
const REDACTED_PROVIDER_PYTHON_OVERRIDE: &str = "REDACTED_PROVIDER_PYTHON";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProviderAdapterKind {
    OpenAiOpfLocal,
    OpenAiMlxLocal,
}

impl ProviderAdapterKind {
    fn manifest_name(self) -> &'static str {
        match self {
            Self::OpenAiOpfLocal => "openai-opf-local",
            Self::OpenAiMlxLocal => "openai-mlx-local",
        }
    }

    fn display_name(self) -> &'static str {
        self.manifest_name()
    }

    fn trust_level(self) -> &'static str {
        match self {
            Self::OpenAiOpfLocal => "optional-external",
            Self::OpenAiMlxLocal => "optional-external",
        }
    }

    fn support_tier(self) -> &'static str {
        match self {
            Self::OpenAiOpfLocal => "supported",
            Self::OpenAiMlxLocal => "experimental",
        }
    }

    fn detection_mode(self) -> &'static str {
        match self {
            Self::OpenAiOpfLocal => "token-span",
            Self::OpenAiMlxLocal => "token-span-mlx",
        }
    }
}

fn adapter_uses_virtualenv(adapter: ProviderAdapterKind) -> bool {
    matches!(
        adapter,
        ProviderAdapterKind::OpenAiOpfLocal | ProviderAdapterKind::OpenAiMlxLocal
    )
}

#[derive(Debug, Clone, Copy)]
struct LabelMapping {
    provider_label: &'static str,
    detector_name: &'static str,
    category: &'static str,
}

#[derive(Debug, Clone, Copy)]
struct ArtifactSpec {
    bundle_rel: &'static str,
    url: &'static str,
    size_bytes: u64,
    sha256: &'static str,
}

#[derive(Debug, Clone, Copy)]
struct ProviderCatalogEntry {
    target: &'static str,
    provider: &'static str,
    model: &'static str,
    aliases: &'static [&'static str],
    legacy_targets: &'static [&'static str],
    adapter: ProviderAdapterKind,
    package: Option<ArtifactSpec>,
    model_artifacts: &'static [ArtifactSpec],
    labels: &'static [LabelMapping],
}

#[derive(Debug)]
pub struct ProviderSession {
    entry: &'static ProviderCatalogEntry,
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
    request_counter: u64,
}

#[derive(Debug)]
struct BundleManifest {
    schema_version: u32,
    target: String,
    provider: String,
    model: String,
    adapter: String,
    runner_rel: String,
    entry_rel: Option<String>,
    checkpoint_rel: String,
    runner_sha256: String,
    runner_executable_sha256: Option<String>,
}

struct BundlePaths {
    runner: PathBuf,
    entry: Option<PathBuf>,
    checkpoint: PathBuf,
}

#[derive(Debug)]
struct VerifiedState {
    schema_version: u32,
    target: String,
    verified_unix_seconds: u64,
}

#[derive(Debug)]
struct ActiveProviderState {
    target: String,
}

#[derive(Debug)]
struct InstallOutcome {
    installed_now: bool,
    bundle_root: PathBuf,
}

#[derive(Debug)]
struct ProviderSpan {
    label: String,
    start: usize,
    end: usize,
}

#[derive(Debug)]
struct ProviderResponse {
    schema_version: u32,
    request_id: String,
    target: String,
    spans: Vec<ProviderSpan>,
    error: Option<String>,
}

const OPENAI_LABEL_MAPPINGS: [LabelMapping; 8] = [
    LabelMapping {
        provider_label: "account_number",
        detector_name: "ACCOUNT_NUMBER",
        category: "pii",
    },
    LabelMapping {
        provider_label: "private_address",
        detector_name: "PRIVATE_ADDRESS",
        category: "pii",
    },
    LabelMapping {
        provider_label: "private_email",
        detector_name: "PRIVATE_EMAIL",
        category: "pii",
    },
    LabelMapping {
        provider_label: "private_person",
        detector_name: "PRIVATE_PERSON",
        category: "pii",
    },
    LabelMapping {
        provider_label: "private_phone",
        detector_name: "PRIVATE_PHONE",
        category: "pii",
    },
    LabelMapping {
        provider_label: "private_url",
        detector_name: "PRIVATE_URL",
        category: "pii",
    },
    LabelMapping {
        provider_label: "private_date",
        detector_name: "PRIVATE_DATE",
        category: "pii",
    },
    LabelMapping {
        provider_label: "secret",
        detector_name: "SECRET",
        category: "secret",
    },
];

const OPENAI_PACKAGE_ARTIFACT: ArtifactSpec = ArtifactSpec {
    bundle_rel: "downloads/opf-source.tar.gz",
    url: "https://github.com/openai/privacy-filter/archive/2e8c95b9771eec29ef61012f6e5e836f9bad7635.tar.gz",
    size_bytes: 88022,
    sha256: "16f7241c5e4d24a31decaeef95b090268369ce4b79a6e20ca5795e377a2fb102",
};

const OPENAI_MODEL_ARTIFACTS: [ArtifactSpec; 4] = [
    ArtifactSpec {
        bundle_rel: "model/config.json",
        url: "https://huggingface.co/openai/privacy-filter/resolve/main/original/config.json?download=1",
        size_bytes: 707,
        sha256: "048a20604a3622de208d30df57cd5424bb583639b9ba20ddd7da593d3f89a248",
    },
    ArtifactSpec {
        bundle_rel: "model/dtypes.json",
        url: "https://huggingface.co/openai/privacy-filter/resolve/main/original/dtypes.json?download=1",
        size_bytes: 4108,
        sha256: "e936acb3d039b35ec55438af2fffd424a53c7685b895775c186b26c7df79fcc7",
    },
    ArtifactSpec {
        bundle_rel: "model/model.safetensors",
        url: "https://huggingface.co/openai/privacy-filter/resolve/main/original/model.safetensors?download=1",
        size_bytes: 2_798_984_088,
        sha256: "9c262cbe68a0c8a50590a648ef8341a2b7d3be1fa11dfb79893fe0b03ce57b5c",
    },
    ArtifactSpec {
        bundle_rel: "model/viterbi_calibration.json",
        url: "https://huggingface.co/openai/privacy-filter/resolve/main/original/viterbi_calibration.json?download=1",
        size_bytes: 372,
        sha256: "bbc8611ef08a55ed72d64856cbbbb9a91db8dfa881f0a92e2afbad6e4bbc775a",
    },
];

const OPENAI_PROVIDER_ENTRY: ProviderCatalogEntry = ProviderCatalogEntry {
    target: OPENAI_PRIVACY_TARGET,
    provider: "openai",
    model: "privacy-filter-v1",
    aliases: &[OPENAI_PROVIDER_ALIAS],
    legacy_targets: &[],
    adapter: ProviderAdapterKind::OpenAiOpfLocal,
    package: Some(OPENAI_PACKAGE_ARTIFACT),
    model_artifacts: &OPENAI_MODEL_ARTIFACTS,
    labels: &OPENAI_LABEL_MAPPINGS,
};

const MLX_MODEL_ARTIFACTS: [ArtifactSpec; 6] = [
    ArtifactSpec {
        bundle_rel: "model/config.json",
        url: "https://huggingface.co/mlx-community/openai-privacy-filter-4bit/resolve/8b784df48dd38a36b757f50c73d23e5bd38f3db0/config.json?download=1",
        size_bytes: 4354,
        sha256: "00aaaa67981f8ca724bfd72b00414f5a2864c367538f9fe85f3f49282c2f6d7b",
    },
    ArtifactSpec {
        bundle_rel: "model/model.safetensors",
        url: "https://huggingface.co/mlx-community/openai-privacy-filter-4bit/resolve/8b784df48dd38a36b757f50c73d23e5bd38f3db0/model.safetensors?download=1",
        size_bytes: 790_435_150,
        sha256: "0ec7afabebaf35cf8482c73b351af888b75fbe0c4aaed7cdeec57bb6b87b3796",
    },
    ArtifactSpec {
        bundle_rel: "model/model.safetensors.index.json",
        url: "https://huggingface.co/mlx-community/openai-privacy-filter-4bit/resolve/8b784df48dd38a36b757f50c73d23e5bd38f3db0/model.safetensors.index.json?download=1",
        size_bytes: 20_455,
        sha256: "bb530de716429568ba7e973e400561ee7983d76f56f62095188f0d4fa87f0e49",
    },
    ArtifactSpec {
        bundle_rel: "model/tokenizer.json",
        url: "https://huggingface.co/mlx-community/openai-privacy-filter-4bit/resolve/8b784df48dd38a36b757f50c73d23e5bd38f3db0/tokenizer.json?download=1",
        size_bytes: 27_868_174,
        sha256: "0614fe83cadab421296e664e1f48f4261fa8fef6e03e63bb75c20f38e37d07d3",
    },
    ArtifactSpec {
        bundle_rel: "model/tokenizer_config.json",
        url: "https://huggingface.co/mlx-community/openai-privacy-filter-4bit/resolve/8b784df48dd38a36b757f50c73d23e5bd38f3db0/tokenizer_config.json?download=1",
        size_bytes: 283,
        sha256: "490477def5405c66ae43cf65756976a4c9963b4c20c148a392eb4c3a833b1725",
    },
    ArtifactSpec {
        bundle_rel: "model/viterbi_calibration.json",
        url: "https://huggingface.co/mlx-community/openai-privacy-filter-4bit/resolve/8b784df48dd38a36b757f50c73d23e5bd38f3db0/viterbi_calibration.json?download=1",
        size_bytes: 372,
        sha256: "bbc8611ef08a55ed72d64856cbbbb9a91db8dfa881f0a92e2afbad6e4bbc775a",
    },
];

const MLX_PROVIDER_ENTRY: ProviderCatalogEntry = ProviderCatalogEntry {
    target: OPENAI_PRIVACY_MLX_TARGET,
    provider: "openai",
    model: "privacy-filter-v1-mlx",
    aliases: &[MLX_PROVIDER_ALIAS],
    legacy_targets: &[],
    adapter: ProviderAdapterKind::OpenAiMlxLocal,
    package: None,
    model_artifacts: &MLX_MODEL_ARTIFACTS,
    labels: &OPENAI_LABEL_MAPPINGS,
};

const PROVIDER_CATALOG: [ProviderCatalogEntry; 2] = [OPENAI_PROVIDER_ENTRY, MLX_PROVIDER_ENTRY];

const OPENAI_RUNNER_SCRIPT: &str = r#"#!/usr/bin/env python3
import argparse
import json
import sys

from opf._api import OPF


def build_char_to_byte_offsets(text: str) -> list[int]:
    offsets = [0]
    total = 0
    for char in text:
        total += len(char.encode("utf-8"))
        offsets.append(total)
    return offsets


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", required=True)
    parser.add_argument("--checkpoint", required=True)
    args = parser.parse_args()

    redactor = OPF(
        model=args.checkpoint,
        device="cpu",
        output_mode="typed",
        output_text_only=False,
    )

    for raw_line in sys.stdin:
        line = raw_line.strip()
        if not line:
            continue

        request_id = "unknown"
        try:
            payload = json.loads(line)
            request_id = str(payload.get("request_id", "unknown"))
            text = payload.get("text")
            schema_version = payload.get("schema_version")
            if schema_version != 1 or not isinstance(text, str):
                raise ValueError("invalid request schema")

            result = redactor.redact(text)
            byte_offsets = build_char_to_byte_offsets(result.text)
            spans = []
            for span in result.detected_spans:
                start = int(span.start)
                end = int(span.end)
                spans.append(
                    {
                        "label": span.label,
                        "start": byte_offsets[start],
                        "end": byte_offsets[end],
                    }
                )
            response = {
                "schema_version": 1,
                "request_id": request_id,
                "target": args.target,
                "spans": spans,
            }
        except Exception as exc:
            response = {
                "schema_version": 1,
                "request_id": request_id,
                "target": args.target,
                "error": f"runtime error: {exc.__class__.__name__}",
                "spans": [],
            }

        sys.stdout.write(json.dumps(response, separators=(",", ":")) + "\n")
        sys.stdout.flush()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
"#;

const MLX_RUNNER_SCRIPT: &str = r#"#!/usr/bin/env python3
import argparse
import json
import pathlib
import sys

import mlx.core as mx
import mlx.nn as nn
from mlx_lm.models.gpt_oss import GptOssMoeModel, Model as GptOssModel, ModelArgs
from mlx_lm.utils import load_model
from transformers import AutoTokenizer


class OpenAIPrivacyFilterModel(nn.Module):
    def __init__(self, args: ModelArgs):
        super().__init__()
        self.args = args
        self.model_type = args.model_type
        self.model = GptOssMoeModel(args)
        self.score = nn.Linear(args.hidden_size, 33, bias=True)

    def __call__(self, input_ids: mx.array, attention_mask=None):
        del attention_mask
        return self.score(self.model(input_ids))

    def sanitize(self, weights):
        return GptOssModel(self.args).sanitize(weights)

    @property
    def layers(self):
        return self.model.layers

    @property
    def quant_predicate(self):
        return GptOssModel(self.args).quant_predicate


def get_model_classes(config):
    config["model_type"] = "gpt_oss"
    if "rope_parameters" in config:
        rope_scaling = dict(config["rope_parameters"])
        if "rope_type" in rope_scaling:
            rope_scaling["type"] = rope_scaling.pop("rope_type")
        config["rope_scaling"] = rope_scaling
    return OpenAIPrivacyFilterModel, ModelArgs


def build_char_to_byte_offsets(text: str) -> list[int]:
    offsets = [0]
    total = 0
    for char in text:
        total += len(char.encode("utf-8"))
        offsets.append(total)
    return offsets


def normalize_label(label: str) -> str:
    if label == "O":
        return "O"
    if "-" not in label:
        return label
    return label.split("-", 1)[1]


def spans_from_predictions(text: str, offsets: list[tuple[int, int]], labels: list[str]) -> list[dict]:
    byte_offsets = build_char_to_byte_offsets(text)
    spans = []
    active_label = None
    active_start = None
    active_end = None

    def finish_active():
        nonlocal active_label, active_start, active_end
        if active_label is not None and active_start is not None and active_end is not None:
            spans.append(
                {
                    "label": active_label,
                    "start": byte_offsets[active_start],
                    "end": byte_offsets[active_end],
                }
            )
        active_label = None
        active_start = None
        active_end = None

    for (start, end), raw_label in zip(offsets, labels):
        if start == end:
            continue
        label = normalize_label(raw_label)
        prefix = raw_label.split("-", 1)[0] if "-" in raw_label else raw_label
        if label == "O":
            finish_active()
            continue
        if prefix in ("B", "S") or active_label != label:
            finish_active()
            active_label = label
            active_start = start
            active_end = end
            if prefix == "S":
                finish_active()
                continue
        else:
            active_end = end
        if prefix == "E":
            finish_active()

    finish_active()
    return spans


def predict_spans(model, tokenizer, id_to_label: dict[int, str], text: str) -> list[dict]:
    encoded = tokenizer(
        text,
        return_offsets_mapping=True,
        truncation=True,
    )
    offsets = encoded.pop("offset_mapping")
    mlx_inputs = {key: mx.array([value]) for key, value in encoded.items()}
    output = model(
        mlx_inputs["input_ids"],
        attention_mask=mlx_inputs.get("attention_mask"),
    )
    logits = getattr(output, "logits", output[0] if isinstance(output, (tuple, list)) else output)
    predictions = mx.argmax(logits, axis=-1).tolist()[0]
    labels = [id_to_label[int(index)] for index in predictions]
    return spans_from_predictions(text, offsets, labels)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", required=True)
    parser.add_argument("--checkpoint", required=True)
    args = parser.parse_args()

    checkpoint = pathlib.Path(args.checkpoint)
    model, config = load_model(
        checkpoint,
        get_model_classes=get_model_classes,
        strict=True,
        lazy=False,
    )
    tokenizer = AutoTokenizer.from_pretrained(checkpoint)
    id_to_label = {int(key): value for key, value in config["id2label"].items()}

    for raw_line in sys.stdin:
        line = raw_line.strip()
        if not line:
            continue

        request_id = "unknown"
        try:
            payload = json.loads(line)
            request_id = str(payload.get("request_id", "unknown"))
            text = payload.get("text")
            schema_version = payload.get("schema_version")
            if schema_version != 1 or not isinstance(text, str):
                raise ValueError("invalid request schema")
            response = {
                "schema_version": 1,
                "request_id": request_id,
                "target": args.target,
                "spans": predict_spans(model, tokenizer, id_to_label, text),
            }
        except Exception as exc:
            response = {
                "schema_version": 1,
                "request_id": request_id,
                "target": args.target,
                "error": f"runtime error: {exc.__class__.__name__}",
                "spans": [],
            }

        sys.stdout.write(json.dumps(response, separators=(",", ":")) + "\n")
        sys.stdout.flush()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
"#;

pub fn run_provider_command(args: &ProviderArgs) -> Result<i32> {
    if let Some(topic) = args.help.clone() {
        print_provider_help(topic);
        return Ok(EXIT_SUCCESS);
    }

    match args.command.as_ref() {
        Some(ProviderSubcommand::Enable { selector }) => {
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
            let message = format!(
                "resolved target: {}\ninstalled: {}\nverified: yes\nactive: yes\npath: {}\n",
                entry.target,
                if installed_now { "yes" } else { "already" },
                bundle.display()
            );
            io_safe::write_stdout(&message)?;
        }
        Some(ProviderSubcommand::Install { selector }) => {
            let entry = resolve_catalog_entry(selector)?;
            let outcome = install_target(entry)?;
            let message = format!(
                "resolved target: {}\ninstalled: {}\nverified: yes\npath: {}\n",
                entry.target,
                if outcome.installed_now {
                    "yes"
                } else {
                    "already"
                },
                outcome.bundle_root.display()
            );
            io_safe::write_stdout(&message)?;
        }
        Some(ProviderSubcommand::Use { selector }) => {
            let entry = resolve_catalog_entry(selector)?;
            let bundle = bundle_root_for_entry(entry)?;
            ensure_ready_bundle(entry, &bundle)?;
            activate_target(entry)?;
            let message = format!(
                "resolved target: {}\nactive: yes\npath: {}\n",
                entry.target,
                bundle.display()
            );
            io_safe::write_stdout(&message)?;
        }
        Some(ProviderSubcommand::Current) => {
            if let Some(state) = load_active_provider_state()? {
                let message = if let Some(entry) = find_catalog_entry_by_target(&state.target) {
                    let message = format!(
                        "active target: {}\nadapter: {}\nmode: {}\nsupport: {}\ntrust: {}\n",
                        state.target,
                        entry.adapter.display_name(),
                        entry.adapter.detection_mode(),
                        entry.adapter.support_tier(),
                        entry.adapter.trust_level()
                    );
                    message
                } else {
                    format!("active target: {}\n", state.target)
                };
                io_safe::write_stdout(&message)?;
            } else {
                io_safe::write_stdout(
                    "No active provider configured.\nSet one up with:\n  redacted provider enable openai\n",
                )?;
            }
        }
        Some(ProviderSubcommand::List) => {
            io_safe::write_stdout(&format_provider_list()?)?;
        }
        Some(ProviderSubcommand::Verify { selector, all }) => {
            if *all {
                let mut verified_targets = Vec::new();
                for entry in &PROVIDER_CATALOG {
                    let bundle = bundle_root_for_entry(entry)?;
                    if is_bundle_installed(entry, &bundle)? {
                        verify_bundle(entry, &bundle)?;
                        verified_targets.push(entry.target);
                    }
                }
                if verified_targets.is_empty() {
                    io_safe::write_stdout("No installed provider bundles found.\n")?;
                } else {
                    let mut output = String::from("Verified provider bundles:\n");
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
                        let active = load_active_provider_state()?.ok_or_else(|| {
                            RedactError::Usage(
                                "No active provider is configured.\n  redacted provider enable openai".into(),
                            )
                        })?;
                        find_catalog_entry_by_target(&active.target).ok_or_else(|| {
                            RedactError::Usage(format!(
                                "Active provider target '{}' is not supported by this build.\n  redacted provider list",
                                active.target
                            ))
                        })?
                    }
                };
                let bundle = bundle_root_for_entry(entry)?;
                verify_bundle(entry, &bundle)?;
                let message = format!(
                    "verified target: {}\npath: {}\n",
                    entry.target,
                    bundle.display()
                );
                io_safe::write_stdout(&message)?;
            }
        }
        Some(ProviderSubcommand::Disable) => {
            if let Some(state) = load_active_provider_state()? {
                clear_active_provider_state()?;
                let message = format!("disabled provider: {}\n", state.target);
                io_safe::write_stdout(&message)?;
            } else {
                io_safe::write_stdout("Provider already disabled.\n")?;
            }
        }
        None => {
            print_provider_help(ProviderHelpTopic::Root);
        }
    }

    Ok(EXIT_SUCCESS)
}

pub fn start_active_session() -> Result<ProviderSession> {
    let active = load_active_provider_state()?.ok_or_else(|| {
        RedactError::Usage(
            "No active privacy-filter provider is configured.\n  redacted provider enable openai\n  redacted provider list".into(),
        )
    })?;
    let entry = find_catalog_entry_by_target(&active.target).ok_or_else(|| {
        RedactError::Usage(format!(
            "Active provider target '{}' is not supported by this build.\n  redacted provider list",
            active.target
        ))
    })?;
    let bundle = bundle_root_for_entry(entry)?;
    ensure_ready_bundle(entry, &bundle)?;

    let manifest = load_bundle_manifest(&bundle_manifest_path(&bundle))?;
    let paths = validate_bundle_paths(entry, &bundle, &manifest)?;
    let mut command = Command::new(&paths.runner);
    if let Some(entry_path) = paths.entry.as_ref() {
        command.arg(entry_path);
    }
    command
        .arg("--target")
        .arg(entry.target)
        .arg("--checkpoint")
        .arg(&paths.checkpoint)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        // Provider stderr is intentionally not surfaced because a runner can
        // accidentally log raw input text that the core must never leak.
        .stderr(Stdio::null());

    let mut child = command.spawn().map_err(|error| {
        RedactError::Detection(format!(
            "Failed to start provider runner for '{}': {}",
            entry.target, error
        ))
    })?;
    let stdin = child.stdin.take().ok_or_else(|| {
        RedactError::Detection(format!(
            "Provider runner for '{}' did not expose stdin",
            entry.target
        ))
    })?;
    let stdout = child.stdout.take().ok_or_else(|| {
        RedactError::Detection(format!(
            "Provider runner for '{}' did not expose stdout",
            entry.target
        ))
    })?;

    Ok(ProviderSession {
        entry,
        child,
        stdin,
        stdout: BufReader::new(stdout),
        request_counter: 0,
    })
}

pub fn detect_with_session(
    session: &mut ProviderSession,
    text: &str,
    allow_patterns: &[String],
    deny_patterns: &[String],
) -> Result<Vec<Finding>> {
    session.request_counter += 1;
    let request_id = format!("req-{}", session.request_counter);
    let request = format!(
        "{{\"schema_version\":{},\"request_id\":\"{}\",\"text\":\"{}\"}}",
        PROVIDER_REQUEST_SCHEMA_VERSION,
        json_escape(&request_id),
        json_escape(text)
    );
    session
        .stdin
        .write_all(request.as_bytes())
        .map_err(|error| {
            RedactError::Detection(format!("Failed to write provider request: {}", error))
        })?;
    session.stdin.write_all(b"\n").map_err(|error| {
        RedactError::Detection(format!(
            "Failed to write provider request newline: {}",
            error
        ))
    })?;
    session.stdin.flush().map_err(|error| {
        RedactError::Detection(format!("Failed to flush provider request: {}", error))
    })?;

    let mut line = String::new();
    let bytes_read = session.stdout.read_line(&mut line).map_err(|error| {
        RedactError::Detection(format!("Failed to read provider response: {}", error))
    })?;
    if bytes_read == 0 {
        return Err(RedactError::Detection(format!(
            "Provider runner for '{}' exited without returning a response.",
            session.entry.target
        )));
    }

    let response = parse_provider_response(line.trim_end())?;
    if response.schema_version != PROVIDER_REQUEST_SCHEMA_VERSION {
        return Err(RedactError::Detection(format!(
            "Provider '{}' returned unsupported schema version {}.",
            session.entry.target, response.schema_version
        )));
    }
    if response.request_id != request_id {
        return Err(RedactError::Detection(format!(
            "Provider '{}' returned a mismatched request id.",
            session.entry.target
        )));
    }
    if response.target != session.entry.target {
        return Err(RedactError::Detection(format!(
            "Provider '{}' returned response for unexpected target '{}'.",
            session.entry.target, response.target
        )));
    }
    if let Some(message) = response.error {
        return Err(RedactError::Detection(format!(
            "Provider '{}' failed: {}",
            session.entry.target, message
        )));
    }

    let mut findings = Vec::new();
    for span in response.spans {
        let mapping = session
            .entry
            .labels
            .iter()
            .find(|mapping| mapping.provider_label == span.label)
            .ok_or_else(|| {
                RedactError::Detection(format!(
                    "Provider '{}' returned unknown label '{}'.",
                    session.entry.target, span.label
                ))
            })?;
        if span.end < span.start
            || span.end > text.len()
            || !text.is_char_boundary(span.start)
            || !text.is_char_boundary(span.end)
        {
            return Err(RedactError::Detection(format!(
                "Provider '{}' returned invalid span {}..{}.",
                session.entry.target, span.start, span.end
            )));
        }
        if !allow_patterns.is_empty()
            && !allow_patterns
                .iter()
                .any(|name| name == mapping.detector_name)
        {
            continue;
        }
        if deny_patterns
            .iter()
            .any(|name| name == mapping.detector_name)
        {
            continue;
        }
        findings.push(Finding {
            detector_name: mapping.detector_name,
            category: mapping.category,
            start: span.start,
            end: span.end,
            confidence: Confidence::Medium,
            matched_len: span.end.saturating_sub(span.start),
        });
    }

    Ok(findings)
}

impl Drop for ProviderSession {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn format_provider_list() -> Result<String> {
    let active_target = load_active_provider_state()?.map(|state| state.target);
    let mut output = String::new();
    output.push_str("Aliases:\n");
    for entry in &PROVIDER_CATALOG {
        for alias in entry.aliases {
            output.push_str(&format!("- {} -> {}\n", alias, entry.target));
        }
    }
    output.push_str("Targets:\n");
    for entry in &PROVIDER_CATALOG {
        let bundle = bundle_root_for_entry(entry)?;
        let installed = is_bundle_installed(entry, &bundle)?;
        let verified = if installed {
            has_verified_state(&bundle)?
        } else {
            false
        };
        let active = active_target
            .as_ref()
            .map(|target| entry.target == target || entry.legacy_targets.contains(&target.as_str()))
            .unwrap_or(false);
        output.push_str(&format!(
            "- {}  adapter={}  mode={}  support={}  trust={}  installed={}  verified={}  active={}",
            entry.target,
            entry.adapter.display_name(),
            entry.adapter.detection_mode(),
            entry.adapter.support_tier(),
            entry.adapter.trust_level(),
            yes_or_no(installed),
            yes_or_no(verified),
            yes_or_no(active),
        ));
        output.push('\n');
    }
    Ok(output)
}

fn install_target(entry: &'static ProviderCatalogEntry) -> Result<InstallOutcome> {
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

    let providers_root = providers_root()?;
    fs::create_dir_all(&providers_root).map_err(|error| {
        RedactError::Config(format!(
            "Cannot create provider directory '{}': {}",
            providers_root.display(),
            error
        ))
    })?;
    let temp_bundle = install_temp_bundle_path(entry)?;
    if temp_bundle.exists() {
        fs::remove_dir_all(&temp_bundle).map_err(|error| {
            RedactError::Config(format!(
                "Cannot clear temp provider directory '{}': {}",
                temp_bundle.display(),
                error
            ))
        })?;
    }
    fs::create_dir_all(&temp_bundle).map_err(|error| {
        RedactError::Config(format!(
            "Cannot create temp provider directory '{}': {}",
            temp_bundle.display(),
            error
        ))
    })?;

    let install_result = match entry.adapter {
        ProviderAdapterKind::OpenAiOpfLocal => install_openai_bundle(entry, &temp_bundle),
        ProviderAdapterKind::OpenAiMlxLocal => install_mlx_bundle(entry, &temp_bundle),
    };

    if let Err(error) = install_result {
        let _ = fs::remove_dir_all(&temp_bundle);
        return Err(error);
    }

    let parent = bundle_root.parent().ok_or_else(|| {
        RedactError::Config(format!(
            "Cannot determine provider bundle parent for '{}'.",
            bundle_root.display()
        ))
    })?;
    fs::create_dir_all(parent).map_err(|error| {
        RedactError::Config(format!(
            "Cannot create provider bundle parent '{}': {}",
            parent.display(),
            error
        ))
    })?;
    fs::rename(&temp_bundle, &bundle_root).map_err(|error| {
        let _ = fs::remove_dir_all(&temp_bundle);
        RedactError::Config(format!(
            "Cannot move provider bundle into place '{}': {}",
            bundle_root.display(),
            error
        ))
    })?;
    if adapter_uses_virtualenv(entry.adapter) {
        repair_bundle_runtime_paths(&bundle_root)?;
    }

    Ok(InstallOutcome {
        installed_now: true,
        bundle_root,
    })
}

fn verify_bundle(entry: &'static ProviderCatalogEntry, bundle_root: &Path) -> Result<()> {
    if !bundle_root.exists() {
        return Err(RedactError::Usage(format!(
            "Provider bundle '{}' is not installed.\n  redacted provider install {}",
            entry.target, entry.target
        )));
    }
    if adapter_uses_virtualenv(entry.adapter) {
        repair_bundle_runtime_paths(bundle_root)?;
    }
    let mut manifest = load_bundle_manifest(&bundle_manifest_path(bundle_root))?;
    if manifest.schema_version != PROVIDER_SCHEMA_VERSION
        || !manifest_matches_entry(&manifest, entry)
        || manifest.adapter != entry.adapter.manifest_name()
    {
        return Err(RedactError::Config(format!(
            "Provider bundle '{}' has invalid manifest metadata.",
            entry.target
        )));
    }
    refresh_bundle_runner_with_manifest(entry, bundle_root, &mut manifest)?;
    let paths = validate_bundle_paths(entry, bundle_root, &manifest)?;
    if !paths.runner.is_file() {
        return Err(RedactError::Config(format!(
            "Provider bundle '{}' is missing runner executable '{}'.",
            entry.target,
            paths.runner.display()
        )));
    }
    verify_runner_integrity(entry, bundle_root, &mut manifest, &paths, true)?;
    if let Some(package) = entry.package.as_ref() {
        verify_artifact_at_path(package, &bundle_root.join(package.bundle_rel))?;
    }
    for artifact in entry.model_artifacts {
        verify_artifact_at_path(artifact, &bundle_root.join(artifact.bundle_rel))?;
    }
    save_verified_state(
        bundle_root,
        &VerifiedState {
            schema_version: PROVIDER_SCHEMA_VERSION,
            target: entry.target.into(),
            verified_unix_seconds: app_paths::unix_timestamp_now()?,
        },
    )?;
    Ok(())
}

fn refresh_bundle_runner_with_manifest(
    entry: &'static ProviderCatalogEntry,
    bundle_root: &Path,
    manifest: &mut BundleManifest,
) -> Result<()> {
    let script = expected_runner_script(entry.adapter);
    let expected_sha256 = sha256_hex_of_bytes(script.as_bytes());
    if manifest.runner_sha256 == expected_sha256 {
        return Ok(());
    }
    let Some(entry_rel) = manifest.entry_rel.as_ref() else {
        return Ok(());
    };
    let runner_path = bundle_child_path(bundle_root, entry_rel, "entry_rel")?;
    io_safe::atomic_write(&runner_path, script)?;
    manifest.runner_sha256 = expected_sha256;
    save_bundle_manifest(bundle_root, manifest)
}

fn expected_runner_script(adapter: ProviderAdapterKind) -> &'static str {
    match adapter {
        ProviderAdapterKind::OpenAiOpfLocal => OPENAI_RUNNER_SCRIPT,
        ProviderAdapterKind::OpenAiMlxLocal => MLX_RUNNER_SCRIPT,
    }
}

fn install_openai_bundle(entry: &ProviderCatalogEntry, temp_bundle: &Path) -> Result<()> {
    let package = entry.package.as_ref().ok_or_else(|| {
        RedactError::Config(format!(
            "Provider '{}' is missing package metadata.",
            entry.target
        ))
    })?;
    let package_path = temp_bundle.join(package.bundle_rel);
    download_and_verify_artifact(package, &package_path)?;

    create_virtualenv(&temp_bundle.join("venv"))?;
    install_package_from_archive(temp_bundle, &package_path)?;

    for artifact in entry.model_artifacts {
        let path = temp_bundle.join(artifact.bundle_rel);
        download_and_verify_artifact(artifact, &path)?;
    }

    let runner_path = temp_bundle
        .join(PROVIDER_RUNNER_DIR)
        .join(OPENAI_RUNNER_SCRIPT_NAME);
    write_openai_runner_script(&runner_path)?;
    let runner_sha256 = sha256_hex_of_bytes(OPENAI_RUNNER_SCRIPT.as_bytes());
    let runner_executable_sha256 =
        sha256_hex_of_path(&temp_bundle.join(default_venv_python_rel()))?;
    let manifest = BundleManifest {
        schema_version: PROVIDER_SCHEMA_VERSION,
        target: entry.target.to_string(),
        provider: entry.provider.to_string(),
        model: entry.model.to_string(),
        adapter: entry.adapter.manifest_name().into(),
        runner_rel: default_venv_python_rel().into(),
        entry_rel: Some(
            Path::new(PROVIDER_RUNNER_DIR)
                .join(OPENAI_RUNNER_SCRIPT_NAME)
                .to_string_lossy()
                .into_owned(),
        ),
        checkpoint_rel: PROVIDER_MODEL_DIR.into(),
        runner_sha256,
        runner_executable_sha256: Some(runner_executable_sha256),
    };
    save_bundle_manifest(temp_bundle, &manifest)?;
    save_verified_state(
        temp_bundle,
        &VerifiedState {
            schema_version: PROVIDER_SCHEMA_VERSION,
            target: entry.target.into(),
            verified_unix_seconds: app_paths::unix_timestamp_now()?,
        },
    )?;
    Ok(())
}

fn install_mlx_bundle(entry: &ProviderCatalogEntry, temp_bundle: &Path) -> Result<()> {
    create_mlx_virtualenv(&temp_bundle.join("venv"))?;
    install_pypi_package(temp_bundle, MLX_EMBEDDINGS_PACKAGE)?;

    for artifact in entry.model_artifacts {
        let path = temp_bundle.join(artifact.bundle_rel);
        download_and_verify_artifact(artifact, &path)?;
    }

    let runner_path = temp_bundle
        .join(PROVIDER_RUNNER_DIR)
        .join(MLX_RUNNER_SCRIPT_NAME);
    write_mlx_runner_script(&runner_path)?;
    let runner_sha256 = sha256_hex_of_bytes(MLX_RUNNER_SCRIPT.as_bytes());
    let runner_executable_sha256 =
        sha256_hex_of_path(&temp_bundle.join(default_venv_python_rel()))?;
    let manifest = BundleManifest {
        schema_version: PROVIDER_SCHEMA_VERSION,
        target: entry.target.to_string(),
        provider: entry.provider.to_string(),
        model: entry.model.to_string(),
        adapter: entry.adapter.manifest_name().into(),
        runner_rel: default_venv_python_rel().into(),
        entry_rel: Some(
            Path::new(PROVIDER_RUNNER_DIR)
                .join(MLX_RUNNER_SCRIPT_NAME)
                .to_string_lossy()
                .into_owned(),
        ),
        checkpoint_rel: PROVIDER_MODEL_DIR.into(),
        runner_sha256,
        runner_executable_sha256: Some(runner_executable_sha256),
    };
    save_bundle_manifest(temp_bundle, &manifest)?;
    save_verified_state(
        temp_bundle,
        &VerifiedState {
            schema_version: PROVIDER_SCHEMA_VERSION,
            target: entry.target.into(),
            verified_unix_seconds: app_paths::unix_timestamp_now()?,
        },
    )?;
    Ok(())
}

fn download_and_verify_artifact(spec: &ArtifactSpec, path: &Path) -> Result<()> {
    download_file_via_python(spec.url, path)?;
    verify_artifact_at_path(spec, path)
}

fn verify_artifact_at_path(spec: &ArtifactSpec, path: &Path) -> Result<()> {
    let metadata = fs::metadata(path).map_err(|error| {
        RedactError::Config(format!(
            "Missing provider artifact '{}': {}",
            path.display(),
            error
        ))
    })?;
    if metadata.len() != spec.size_bytes {
        return Err(RedactError::Config(format!(
            "Provider artifact '{}' has unexpected size {} (expected {}).",
            path.display(),
            metadata.len(),
            spec.size_bytes
        )));
    }
    let actual_sha256 = sha256_hex_of_path(path)?;
    if actual_sha256 != spec.sha256 {
        return Err(RedactError::Config(format!(
            "Provider artifact '{}' failed SHA-256 verification.",
            path.display()
        )));
    }
    Ok(())
}

fn ensure_ready_bundle(entry: &'static ProviderCatalogEntry, bundle_root: &Path) -> Result<()> {
    if !is_bundle_installed(entry, bundle_root)? {
        return Err(RedactError::Usage(format!(
            "Provider bundle '{}' is not installed.\n  redacted provider enable {}",
            entry.target, entry.provider
        )));
    }
    if !has_verified_state(bundle_root)? {
        return Err(RedactError::Usage(format!(
            "Provider bundle '{}' has not been verified yet.\n  redacted provider verify {}",
            entry.target, entry.target
        )));
    }
    let mut manifest = load_bundle_manifest(&bundle_manifest_path(bundle_root))?;
    if !manifest_matches_entry(&manifest, entry)
        || manifest.adapter != entry.adapter.manifest_name()
    {
        return Err(RedactError::Config(format!(
            "Provider bundle at '{}' does not match target '{}'.",
            bundle_root.display(),
            entry.target
        )));
    }
    let paths = validate_bundle_paths(entry, bundle_root, &manifest)?;
    if !paths.runner.is_file() {
        return Err(RedactError::Config(format!(
            "Provider bundle '{}' is missing runner executable '{}'.",
            entry.target,
            paths.runner.display()
        )));
    }
    if let Some(entry_path) = paths.entry.as_ref() {
        if !entry_path.is_file() {
            return Err(RedactError::Config(format!(
                "Provider bundle '{}' is missing runner entry '{}'.",
                entry.target,
                entry_path.display()
            )));
        }
    }
    if !paths.checkpoint.exists() {
        return Err(RedactError::Config(format!(
            "Provider bundle '{}' is missing checkpoint path '{}'.",
            entry.target,
            paths.checkpoint.display()
        )));
    }
    verify_runner_integrity(entry, bundle_root, &mut manifest, &paths, false)?;
    Ok(())
}

fn validate_bundle_paths(
    entry: &'static ProviderCatalogEntry,
    bundle_root: &Path,
    manifest: &BundleManifest,
) -> Result<BundlePaths> {
    if adapter_uses_virtualenv(entry.adapter) {
        let expected_runner = default_venv_python_rel();
        if manifest.runner_rel != expected_runner {
            return Err(RedactError::Config(format!(
                "Provider bundle '{}' has unexpected runner path '{}'. Expected '{}'.",
                entry.target, manifest.runner_rel, expected_runner
            )));
        }
        let expected_entry = expected_entry_rel(entry.adapter);
        match (manifest.entry_rel.as_deref(), expected_entry) {
            (Some(actual), Some(expected)) if actual == expected => {}
            (Some(actual), Some(expected)) => {
                return Err(RedactError::Config(format!(
                    "Provider bundle '{}' has unexpected runner entry '{}'. Expected '{}'.",
                    entry.target, actual, expected
                )));
            }
            _ => {
                return Err(RedactError::Config(format!(
                    "Provider bundle '{}' is missing runner entry metadata.",
                    entry.target
                )));
            }
        }
    }

    let runner = bundle_child_path(bundle_root, &manifest.runner_rel, "runner_rel")?;
    let entry_path = manifest
        .entry_rel
        .as_deref()
        .map(|entry_rel| bundle_child_path(bundle_root, entry_rel, "entry_rel"))
        .transpose()?;
    let checkpoint = bundle_child_path(bundle_root, &manifest.checkpoint_rel, "checkpoint_rel")?;
    Ok(BundlePaths {
        runner,
        entry: entry_path,
        checkpoint,
    })
}

fn expected_entry_rel(adapter: ProviderAdapterKind) -> Option<&'static str> {
    match adapter {
        ProviderAdapterKind::OpenAiOpfLocal => Some("runner/openai_privacy_runner.py"),
        ProviderAdapterKind::OpenAiMlxLocal => Some("runner/mlx_privacy_runner.py"),
    }
}

fn bundle_child_path(bundle_root: &Path, rel: &str, field: &str) -> Result<PathBuf> {
    let rel_path = Path::new(rel);
    if rel.is_empty() || rel_path.is_absolute() {
        return Err(RedactError::Config(format!(
            "Provider manifest field '{}' must be a relative path inside the bundle.",
            field
        )));
    }
    for component in rel_path.components() {
        match component {
            Component::Normal(_) | Component::CurDir => {}
            _ => {
                return Err(RedactError::Config(format!(
                    "Provider manifest field '{}' must stay inside the bundle.",
                    field
                )));
            }
        }
    }
    Ok(bundle_root.join(rel_path))
}

fn verify_runner_integrity(
    entry: &'static ProviderCatalogEntry,
    bundle_root: &Path,
    manifest: &mut BundleManifest,
    paths: &BundlePaths,
    allow_manifest_repair: bool,
) -> Result<()> {
    if let Some(entry_path) = paths.entry.as_ref() {
        verify_sha256(entry_path, &manifest.runner_sha256, "Provider runner entry")?;
        let actual_runner_sha256 = sha256_hex_of_path(&paths.runner)?;
        match manifest.runner_executable_sha256.as_ref() {
            Some(expected) if expected == &actual_runner_sha256 => Ok(()),
            Some(_) => Err(RedactError::Config(format!(
                "Provider runner executable '{}' failed integrity verification.",
                paths.runner.display()
            ))),
            None if allow_manifest_repair => {
                manifest.runner_executable_sha256 = Some(actual_runner_sha256);
                save_bundle_manifest(bundle_root, manifest)
            }
            None => Err(RedactError::Config(format!(
                "Provider bundle '{}' is missing launched runner integrity metadata.\n  redacted provider verify {}",
                entry.target, entry.target
            ))),
        }
    } else {
        verify_sha256(&paths.runner, &manifest.runner_sha256, "Provider runner")
    }
}

fn verify_sha256(path: &Path, expected: &str, label: &str) -> Result<()> {
    if !path.is_file() {
        return Err(RedactError::Config(format!(
            "{} integrity target '{}' is missing.",
            label,
            path.display()
        )));
    }
    let actual = sha256_hex_of_path(path)?;
    if actual != expected {
        return Err(RedactError::Config(format!(
            "{} '{}' failed integrity verification.",
            label,
            path.display()
        )));
    }
    Ok(())
}

fn repair_bundle_runtime_paths(bundle_root: &Path) -> Result<()> {
    let current_root = bundle_root.to_string_lossy().into_owned();
    let Some(embedded_root) = detect_embedded_bundle_root(bundle_root)? else {
        return Ok(());
    };
    if embedded_root == current_root {
        return Ok(());
    }

    for path in bundle_runtime_rewrite_candidates(bundle_root)? {
        rewrite_bundle_root_in_text_file(&path, &embedded_root, &current_root)?;
    }
    Ok(())
}

fn detect_embedded_bundle_root(bundle_root: &Path) -> Result<Option<String>> {
    let pyvenv_path = bundle_root.join("venv").join("pyvenv.cfg");
    if pyvenv_path.is_file() {
        let content = fs::read_to_string(&pyvenv_path).map_err(|error| {
            RedactError::Config(format!(
                "Cannot read virtualenv metadata '{}': {}",
                pyvenv_path.display(),
                error
            ))
        })?;
        for line in content.lines() {
            let Some((key, value)) = line.split_once('=') else {
                continue;
            };
            if key.trim() != "command" {
                continue;
            }
            if let Some((_, venv_path)) = value.trim().rsplit_once(" -m venv ") {
                if let Some(root) = strip_virtualenv_suffix(venv_path) {
                    return Ok(Some(root.to_string()));
                }
            }
        }
    }

    for scripts_dir in bundle_runtime_script_dirs(bundle_root) {
        if !scripts_dir.is_dir() {
            continue;
        }
        for entry in fs::read_dir(&scripts_dir).map_err(|error| {
            RedactError::Config(format!(
                "Cannot list runtime scripts in '{}': {}",
                scripts_dir.display(),
                error
            ))
        })? {
            let path = entry
                .map_err(|error| {
                    RedactError::Config(format!(
                        "Cannot inspect runtime script entry in '{}': {}",
                        scripts_dir.display(),
                        error
                    ))
                })?
                .path();
            if !path.is_file() {
                continue;
            }
            let Some(first_line) = read_first_line(&path)? else {
                continue;
            };
            if !first_line.starts_with("#!") {
                continue;
            }
            let interpreter = &first_line[2..];
            if let Some(index) = interpreter.find("/venv/") {
                return Ok(Some(interpreter[..index].to_string()));
            }
            if let Some(index) = interpreter.find("\\venv\\") {
                return Ok(Some(interpreter[..index].to_string()));
            }
        }
    }

    Ok(None)
}

fn strip_virtualenv_suffix(path: &str) -> Option<&str> {
    path.strip_suffix("/venv")
        .or_else(|| path.strip_suffix("\\venv"))
}

fn bundle_runtime_rewrite_candidates(bundle_root: &Path) -> Result<Vec<PathBuf>> {
    let mut paths = Vec::new();
    let pyvenv_path = bundle_root.join("venv").join("pyvenv.cfg");
    if pyvenv_path.is_file() {
        paths.push(pyvenv_path);
    }

    for scripts_dir in bundle_runtime_script_dirs(bundle_root) {
        if !scripts_dir.is_dir() {
            continue;
        }
        for entry in fs::read_dir(&scripts_dir).map_err(|error| {
            RedactError::Config(format!(
                "Cannot list runtime scripts in '{}': {}",
                scripts_dir.display(),
                error
            ))
        })? {
            let path = entry
                .map_err(|error| {
                    RedactError::Config(format!(
                        "Cannot inspect runtime script entry in '{}': {}",
                        scripts_dir.display(),
                        error
                    ))
                })?
                .path();
            if path.is_file() {
                paths.push(path);
            }
        }
    }

    let venv_root = bundle_root.join("venv");
    if venv_root.is_dir() {
        collect_named_files(&venv_root, "direct_url.json", &mut paths)?;
    }

    Ok(paths)
}

fn bundle_runtime_script_dirs(bundle_root: &Path) -> [PathBuf; 2] {
    [
        bundle_root.join("venv").join("bin"),
        bundle_root.join("venv").join("Scripts"),
    ]
}

fn collect_named_files(root: &Path, file_name: &str, output: &mut Vec<PathBuf>) -> Result<()> {
    for entry in fs::read_dir(root).map_err(|error| {
        RedactError::Config(format!("Cannot list '{}': {}", root.display(), error))
    })? {
        let path = entry
            .map_err(|error| {
                RedactError::Config(format!(
                    "Cannot inspect entry under '{}': {}",
                    root.display(),
                    error
                ))
            })?
            .path();
        if path.is_dir() {
            collect_named_files(&path, file_name, output)?;
        } else if path
            .file_name()
            .and_then(|name| name.to_str())
            .map(|name| name == file_name)
            .unwrap_or(false)
        {
            output.push(path);
        }
    }
    Ok(())
}

fn read_first_line(path: &Path) -> Result<Option<String>> {
    let content = fs::read(path).map_err(|error| {
        RedactError::Config(format!("Cannot read '{}': {}", path.display(), error))
    })?;
    if content.is_empty() {
        return Ok(None);
    }
    let text = match std::str::from_utf8(&content) {
        Ok(value) => value,
        Err(_) => return Ok(None),
    };
    Ok(text.lines().next().map(ToString::to_string))
}

fn rewrite_bundle_root_in_text_file(path: &Path, old_root: &str, new_root: &str) -> Result<()> {
    let content = fs::read(path).map_err(|error| {
        RedactError::Config(format!("Cannot read '{}': {}", path.display(), error))
    })?;
    if !content
        .windows(old_root.len())
        .any(|window| window == old_root.as_bytes())
    {
        return Ok(());
    }
    let text = match String::from_utf8(content) {
        Ok(value) => value,
        Err(_) => return Ok(()),
    };
    let rewritten = text.replace(old_root, new_root);
    if rewritten == text {
        return Ok(());
    }

    let permissions = fs::metadata(path)
        .map_err(|error| {
            RedactError::Config(format!("Cannot inspect '{}': {}", path.display(), error))
        })?
        .permissions();
    fs::write(path, rewritten).map_err(|error| {
        RedactError::Config(format!("Cannot rewrite '{}': {}", path.display(), error))
    })?;
    fs::set_permissions(path, permissions).map_err(|error| {
        RedactError::Config(format!(
            "Cannot restore permissions on '{}': {}",
            path.display(),
            error
        ))
    })?;
    Ok(())
}

fn is_bundle_installed(entry: &'static ProviderCatalogEntry, bundle_root: &Path) -> Result<bool> {
    if !bundle_root.exists() {
        return Ok(false);
    }
    let manifest_path = bundle_manifest_path(bundle_root);
    if !manifest_path.is_file() {
        return Ok(false);
    }
    let manifest = load_bundle_manifest(&manifest_path)?;
    Ok(manifest_matches_entry(&manifest, entry))
}

fn manifest_matches_entry(manifest: &BundleManifest, entry: &'static ProviderCatalogEntry) -> bool {
    manifest.target == entry.target || entry.legacy_targets.contains(&manifest.target.as_str())
}

fn has_verified_state(bundle_root: &Path) -> Result<bool> {
    let path = verified_state_path(bundle_root);
    if !path.exists() {
        return Ok(false);
    }
    let state = load_verified_state(&path)?;
    Ok(state.schema_version == PROVIDER_SCHEMA_VERSION && !state.target.is_empty())
}

fn activate_target(entry: &'static ProviderCatalogEntry) -> Result<()> {
    let config_root = app_paths::config_root()?;
    fs::create_dir_all(&config_root).map_err(|error| {
        RedactError::Config(format!(
            "Cannot create provider config directory '{}': {}",
            config_root.display(),
            error
        ))
    })?;
    save_active_provider_state(&ActiveProviderState {
        target: entry.target.into(),
    })
}

fn clear_active_provider_state() -> Result<()> {
    let path = active_provider_state_path()?;
    if path.exists() {
        fs::remove_file(&path).map_err(|error| {
            RedactError::Config(format!(
                "Cannot remove active provider state '{}': {}",
                path.display(),
                error
            ))
        })?;
    }
    Ok(())
}

fn save_active_provider_state(state: &ActiveProviderState) -> Result<()> {
    let path = active_provider_state_path()?;
    let content = format!("target={}\n", state.target);
    io_safe::atomic_write(&path, &content)
}

fn load_active_provider_state() -> Result<Option<ActiveProviderState>> {
    let path = active_provider_state_path()?;
    if !path.exists() {
        return Ok(None);
    }
    let values = app_paths::parse_key_value_file(&path, "provider")?;
    let target = values.get("target").cloned().ok_or_else(|| {
        RedactError::Config(format!(
            "Provider state file '{}' is missing target.",
            path.display()
        ))
    })?;
    Ok(Some(ActiveProviderState { target }))
}

fn save_bundle_manifest(bundle_root: &Path, manifest: &BundleManifest) -> Result<()> {
    let path = bundle_manifest_path(bundle_root);
    let mut content = String::new();
    content.push_str(&format!("schema_version={}\n", manifest.schema_version));
    content.push_str(&format!("target={}\n", manifest.target));
    content.push_str(&format!("provider={}\n", manifest.provider));
    content.push_str(&format!("model={}\n", manifest.model));
    content.push_str(&format!("adapter={}\n", manifest.adapter));
    content.push_str(&format!("runner_rel={}\n", manifest.runner_rel));
    if let Some(entry_rel) = manifest.entry_rel.as_ref() {
        content.push_str(&format!("entry_rel={}\n", entry_rel));
    }
    content.push_str(&format!("checkpoint_rel={}\n", manifest.checkpoint_rel));
    content.push_str(&format!("runner_sha256={}\n", manifest.runner_sha256));
    if let Some(runner_executable_sha256) = manifest.runner_executable_sha256.as_ref() {
        content.push_str(&format!(
            "runner_executable_sha256={}\n",
            runner_executable_sha256
        ));
    }
    io_safe::atomic_write(&path, &content)
}

fn load_bundle_manifest(path: &Path) -> Result<BundleManifest> {
    let values = app_paths::parse_key_value_file(path, "provider")?;
    let adapter = values
        .get("adapter")
        .cloned()
        .or_else(|| infer_legacy_manifest_adapter(&values))
        .ok_or_else(|| {
            RedactError::Config(format!(
                "Provider metadata '{}' is missing key 'adapter'.",
                path.display()
            ))
        })?;
    Ok(BundleManifest {
        schema_version: app_paths::parse_required_u32(&values, "schema_version", path, "provider")?,
        target: app_paths::parse_required_value(&values, "target", path, "provider")?,
        provider: app_paths::parse_required_value(&values, "provider", path, "provider")?,
        model: app_paths::parse_required_value(&values, "model", path, "provider")?,
        adapter,
        runner_rel: app_paths::parse_required_value(&values, "runner_rel", path, "provider")?,
        entry_rel: values.get("entry_rel").cloned(),
        checkpoint_rel: app_paths::parse_required_value(
            &values,
            "checkpoint_rel",
            path,
            "provider",
        )?,
        runner_sha256: app_paths::parse_required_value(&values, "runner_sha256", path, "provider")?,
        runner_executable_sha256: values.get("runner_executable_sha256").cloned(),
    })
}

fn infer_legacy_manifest_adapter(values: &HashMap<String, String>) -> Option<String> {
    let target = values.get("target")?;
    find_catalog_entry_by_target(target).map(|entry| entry.adapter.manifest_name().to_string())
}

fn save_verified_state(bundle_root: &Path, state: &VerifiedState) -> Result<()> {
    let path = verified_state_path(bundle_root);
    let content = format!(
        "schema_version={}\ntarget={}\nverified_unix_seconds={}\n",
        state.schema_version, state.target, state.verified_unix_seconds
    );
    io_safe::atomic_write(&path, &content)
}

fn load_verified_state(path: &Path) -> Result<VerifiedState> {
    let values = app_paths::parse_key_value_file(path, "provider")?;
    Ok(VerifiedState {
        schema_version: app_paths::parse_required_u32(&values, "schema_version", path, "provider")?,
        target: app_paths::parse_required_value(&values, "target", path, "provider")?,
        verified_unix_seconds: app_paths::parse_required_u64(
            &values,
            "verified_unix_seconds",
            path,
            "provider",
        )?,
    })
}

fn bundle_manifest_path(bundle_root: &Path) -> PathBuf {
    bundle_root.join(PROVIDER_BUNDLE_MANIFEST_FILE)
}

fn verified_state_path(bundle_root: &Path) -> PathBuf {
    bundle_root.join(VERIFIED_PROVIDER_STATE_FILE)
}

fn active_provider_state_path() -> Result<PathBuf> {
    Ok(app_paths::config_root()?.join(ACTIVE_PROVIDER_STATE_FILE))
}

fn bundle_root_for_entry(entry: &ProviderCatalogEntry) -> Result<PathBuf> {
    Ok(providers_root()?.join(entry.provider).join(entry.model))
}

fn install_temp_bundle_path(entry: &ProviderCatalogEntry) -> Result<PathBuf> {
    let now = app_paths::unix_timestamp_now()?;
    Ok(providers_root()?.join(format!(
        ".install-{}-{}-{}",
        entry.provider, entry.model, now
    )))
}

fn providers_root() -> Result<PathBuf> {
    Ok(app_paths::data_root()?.join(PROVIDER_BUNDLES_DIR))
}

fn resolve_catalog_entry(selector: &str) -> Result<&'static ProviderCatalogEntry> {
    if selector.contains('/') {
        return find_catalog_entry_by_target(selector).ok_or_else(|| {
            RedactError::Usage(format!(
                "Unknown provider target '{}'.\n  redacted provider list",
                selector
            ))
        });
    }
    let mut matches = PROVIDER_CATALOG
        .iter()
        .filter(|entry| entry.aliases.contains(&selector));
    let entry = matches.next().ok_or_else(|| {
        RedactError::Usage(format!(
            "Unknown provider alias '{}'.\n  redacted provider list",
            selector
        ))
    })?;
    if matches.next().is_some() {
        return Err(RedactError::Usage(format!(
            "Provider alias '{}' is ambiguous.\n  redacted provider list",
            selector
        )));
    }
    Ok(entry)
}

fn find_catalog_entry_by_target(target: &str) -> Option<&'static ProviderCatalogEntry> {
    PROVIDER_CATALOG
        .iter()
        .find(|entry| entry.target == target || entry.legacy_targets.contains(&target))
}

fn default_venv_python_rel() -> &'static str {
    if cfg!(windows) {
        "venv/Scripts/python.exe"
    } else {
        "venv/bin/python"
    }
}

fn create_virtualenv(venv_path: &Path) -> Result<()> {
    let python = system_python_command();
    create_virtualenv_with_python(&python, venv_path)
}

fn create_mlx_virtualenv(venv_path: &Path) -> Result<()> {
    let python = mlx_python_command()?;
    create_virtualenv_with_python(&python, venv_path)
}

fn create_virtualenv_with_python(python: &str, venv_path: &Path) -> Result<()> {
    let output = Command::new(python)
        .arg("-m")
        .arg("venv")
        .arg(venv_path)
        .output()
        .map_err(|error| {
            RedactError::Config(format!("Failed to start '{} -m venv': {}", python, error))
        })?;
    if !output.status.success() {
        return Err(RedactError::Config(format!(
            "Virtualenv creation failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    Ok(())
}

fn mlx_python_command() -> Result<String> {
    if let Ok(python) = std::env::var(REDACTED_PROVIDER_PYTHON_OVERRIDE) {
        if python_version_at_least(&python, 3, 10)? {
            return Ok(python);
        }
        return Err(RedactError::Config(format!(
            "MLX provider requires Python 3.10 or newer, but '{}' is older.",
            python
        )));
    }

    for candidate in ["python3.12", "python3.11", "python3.10", "python3"] {
        if python_version_at_least(candidate, 3, 10).unwrap_or(false) {
            return Ok(candidate.into());
        }
    }

    Err(RedactError::Config(
        "MLX provider requires Python 3.10 or newer. Install Python 3.10+ or set REDACTED_PROVIDER_PYTHON.".into(),
    ))
}

fn python_version_at_least(python: &str, major: u32, minor: u32) -> Result<bool> {
    let output = Command::new(python)
        .arg("-c")
        .arg("import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
        .output()
        .map_err(|error| {
            RedactError::Config(format!(
                "Failed to check Python version for '{}': {}",
                python, error
            ))
        })?;
    if !output.status.success() {
        return Ok(false);
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let version = stdout.trim();
    let Some((actual_major, actual_minor)) = version.split_once('.') else {
        return Ok(false);
    };
    let actual_major = actual_major.parse::<u32>().map_err(|error| {
        RedactError::Config(format!(
            "Cannot parse Python major version '{}': {}",
            actual_major, error
        ))
    })?;
    let actual_minor = actual_minor.parse::<u32>().map_err(|error| {
        RedactError::Config(format!(
            "Cannot parse Python minor version '{}': {}",
            actual_minor, error
        ))
    })?;
    Ok((actual_major, actual_minor) >= (major, minor))
}

fn install_package_from_archive(bundle_root: &Path, archive_path: &Path) -> Result<()> {
    let python = bundle_root.join(default_venv_python_rel());
    let output = Command::new(&python)
        .arg("-m")
        .arg("pip")
        .arg("install")
        .arg("--disable-pip-version-check")
        .arg("--no-input")
        .arg(archive_path)
        .output()
        .map_err(|error| {
            RedactError::Config(format!(
                "Failed to start pip install for '{}': {}",
                archive_path.display(),
                error
            ))
        })?;
    if !output.status.success() {
        return Err(RedactError::Config(format!(
            "Provider package installation failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    Ok(())
}

fn install_pypi_package(bundle_root: &Path, package: &str) -> Result<()> {
    let python = bundle_root.join(default_venv_python_rel());
    let output = Command::new(&python)
        .arg("-m")
        .arg("pip")
        .arg("install")
        .arg("--disable-pip-version-check")
        .arg("--no-input")
        .arg(package)
        .output()
        .map_err(|error| {
            RedactError::Config(format!(
                "Failed to start pip install for '{}': {}",
                package, error
            ))
        })?;
    if !output.status.success() {
        return Err(RedactError::Config(format!(
            "Provider package installation failed for '{}': {}",
            package,
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    Ok(())
}

fn write_openai_runner_script(path: &Path) -> Result<()> {
    io_safe::atomic_write(path, OPENAI_RUNNER_SCRIPT)
}

fn write_mlx_runner_script(path: &Path) -> Result<()> {
    io_safe::atomic_write(path, MLX_RUNNER_SCRIPT)
}

fn system_python_command() -> String {
    std::env::var(REDACTED_PROVIDER_PYTHON_OVERRIDE).unwrap_or_else(|_| "python3".into())
}

fn download_file_via_python(url: &str, destination: &Path) -> Result<()> {
    let python = system_python_command();
    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent).map_err(|error| {
            RedactError::Config(format!(
                "Cannot create download directory '{}': {}",
                parent.display(),
                error
            ))
        })?;
    }
    let output = Command::new(&python)
        .arg("-c")
        .arg(
            r#"import pathlib, shutil, sys, urllib.request
url = sys.argv[1]
dest = pathlib.Path(sys.argv[2])
dest.parent.mkdir(parents=True, exist_ok=True)
with urllib.request.urlopen(url, timeout=60) as response, open(dest, "wb") as handle:
    shutil.copyfileobj(response, handle, length=1024 * 1024)
"#,
        )
        .arg(url)
        .arg(destination)
        .output()
        .map_err(|error| {
            RedactError::Config(format!(
                "Failed to start download helper '{}': {}",
                python, error
            ))
        })?;
    if !output.status.success() {
        return Err(RedactError::Config(format!(
            "Failed to download '{}': {}",
            url,
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    Ok(())
}

fn parse_provider_response(line: &str) -> Result<ProviderResponse> {
    let value = JsonParser::new(line).parse().map_err(|message| {
        RedactError::Detection(format!("Invalid provider response JSON: {}", message))
    })?;
    let object = value
        .as_object()
        .ok_or_else(|| RedactError::Detection("Provider response must be a JSON object.".into()))?;
    let schema_version = object
        .get("schema_version")
        .and_then(JsonValue::as_u32)
        .ok_or_else(|| {
            RedactError::Detection("Provider response is missing schema_version.".into())
        })?;
    let request_id = object
        .get("request_id")
        .and_then(JsonValue::as_str)
        .ok_or_else(|| RedactError::Detection("Provider response is missing request_id.".into()))?
        .to_string();
    let target = object
        .get("target")
        .and_then(JsonValue::as_str)
        .ok_or_else(|| RedactError::Detection("Provider response is missing target.".into()))?
        .to_string();
    let error = object
        .get("error")
        .and_then(JsonValue::as_str)
        .map(ToString::to_string);
    let spans = object
        .get("spans")
        .and_then(JsonValue::as_array)
        .ok_or_else(|| RedactError::Detection("Provider response is missing spans.".into()))?
        .iter()
        .map(parse_provider_span)
        .collect::<Result<Vec<_>>>()?;
    Ok(ProviderResponse {
        schema_version,
        request_id,
        target,
        spans,
        error,
    })
}

fn parse_provider_span(value: &JsonValue) -> Result<ProviderSpan> {
    let object = value.as_object().ok_or_else(|| {
        RedactError::Detection("Provider span entry must be a JSON object.".into())
    })?;
    let label = object
        .get("label")
        .and_then(JsonValue::as_str)
        .ok_or_else(|| RedactError::Detection("Provider span is missing label.".into()))?
        .to_string();
    let start = object
        .get("start")
        .and_then(JsonValue::as_usize)
        .ok_or_else(|| RedactError::Detection("Provider span is missing start.".into()))?;
    let end = object
        .get("end")
        .and_then(JsonValue::as_usize)
        .ok_or_else(|| RedactError::Detection("Provider span is missing end.".into()))?;
    Ok(ProviderSpan { label, start, end })
}

#[derive(Debug, Clone)]
enum JsonValue {
    Object(HashMap<String, JsonValue>),
    Array(Vec<JsonValue>),
    String(String),
    Number(i64),
    Bool,
    Null,
}

impl JsonValue {
    fn as_object(&self) -> Option<&HashMap<String, JsonValue>> {
        match self {
            Self::Object(value) => Some(value),
            _ => None,
        }
    }

    fn as_array(&self) -> Option<&Vec<JsonValue>> {
        match self {
            Self::Array(value) => Some(value),
            _ => None,
        }
    }

    fn as_str(&self) -> Option<&str> {
        match self {
            Self::String(value) => Some(value),
            _ => None,
        }
    }

    fn as_u32(&self) -> Option<u32> {
        match self {
            Self::Number(value) => u32::try_from(*value).ok(),
            _ => None,
        }
    }

    fn as_usize(&self) -> Option<usize> {
        match self {
            Self::Number(value) => usize::try_from(*value).ok(),
            _ => None,
        }
    }
}

struct JsonParser<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> JsonParser<'a> {
    fn new(input: &'a str) -> Self {
        Self {
            bytes: input.as_bytes(),
            position: 0,
        }
    }

    fn parse(mut self) -> std::result::Result<JsonValue, String> {
        let value = self.parse_value()?;
        self.skip_whitespace();
        if self.position != self.bytes.len() {
            return Err("trailing characters after JSON value".into());
        }
        Ok(value)
    }

    fn parse_value(&mut self) -> std::result::Result<JsonValue, String> {
        self.skip_whitespace();
        match self.peek_byte() {
            Some(b'{') => self.parse_object(),
            Some(b'[') => self.parse_array(),
            Some(b'"') => self.parse_string().map(JsonValue::String),
            Some(b'-') | Some(b'0'..=b'9') => self.parse_number().map(JsonValue::Number),
            Some(b't') => {
                self.expect_bytes(b"true")?;
                Ok(JsonValue::Bool)
            }
            Some(b'f') => {
                self.expect_bytes(b"false")?;
                Ok(JsonValue::Bool)
            }
            Some(b'n') => {
                self.expect_bytes(b"null")?;
                Ok(JsonValue::Null)
            }
            Some(other) => Err(format!("unexpected byte '{}'", other as char)),
            None => Err("unexpected end of input".into()),
        }
    }

    fn parse_object(&mut self) -> std::result::Result<JsonValue, String> {
        self.expect_byte(b'{')?;
        let mut object = HashMap::new();
        self.skip_whitespace();
        if self.consume_if(b'}') {
            return Ok(JsonValue::Object(object));
        }
        loop {
            self.skip_whitespace();
            let key = self.parse_string()?;
            self.skip_whitespace();
            self.expect_byte(b':')?;
            let value = self.parse_value()?;
            object.insert(key, value);
            self.skip_whitespace();
            if self.consume_if(b'}') {
                break;
            }
            self.expect_byte(b',')?;
        }
        Ok(JsonValue::Object(object))
    }

    fn parse_array(&mut self) -> std::result::Result<JsonValue, String> {
        self.expect_byte(b'[')?;
        let mut values = Vec::new();
        self.skip_whitespace();
        if self.consume_if(b']') {
            return Ok(JsonValue::Array(values));
        }
        loop {
            values.push(self.parse_value()?);
            self.skip_whitespace();
            if self.consume_if(b']') {
                break;
            }
            self.expect_byte(b',')?;
        }
        Ok(JsonValue::Array(values))
    }

    fn parse_string(&mut self) -> std::result::Result<String, String> {
        self.expect_byte(b'"')?;
        let mut output = String::new();
        while let Some(byte) = self.next_byte() {
            match byte {
                b'"' => return Ok(output),
                b'\\' => {
                    let escaped = self
                        .next_byte()
                        .ok_or_else(|| "unterminated escape sequence".to_string())?;
                    match escaped {
                        b'"' => output.push('"'),
                        b'\\' => output.push('\\'),
                        b'/' => output.push('/'),
                        b'b' => output.push('\u{0008}'),
                        b'f' => output.push('\u{000C}'),
                        b'n' => output.push('\n'),
                        b'r' => output.push('\r'),
                        b't' => output.push('\t'),
                        b'u' => {
                            let code_point = self.parse_unicode_escape()?;
                            let character = char::from_u32(code_point)
                                .ok_or_else(|| "invalid unicode escape".to_string())?;
                            output.push(character);
                        }
                        other => {
                            return Err(format!("unsupported escape byte '{}'", other as char));
                        }
                    }
                }
                other => output.push(other as char),
            }
        }
        Err("unterminated string".into())
    }

    fn parse_unicode_escape(&mut self) -> std::result::Result<u32, String> {
        let mut value = 0u32;
        for _ in 0..4 {
            let byte = self
                .next_byte()
                .ok_or_else(|| "unterminated unicode escape".to_string())?;
            value <<= 4;
            value |= match byte {
                b'0'..=b'9' => u32::from(byte - b'0'),
                b'a'..=b'f' => u32::from(byte - b'a') + 10,
                b'A'..=b'F' => u32::from(byte - b'A') + 10,
                other => {
                    return Err(format!("invalid unicode escape byte '{}'", other as char));
                }
            };
        }
        Ok(value)
    }

    fn parse_number(&mut self) -> std::result::Result<i64, String> {
        let start = self.position;
        if self.peek_byte() == Some(b'-') {
            self.position += 1;
        }
        while matches!(self.peek_byte(), Some(b'0'..=b'9')) {
            self.position += 1;
        }
        let text = std::str::from_utf8(&self.bytes[start..self.position])
            .map_err(|_| "invalid number".to_string())?;
        text.parse::<i64>()
            .map_err(|_| format!("invalid number '{}'", text))
    }

    fn expect_bytes(&mut self, expected: &[u8]) -> std::result::Result<(), String> {
        for byte in expected {
            self.expect_byte(*byte)?;
        }
        Ok(())
    }

    fn expect_byte(&mut self, expected: u8) -> std::result::Result<(), String> {
        let byte = self
            .next_byte()
            .ok_or_else(|| format!("expected byte '{}'", expected as char))?;
        if byte != expected {
            return Err(format!(
                "expected byte '{}', got '{}'",
                expected as char, byte as char
            ));
        }
        Ok(())
    }

    fn consume_if(&mut self, expected: u8) -> bool {
        if self.peek_byte() == Some(expected) {
            self.position += 1;
            true
        } else {
            false
        }
    }

    fn skip_whitespace(&mut self) {
        while matches!(self.peek_byte(), Some(b' ' | b'\n' | b'\r' | b'\t')) {
            self.position += 1;
        }
    }

    fn peek_byte(&self) -> Option<u8> {
        self.bytes.get(self.position).copied()
    }

    fn next_byte(&mut self) -> Option<u8> {
        let byte = self.peek_byte()?;
        self.position += 1;
        Some(byte)
    }
}

fn sha256_hex_of_path(path: &Path) -> Result<String> {
    let mut file = fs::File::open(path).map_err(|error| {
        RedactError::Config(format!(
            "Cannot open '{}' for SHA-256: {}",
            path.display(),
            error
        ))
    })?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let bytes_read = file.read(&mut buffer).map_err(|error| {
            RedactError::Config(format!(
                "Cannot read '{}' for SHA-256: {}",
                path.display(),
                error
            ))
        })?;
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buffer[..bytes_read]);
    }
    Ok(hasher.finalize_hex())
}

fn sha256_hex_of_bytes(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher.finalize_hex()
}

struct Sha256 {
    state: [u32; 8],
    length_bits: u64,
    buffer: [u8; 64],
    buffer_len: usize,
}

impl Sha256 {
    fn new() -> Self {
        Self {
            state: [
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
                0x5be0cd19,
            ],
            length_bits: 0,
            buffer: [0; 64],
            buffer_len: 0,
        }
    }

    fn update(&mut self, mut input: &[u8]) {
        self.length_bits = self.length_bits.wrapping_add((input.len() as u64) * 8);

        if self.buffer_len > 0 {
            let take = std::cmp::min(64 - self.buffer_len, input.len());
            self.buffer[self.buffer_len..self.buffer_len + take].copy_from_slice(&input[..take]);
            self.buffer_len += take;
            input = &input[take..];
            if self.buffer_len == 64 {
                Self::process_block(&mut self.state, &self.buffer);
                self.buffer_len = 0;
            }
        }

        while input.len() >= 64 {
            let mut block = [0u8; 64];
            block.copy_from_slice(&input[..64]);
            Self::process_block(&mut self.state, &block);
            input = &input[64..];
        }

        if !input.is_empty() {
            self.buffer[..input.len()].copy_from_slice(input);
            self.buffer_len = input.len();
        }
    }

    fn finalize_hex(mut self) -> String {
        self.buffer[self.buffer_len] = 0x80;
        self.buffer_len += 1;

        if self.buffer_len > 56 {
            for byte in &mut self.buffer[self.buffer_len..] {
                *byte = 0;
            }
            Self::process_block(&mut self.state, &self.buffer);
            self.buffer = [0; 64];
            self.buffer_len = 0;
        }

        for byte in &mut self.buffer[self.buffer_len..56] {
            *byte = 0;
        }
        self.buffer[56..64].copy_from_slice(&self.length_bits.to_be_bytes());
        Self::process_block(&mut self.state, &self.buffer);

        let mut output = String::with_capacity(64);
        for word in self.state {
            output.push_str(&format!("{:08x}", word));
        }
        output
    }

    fn process_block(state: &mut [u32; 8], block: &[u8; 64]) {
        const ROUND_CONSTANTS: [u32; 64] = [
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
            0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
            0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
            0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
            0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
            0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
            0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
            0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
            0xc67178f2,
        ];

        let mut schedule = [0u32; 64];
        for (index, slot) in schedule.iter_mut().enumerate().take(16) {
            let offset = index * 4;
            *slot = u32::from_be_bytes([
                block[offset],
                block[offset + 1],
                block[offset + 2],
                block[offset + 3],
            ]);
        }
        for index in 16..64 {
            let s0 = schedule[index - 15].rotate_right(7)
                ^ schedule[index - 15].rotate_right(18)
                ^ (schedule[index - 15] >> 3);
            let s1 = schedule[index - 2].rotate_right(17)
                ^ schedule[index - 2].rotate_right(19)
                ^ (schedule[index - 2] >> 10);
            schedule[index] = schedule[index - 16]
                .wrapping_add(s0)
                .wrapping_add(schedule[index - 7])
                .wrapping_add(s1);
        }

        let mut a = state[0];
        let mut b = state[1];
        let mut c = state[2];
        let mut d = state[3];
        let mut e = state[4];
        let mut f = state[5];
        let mut g = state[6];
        let mut h = state[7];

        for index in 0..64 {
            let sum1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let choose = (e & f) ^ ((!e) & g);
            let temp1 = h
                .wrapping_add(sum1)
                .wrapping_add(choose)
                .wrapping_add(ROUND_CONSTANTS[index])
                .wrapping_add(schedule[index]);
            let sum0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let majority = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = sum0.wrapping_add(majority);

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        state[0] = state[0].wrapping_add(a);
        state[1] = state[1].wrapping_add(b);
        state[2] = state[2].wrapping_add(c);
        state[3] = state[3].wrapping_add(d);
        state[4] = state[4].wrapping_add(e);
        state[5] = state[5].wrapping_add(f);
        state[6] = state[6].wrapping_add(g);
        state[7] = state[7].wrapping_add(h);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    fn temp_path(name: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!("redacted_provider_test_{}", name));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        root
    }

    #[test]
    fn resolve_openai_alias_to_default_target() {
        let entry = resolve_catalog_entry("openai").unwrap();
        assert_eq!(entry.target, OPENAI_PRIVACY_TARGET);
    }

    #[test]
    fn resolve_mlx_alias_to_exact_runtime_target() {
        let entry = resolve_catalog_entry("mlx").unwrap();
        assert_eq!(entry.target, OPENAI_PRIVACY_MLX_TARGET);
        assert_eq!(entry.adapter, ProviderAdapterKind::OpenAiMlxLocal);
    }

    #[test]
    fn sha256_matches_known_vector() {
        assert_eq!(
            sha256_hex_of_bytes(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn json_parser_handles_provider_response() {
        let response = parse_provider_response(
            r#"{"schema_version":1,"request_id":"req-1","target":"openai/privacy-filter-v1","spans":[{"label":"private_email","start":1,"end":3}]}"#,
        )
        .unwrap();
        assert_eq!(response.request_id, "req-1");
        assert_eq!(response.spans.len(), 1);
        assert_eq!(response.spans[0].label, "private_email");
    }

    #[test]
    fn bundle_manifest_round_trip() {
        let root = temp_path("manifest");
        let manifest = BundleManifest {
            schema_version: 1,
            target: OPENAI_PRIVACY_TARGET.into(),
            provider: "openai".into(),
            model: "privacy-filter-v1".into(),
            adapter: ProviderAdapterKind::OpenAiOpfLocal.manifest_name().into(),
            runner_rel: "venv/bin/python".into(),
            entry_rel: Some("runner/openai_privacy_runner.py".into()),
            checkpoint_rel: "model".into(),
            runner_sha256: "abc123".into(),
            runner_executable_sha256: Some("def456".into()),
        };
        save_bundle_manifest(&root, &manifest).unwrap();
        let loaded = load_bundle_manifest(&bundle_manifest_path(&root)).unwrap();
        assert_eq!(loaded.target, manifest.target);
        assert_eq!(loaded.runner_sha256, manifest.runner_sha256);
        assert_eq!(
            loaded.runner_executable_sha256,
            manifest.runner_executable_sha256
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn legacy_manifest_without_adapter_still_loads() {
        let root = temp_path("legacy_manifest");
        let path = bundle_manifest_path(&root);
        let content = "\
schema_version=1
target=openai/privacy-filter-v1
provider=openai
model=privacy-filter-v1
runner_rel=runner/openai_privacy_runner.py
entry_rel=venv/bin/python
checkpoint_rel=model
runner_sha256=abc123
";
        io_safe::atomic_write(&path, content).unwrap();

        let loaded = load_bundle_manifest(&path).unwrap();
        assert_eq!(
            loaded.adapter,
            ProviderAdapterKind::OpenAiOpfLocal.manifest_name()
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[cfg(unix)]
    #[test]
    fn ready_bundle_requires_verified_state() {
        let root = temp_path("ready_bundle");
        let manifest = BundleManifest {
            schema_version: 1,
            target: OPENAI_PRIVACY_TARGET.into(),
            provider: "openai".into(),
            model: "privacy-filter-v1".into(),
            adapter: ProviderAdapterKind::OpenAiOpfLocal.manifest_name().into(),
            runner_rel: "bin/fake-runner".into(),
            entry_rel: None,
            checkpoint_rel: "model".into(),
            runner_sha256: "abc".into(),
            runner_executable_sha256: None,
        };
        save_bundle_manifest(&root, &manifest).unwrap();
        fs::create_dir_all(root.join("bin")).unwrap();
        fs::write(root.join("bin").join("fake-runner"), "#!/bin/sh\n").unwrap();
        fs::set_permissions(
            root.join("bin").join("fake-runner"),
            fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        fs::create_dir_all(root.join("model")).unwrap();
        let result = ensure_ready_bundle(&OPENAI_PROVIDER_ENTRY, &root);
        assert!(result.is_err());
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn bundle_child_path_rejects_paths_outside_bundle() {
        let root = temp_path("bundle_child_path");
        assert!(bundle_child_path(&root, "../runner", "runner_rel").is_err());
        assert!(bundle_child_path(&root, "/tmp/runner", "runner_rel").is_err());
        assert!(bundle_child_path(&root, "runner/provider.py", "runner_rel").is_ok());
        let _ = fs::remove_dir_all(&root);
    }

    #[cfg(unix)]
    #[test]
    fn ready_bundle_rejects_redirected_virtualenv_runner() {
        let root = temp_path("redirected_runner");
        let entry_script = root.join("runner").join(OPENAI_RUNNER_SCRIPT_NAME);
        let evil_runner = root.join("runner").join("evil");
        fs::create_dir_all(root.join("runner")).unwrap();
        fs::create_dir_all(root.join("model")).unwrap();
        fs::write(&entry_script, OPENAI_RUNNER_SCRIPT).unwrap();
        fs::write(&evil_runner, "#!/bin/sh\nexit 0\n").unwrap();
        fs::set_permissions(&evil_runner, fs::Permissions::from_mode(0o755)).unwrap();
        let manifest = BundleManifest {
            schema_version: 1,
            target: OPENAI_PRIVACY_TARGET.into(),
            provider: "openai".into(),
            model: "privacy-filter-v1".into(),
            adapter: ProviderAdapterKind::OpenAiOpfLocal.manifest_name().into(),
            runner_rel: "runner/evil".into(),
            entry_rel: Some(format!("runner/{}", OPENAI_RUNNER_SCRIPT_NAME)),
            checkpoint_rel: "model".into(),
            runner_sha256: sha256_hex_of_bytes(OPENAI_RUNNER_SCRIPT.as_bytes()),
            runner_executable_sha256: Some(sha256_hex_of_path(&evil_runner).unwrap()),
        };
        save_bundle_manifest(&root, &manifest).unwrap();
        save_verified_state(
            &root,
            &VerifiedState {
                schema_version: 1,
                target: OPENAI_PRIVACY_TARGET.into(),
                verified_unix_seconds: 1,
            },
        )
        .unwrap();

        let result = ensure_ready_bundle(&OPENAI_PROVIDER_ENTRY, &root);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("unexpected runner path"));
        let _ = fs::remove_dir_all(&root);
    }

    #[cfg(unix)]
    #[test]
    fn repair_bundle_runtime_paths_rewrites_moved_virtualenv_references() {
        let root = temp_path("repair_bundle_runtime_paths");
        let bundle_root = root
            .join("providers")
            .join("openai")
            .join("privacy-filter-v1");
        let scripts_dir = bundle_root.join("venv").join("bin");
        let dist_info_dir = bundle_root
            .join("venv")
            .join("lib")
            .join("python3.12")
            .join("site-packages")
            .join("opf-0.1.0.dist-info");
        fs::create_dir_all(&scripts_dir).unwrap();
        fs::create_dir_all(&dist_info_dir).unwrap();

        let embedded_root = root
            .join("providers")
            .join(".install-openai-privacy-filter-v1-12345");
        fs::write(
            bundle_root.join("venv").join("pyvenv.cfg"),
            format!(
                "command = /opt/python/bin/python3.12 -m venv {}/venv\n",
                embedded_root.display()
            ),
        )
        .unwrap();
        let opf_path = scripts_dir.join("opf");
        fs::write(
            &opf_path,
            format!(
                "#!{}/venv/bin/python\nprint('opf')\n",
                embedded_root.display()
            ),
        )
        .unwrap();
        fs::set_permissions(&opf_path, fs::Permissions::from_mode(0o755)).unwrap();
        fs::write(
            dist_info_dir.join("direct_url.json"),
            format!(
                "{{\"url\":\"file://{}/downloads/opf-source.tar.gz\"}}\n",
                embedded_root.display()
            ),
        )
        .unwrap();

        repair_bundle_runtime_paths(&bundle_root).unwrap();

        let rewritten_cfg =
            fs::read_to_string(bundle_root.join("venv").join("pyvenv.cfg")).unwrap();
        assert!(rewritten_cfg.contains(&bundle_root.to_string_lossy().into_owned()));
        assert!(!rewritten_cfg.contains(&embedded_root.to_string_lossy().into_owned()));

        let rewritten_opf = fs::read_to_string(&opf_path).unwrap();
        assert!(rewritten_opf.contains(&bundle_root.to_string_lossy().into_owned()));
        assert!(!rewritten_opf.contains(&embedded_root.to_string_lossy().into_owned()));

        let mode = fs::metadata(&opf_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o755);

        let rewritten_direct_url =
            fs::read_to_string(dist_info_dir.join("direct_url.json")).unwrap();
        assert!(rewritten_direct_url.contains(&bundle_root.to_string_lossy().into_owned()));
        assert!(!rewritten_direct_url.contains(&embedded_root.to_string_lossy().into_owned()));

        let _ = fs::remove_dir_all(&root);
    }
}
