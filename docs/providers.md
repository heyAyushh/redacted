# Privacy Filter Providers

This document describes the optional provider subsystem behind
`redacted --privacy-filter`.

## Scope

- The provider pass is **off by default**.
- Native detectors still run exactly as before.
- The provider pass is an **extra detection pass**, not a replacement detector
  registry and not a provider-owned redaction pipeline.
- Provider mode is an **adapter boundary** outside the hardened Rust-only core
  scan path.
- `redacted` still owns final masking, reports, retain rules, except rules, and
  file writes.

## Alias Resolution

`redacted` supports two selector forms:

- Alias: `openai` or `mlx`
- Exact target: `openai/privacy-filter-v1` or `openai/privacy-filter-v1-mlx`

Aliases are onboarding shortcuts. They always resolve to a pinned exact target.
Commands print the resolved target before they change local state.

Current built-in mapping:

- `openai -> openai/privacy-filter-v1`
- `mlx -> openai/privacy-filter-v1-mlx`

Support tier:

- `openai/privacy-filter-v1` is the supported token-span path.
- `openai/privacy-filter-v1-mlx` is experimental and runs the converted OpenAI
  Privacy Filter model through local MLX packages on Apple Silicon. It requires
  Python 3.10 or newer for the MLX package environment.

Provider selection is persistent. If you run `redacted provider enable mlx`,
future `redacted --privacy-filter ...` scans use MLX until you switch back with
`redacted provider use openai` or disable provider mode.

Generative runtimes are intentionally not exposed as privacy-filter providers
unless they run a real detector with verified span output.

## Commands

```bash
redacted provider enable <provider-or-target>
redacted provider install <provider-or-target>
redacted provider use <provider-or-target>
redacted provider current
redacted provider list
redacted provider verify [<provider-or-target> | --all]
redacted provider disable
```

Human-friendly setup:

```bash
redacted provider enable openai
redacted --privacy-filter --input logs/
```

Experimental MLX setup:

```bash
redacted provider enable mlx
redacted --privacy-filter --input logs/
```

Switch back to the supported OPF runtime:

```bash
redacted provider use openai
redacted --privacy-filter --input logs/
```

## State and Install Layout

Config state is stored under the app config root:

- `XDG_CONFIG_HOME/redacted` when `XDG_CONFIG_HOME` is set
- otherwise `~/.config/redacted`

App data is stored under the app data root:

- `XDG_DATA_HOME/redacted` when `XDG_DATA_HOME` is set
- otherwise `~/.local/share/redacted`

Important files:

- Active target: `active-provider.state`
- Installed bundles: `providers/<provider>/<model>/...`

OpenAI bundle layout:

```text
<data-root>/providers/openai/privacy-filter-v1/
  bundle.state
  verified.state
  downloads/
    opf-source.tar.gz
  model/
    config.json
    dtypes.json
    model.safetensors
    viterbi_calibration.json
  runner/
    openai_privacy_runner.py
  venv/
    ...
```

MLX bundle layout:

```text
<data-root>/providers/openai/privacy-filter-v1-mlx/
  bundle.state
  verified.state
  model/
    config.json
    model.safetensors
    model.safetensors.index.json
    tokenizer.json
    tokenizer_config.json
    viterbi_calibration.json
  runner/
    mlx_privacy_runner.py
  venv/
    ...
```

## Integrity Verification

The checked-in provider catalog pins:

- adapter kind
- package source URL
- package source SHA-256
- package source byte size
- model artifact URLs
- model artifact SHA-256 values
- model artifact byte sizes
- Python dependency versions and SHA-256 hashes in `provider-locks/`
- canonical label mapping

Each installed `bundle.state` also records the relative runner paths and hashes:

- `runner_rel` must stay inside the bundle and, for virtualenv adapters, must be the expected virtualenv Python path.
- `entry_rel` must stay inside the bundle and match the expected adapter entry script.
- `runner_sha256` verifies the adapter entry script.
- `runner_executable_sha256` verifies the launched executable itself.

Current MLX model pin:

```text
target:   openai/privacy-filter-v1-mlx
source:   mlx-community/openai-privacy-filter-4bit
revision: 8b784df48dd38a36b757f50c73d23e5bd38f3db0
deps:     provider-locks/openai-privacy-filter-v1-mlx-requirements.txt
```

Main MLX model artifact:

```text
file:   model.safetensors
size:   790,435,150 bytes
sha256: 0ec7afabebaf35cf8482c73b351af888b75fbe0c4aaed7cdeec57bb6b87b3796
```

`redacted provider install ...`:

1. resolves the selector to a pinned exact target
2. installs the selected OpenAI Privacy Filter runtime bundle
3. installs Python dependencies with pip `--require-hashes`
4. verifies pinned package and model artifacts by size and SHA-256
5. writes `verified.state`

`redacted provider verify ...` re-hashes the installed artifacts again and
refreshes `verified.state`.

Normal scans with `--privacy-filter` do **not** download anything.

## Active Provider State

`redacted provider use ...` and `redacted provider enable ...` set the active
exact target in `active-provider.state`.

`redacted --privacy-filter ...` uses that active target and fails fast if:

- no active target is configured
- the selected bundle is not installed
- the selected bundle has not been verified
- the selected bundle is missing its runner or checkpoint path

## Runner Contract

`redacted` talks to the provider runner over newline-delimited JSON on
stdin/stdout.

Request:

```json
{"schema_version":1,"request_id":"req-1","text":"Alice was born on 1990-01-02"}
```

Response:

```json
{
  "schema_version": 1,
  "request_id": "req-1",
  "target": "openai/privacy-filter-v1",
  "spans": [
    {"label":"private_person","start":0,"end":5},
    {"label":"private_date","start":18,"end":28}
  ]
}
```

Rules:

- request and response schema version is `1`
- responses contain only labels and byte spans
- responses do not contain raw span text
- `redacted` owns masking, reports, retain rules, except rules, and file writes

The MLX runner follows the same contract. MLX-specific model loading,
tokenization, and label decoding stay inside the provider runner; the Rust core
only sees labels and byte spans.

## Canonical Label Mapping

The built-in OpenAI target maps provider labels into stable `redacted`
detector names:

- `account_number -> ACCOUNT_NUMBER`
- `private_address -> PRIVATE_ADDRESS`
- `private_email -> PRIVATE_EMAIL`
- `private_person -> PRIVATE_PERSON`
- `private_phone -> PRIVATE_PHONE`
- `private_url -> PRIVATE_URL`
- `private_date -> PRIVATE_DATE`
- `secret -> SECRET`

## Troubleshooting

Common failures and the next command to run:

- No active provider:
  - `redacted provider enable openai`
- Bundle installed but not active:
  - `redacted provider use openai`
- Bundle missing verification stamp:
  - `redacted provider verify openai`
- Want the experimental MLX runtime:
  - `redacted provider enable mlx`
- Need to see what is installed:
  - `redacted provider list`
- Need to clear the current selection:
  - `redacted provider disable`
