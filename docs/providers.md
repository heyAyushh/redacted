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

- Alias: `openai`
- Exact target: `openai/privacy-filter-v1`
- Alias: `ollama`
- Exact target: `ollama/structured-v1`

Aliases are onboarding shortcuts. They always resolve to a pinned exact target.
Commands print the resolved target before they change local state.

Current built-in mapping:

- `openai -> openai/privacy-filter-v1`
- `ollama -> ollama/structured-v1`

Support tiers:

- `openai/privacy-filter-v1` is the supported token-span path.
- `ollama/structured-v1` is an experimental generative-extraction path.

## Commands

```bash
redacted provider enable <provider-or-target> [--runtime-model <NAME>]
redacted provider install <provider-or-target> [--runtime-model <NAME>]
redacted provider use <provider-or-target> [--runtime-model <NAME>]
redacted provider current
redacted provider list
redacted provider verify [<provider-or-target> | --all]
redacted provider disable
```

Human-friendly setup:

```bash
redacted provider enable openai
redacted provider enable ollama --runtime-model qwen3-coder:30b
redacted --privacy-filter --input logs/
```

For Ollama:

- `--runtime-model <NAME>` chooses the local Ollama model to use.
- If you omit `--runtime-model` and there is exactly one local Ollama model, that model is used automatically.
- If there are multiple local Ollama models, `enable` and `install` fail fast and ask you to choose one explicitly.

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

Example bundle layout:

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

Ollama bundle layout:

```text
<data-root>/providers/ollama/structured-v1/
  bundle.state
  verified.state
  runtime/
    ollama-runtime.state
  runner/
    ollama_privacy_runner.py
```

## Integrity Verification

The checked-in provider catalog pins:

- adapter kind
- package source URL when the target ships its own runtime bundle
- package source SHA-256
- package source byte size
- model artifact URLs when the target ships local model files
- model artifact SHA-256 values
- model artifact byte sizes
- canonical label mapping

`redacted provider install ...`:

1. resolves the selector to a pinned exact target
2. installs the adapter-specific runtime bundle
3. verifies pinned artifacts when the target ships local runtime files
4. verifies the local runtime state required by that adapter
5. writes `verified.state`

`redacted provider verify ...` re-hashes the installed artifacts again and
refreshes `verified.state`.

Normal scans with `--privacy-filter` do **not** download anything.

Adapter-specific notes:

- `openai/privacy-filter-v1` installs a bundle-local OPF runtime plus pinned
  model artifacts and verifies them by size and SHA-256.
- `ollama/structured-v1` installs a small local runner plus runtime config and
  verifies that the local Ollama API can serve the configured model.

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

Internally, adapters are free to do provider-specific translation. For example:

- the OpenAI adapter converts OPF span output into the common span ABI
- the Ollama adapter asks the local Ollama API for structured JSON and then
  converts exact snippet matches into byte spans

That distinction matters:

- the OpenAI path starts from a model built for token/span labeling
- the Ollama path asks a generative model to emit structured JSON and then
  reconstructs spans from exact substring matches
- because of that, the Ollama path is lower-fidelity and should be treated as experimental

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
- Want the Ollama-backed adapter instead:
  - `redacted provider enable ollama --runtime-model qwen3-coder:30b`
- Bundle installed but not active:
  - `redacted provider use openai`
- Ollama API not running:
  - start Ollama locally, then run `redacted provider enable ollama --runtime-model qwen3-coder:30b`
- Bundle missing verification stamp:
  - `redacted provider verify openai`
- Need to see what is installed:
  - `redacted provider list`
- Need to clear the current selection:
  - `redacted provider disable`
