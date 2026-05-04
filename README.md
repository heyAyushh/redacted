# redacted

[![CI](https://github.com/heyAyushh/redacted/actions/workflows/ci.yml/badge.svg)](https://github.com/heyAyushh/redacted/actions/workflows/ci.yml)

![redacted banner](assets/readme-banner.png)

**Production-grade CLI for redacting secrets and PII from text and files.**

Fast local redaction for logs, prompts, configs, and files. The default scan
path is a single Rust binary with no crates.io dependencies, no network calls,
and no model downloads.

---

## Install

```bash
cargo install --git https://github.com/heyAyushh/redacted --locked
redacted --version
```

That installs the Rust CLI only. Optional provider models are never downloaded
by install, build, tests, or normal scans.

---

## Try It

```bash
redacted --text "email jane@example.com password=correct-horse-battery-staple"
# → email [REDACTED:EMAIL] [REDACTED:PASSWORD]
```

```bash
echo "AWS key: AKIAIOSFODNN7EXAMPLE" | redacted
# → AWS key: [REDACTED:AWS_KEY]
```

```bash
redacted --input secrets.log --output clean.log
redacted --input logs/ --output cleaned/ --summary
```

Use it in CI:

```bash
redacted --input . --fail-on-find --dry-run
```

---

## Optional Local Privacy Filter

`redacted` can add a second local detection pass using an installed provider
bundle. This is off by default and separate from the hardened Rust-only scan
path.

```bash
# One-time setup: downloads, hash-verifies, and activates the pinned local model
redacted provider enable openai

# Scan with the extra local provider pass
redacted --privacy-filter --text "Jane Doe emailed jane@example.com from 411 111th St."
```

Provider scans use the local installed bundle. They do not call the OpenAI API.
The first run can be slower because the local model has to load.

Apple Silicon users can try the experimental MLX runtime for the same
[OpenAI Privacy Filter model](https://huggingface.co/openai/privacy-filter/tree/main/original)
through the pinned
[mlx-community/openai-privacy-filter-4bit conversion](https://huggingface.co/mlx-community/openai-privacy-filter-4bit/tree/8b784df48dd38a36b757f50c73d23e5bd38f3db0):

```bash
redacted provider enable mlx
redacted --privacy-filter --input logs/
```

---

## Optional External Detectors

`redacted` can also run active external detector engines for `--input` scans.
This is off by default and separate from the Rust-only native detector path.

TruffleHog is the first supported external detector engine:

```bash
# One-time setup: binds to your local trufflehog executable and hashes it
redacted detector install trufflehog
redacted detector use trufflehog

# Run native detectors plus active external detectors for this scan
redacted --detectors --input repo/

# Optional: make active external detectors run by default for --input scans
redacted detector default on
```

External detector scans run TruffleHog with JSON output, `--no-verification`,
`--no-update`, and `--no-color`. `redacted` still owns final masking, reports,
retain/except policy, and file writes.

---

## Key Features

- **Zero dependencies in the core binary** — uses only the Rust standard library; no crates.io supply-chain risk in the default scan path.
- **Offline by default** — built-in scans never phone home or download anything.
- **Safe by default** — skips binary files, ignores hidden dirs, refuses to follow symlinks, caps file size at 25 MiB.
- **Atomic writes** — output is written to a temp file then renamed, so partial writes never corrupt data.
- **Purpose-built scanners** — every detector is a hand-written, O(n), non-backtracking scanner. No regex engine, no ReDoS risk.
- **CI-friendly** — `--fail-on-find` exits non-zero when secrets are detected; `--dry-run` previews without modifying files.
- **Structured output** — `--format json` and `--report-json` produce machine-readable reports with masked samples (secrets are never leaked in reports).
- **Extensible** — add custom patterns via `--pattern NAME=REGEX` or a TOML config file.
- **Optional privacy-filter pass** — add a second local detection pass from an installed provider bundle with `--privacy-filter`.
- **Optional external detectors** — add active external secret engines such as TruffleHog with `--detectors`.

---

## Quick Start

```bash
# Redact a string
redacted --text "email me at user@example.com"
# → email me at [REDACTED:EMAIL]

# Pipe from stdin
echo "AWS key: AKIAIOSFODNN7EXAMPLE" | redacted
# → AWS key: [REDACTED:AWS_KEY]

# Redact a file and write output
redacted --input secrets.log --output clean.log

# Redact a directory tree
redacted --input logs/ --output cleaned/ --summary

# Dry-run in CI (exit code 3 if secrets found)
redacted --input . --fail-on-find --dry-run

# In-place redaction
redacted --input config.env --in-place

# Redact filesystem paths
redacted --text "config at /etc/nginx/nginx.conf"
# → config at [REDACTED:PATH]

# Redact IP addresses (IPv4 and IPv6)
redacted --text "server 192.168.1.100"
# → server [REDACTED:IP]

redacted --text "addr: 2001:0db8:85a3::8a2e:0370:7334"
# → addr: [REDACTED:IP]

# Multiple types in one pass
redacted --text "user@a.com at /var/log/app.log from 10.0.0.1"
# → [REDACTED:EMAIL] at [REDACTED:PATH] from [REDACTED:IP]
```

---

## Optional Extras

```bash
# Enable the pinned OpenAI Privacy Filter bundle once
redacted provider enable openai

# Run the extra provider-backed pass
redacted --input logs/ --output cleaned/ --summary --privacy-filter

# Enable TruffleHog as an external detector once
redacted detector install trufflehog
redacted detector use trufflehog

# Run active external detectors for this scan
redacted --input logs/ --summary --detectors

# Enable the PDF document adapter once
redacted document enable pdf

# Scan a PDF through the document adapter path
redacted --input report.pdf --document-adapter

# Run a repeatable benchmark
redacted benchmark --input logs/ --iterations 5 --privacy-filter --document-adapter
```

---

## Detectors

When extending `redacted`, prefer building **detectors** that plug into the native scan pipeline. Reserve terms like **bridge** or **adapter** for rare cases where `redacted` wraps an external engine and translates its results back into native findings.

### Secrets (12)

| Detector | Name | Matches |
|----------|------|---------|
| AWS Key | `AWS_KEY` | `AKIA`, `ABIA`, `ACCA`, `ASIA` prefixed 20-char keys |
| Bearer Token | `BEARER_TOKEN` | `Bearer <token>` with ≥20-char token |
| JWT | `JWT` | `eyJ`-prefixed base64url tokens with 2 dots |
| Private Key | `PRIVATE_KEY` | PEM-encoded private key blocks (RSA, EC, DSA, OpenSSH, PGP) |
| Generic API Key | `API_KEY` | `api_key=`, `apikey=`, `access_key=`, `secret_key=` assignments |
| Database URL | `DATABASE_URL` | `postgres://`, `mysql://`, `mongodb://`, `redis://`, etc. |
| Password | `PASSWORD` | `password=`, `passwd=`, `pass=` assignments |
| Webhook Secret | `WEBHOOK_SECRET` | `whsec_` and `whsk_` prefixed tokens |
| Slack Token | `SLACK_TOKEN` | `xoxb-`, `xoxp-`, `xoxs-`, etc. prefixed tokens |
| GitHub Token | `GITHUB_TOKEN` | `ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_`, `github_pat_` prefixed tokens |
| Stripe Key | `STRIPE_KEY` | `sk_live_`, `sk_test_`, `pk_live_`, `pk_test_`, etc. |
| Generic Secret | `GENERIC_SECRET` | `SECRET=`, `TOKEN=`, `CREDENTIAL=`, `AUTH_KEY=` assignments |

### PII (7)

| Detector | Name | Matches |
|----------|------|---------|
| Email | `EMAIL` | RFC-style email addresses |
| Phone | `PHONE` | Phone numbers (7–15 digits, optional `+`, parens, dashes) |
| IP Address | `IP` | IPv4 (dotted-quad with octet validation) and IPv6 (colon-separated including `::` shorthand) |
| Credit Card | `CREDIT_CARD` | 13–19 digit card numbers with Luhn checksum validation |
| SSN | `SSN` | US Social Security Numbers (`NNN-NN-NNNN` with area/group/serial validation) |
| Filesystem Path | `PATH` | Absolute (`/etc/...`), relative (`./src/...`, `../`), home (`~/...`), and Windows (`C:\...`) paths |

### Custom

Add your own patterns via CLI or config:

```bash
redacted --text "ref PROJ-42" --pattern "PROJECT_ID=PROJ-\\d+"
# → ref [REDACTED:PROJECT_ID]
```

---

## Privacy Filter Providers

`redacted` can run one extra optional detection pass from a local provider bundle.
This is **off by default** and it does **not** replace the native detectors.

The important trust boundary is:

- The default Rust-only scan path keeps the original lightweight, offline-by-default hardening story.
- Provider-backed privacy filtering is an **optional adapter mode** outside that hardened core path.
- `redacted` still owns masking, reporting, retain rules, except rules, and file writes.

Current built-in aliases and targets:

| Alias | Exact target | Status | What it runs |
|-------|--------------|--------|--------------|
| `openai` | `openai/privacy-filter-v1` | Supported | Local OPF runner around [OpenAI Privacy Filter original artifacts](https://huggingface.co/openai/privacy-filter/tree/main/original) |
| `mlx` | `openai/privacy-filter-v1-mlx` | Experimental | Apple MLX runtime for the pinned [mlx-community/openai-privacy-filter-4bit conversion](https://huggingface.co/mlx-community/openai-privacy-filter-4bit/tree/8b784df48dd38a36b757f50c73d23e5bd38f3db0) |

### What It Does

When you add `--privacy-filter`, `redacted`:

1. Runs the normal built-in detectors.
2. Runs the active local provider bundle once more over the same text.
3. Merges both sets of findings.
4. Applies the usual retain, except, report, and redact logic once.

So the feature is an **extra pass**, not a second output mode and not a provider-owned redaction pipeline.

### Human Onboarding

```bash
# Install, verify, and activate the pinned OpenAI provider bundle
redacted provider enable openai

# Or, on Apple Silicon, use the experimental MLX runtime for the same filter
redacted provider enable mlx

# Scan with the extra pass enabled
redacted --privacy-filter --input logs/
```

The command prints the exact resolved target, for example:

```text
resolved target: openai/privacy-filter-v1
```

For MLX, the resolved target is:

```text
resolved target: openai/privacy-filter-v1-mlx
```

### Switching Later

```bash
redacted provider list
redacted provider current
redacted provider use openai
redacted provider disable
```

### Important Behavior

- `--privacy-filter` never downloads anything during a scan.
- `--privacy-filter` uses the active locally installed provider bundle; it does not call the OpenAI API during scans.
- The first provider-backed scan can be slower because the local model and runner need to load.
- Provider downloads happen only through `redacted provider install ...` or `redacted provider enable ...`.
- If no active provider is configured, `--privacy-filter` fails fast with the next exact setup command.
- The provider bundle is verified when installed and can be re-checked later with `redacted provider verify`.
- Python runtime dependencies for provider bundles are installed from checked-in hash-locked requirements files.
- `openai/privacy-filter-v1` is the supported token-span runtime using the [OpenAI Privacy Filter OPF source archive](https://github.com/openai/privacy-filter/tree/2e8c95b9771eec29ef61012f6e5e836f9bad7635) and [OpenAI Privacy Filter model artifacts](https://huggingface.co/openai/privacy-filter/tree/main/original).
- `openai/privacy-filter-v1-mlx` is experimental, requires Python 3.10+, and downloads the pinned [mlx-community/openai-privacy-filter-4bit](https://huggingface.co/mlx-community/openai-privacy-filter-4bit/tree/8b784df48dd38a36b757f50c73d23e5bd38f3db0) conversion for local MLX inference.
- Generative model runtimes are not exposed as privacy-filter providers unless they run a real detector with verified span output.

### Provider Sources

The `openai` alias resolves to `openai/privacy-filter-v1`, which downloads:

- [OpenAI Privacy Filter OPF source archive](https://github.com/openai/privacy-filter/archive/2e8c95b9771eec29ef61012f6e5e836f9bad7635.tar.gz), pinned to commit `2e8c95b9771eec29ef61012f6e5e836f9bad7635`
- [OpenAI Privacy Filter original model artifacts](https://huggingface.co/openai/privacy-filter/tree/main/original)
- [OpenAI Privacy Filter original/model.safetensors](https://huggingface.co/openai/privacy-filter/resolve/main/original/model.safetensors?download=1)

The main OpenAI model file is pinned by verification metadata:

```text
size:   2,798,984,088 bytes
sha256: 9c262cbe68a0c8a50590a648ef8341a2b7d3be1fa11dfb79893fe0b03ce57b5c
```

The `mlx` alias resolves to `openai/privacy-filter-v1-mlx`, which downloads
from [mlx-community/openai-privacy-filter-4bit](https://huggingface.co/mlx-community/openai-privacy-filter-4bit/tree/8b784df48dd38a36b757f50c73d23e5bd38f3db0)
at this exact revision:

```text
8b784df48dd38a36b757f50c73d23e5bd38f3db0
```

The main MLX model file is
[model.safetensors](https://huggingface.co/mlx-community/openai-privacy-filter-4bit/blob/8b784df48dd38a36b757f50c73d23e5bd38f3db0/model.safetensors),
pinned to:

```text
size:   790,435,150 bytes
sha256: 0ec7afabebaf35cf8482c73b351af888b75fbe0c4aaed7cdeec57bb6b87b3796
```

All provider artifacts are checked by size and SHA-256 before the provider is
marked verified.
Provider Python dependencies are installed with pip `--require-hashes` from
checked-in lock files under `provider-locks/`.

### External Detector Engines

External detectors are optional secret-scanner engines outside the hardened
Rust-only core. Native detectors always run; `--detectors` adds active external
engines for `--input` scans.

Current built-in external detector target:

| Alias | Exact target | Status | What it runs |
|-------|--------------|--------|--------------|
| `trufflehog` | `trufflehog/secrets-v1` | Supported external engine | Local [TruffleHog](https://github.com/trufflesecurity/trufflehog/tree/main) CLI through `trufflehog filesystem --json --no-verification --no-update --no-color` |

Commands:

```bash
redacted detector install trufflehog
redacted detector use trufflehog
redacted detector current
redacted detector list
redacted detector verify --all
redacted detector default on
redacted detector disable trufflehog
```

Scan examples:

```bash
redacted --detectors --input repo/
redacted --no-detectors --input repo/
```

Important behavior:

- `redacted detector install trufflehog` does not download TruffleHog; it binds to the local `trufflehog` executable in `PATH` and pins its SHA-256.
- `redacted --detectors ...` requires `--input`; external detectors do not run for `--text` or stdin.
- `redacted detector default on` makes active external detectors run by default for `--input` scans.
- `--no-detectors` disables external detectors for one scan even when the default is on.
- TruffleHog is AGPL-3.0 and remains an external tool; it is not vendored into the MIT Rust core.
- Network verification is disabled by default with TruffleHog `--no-verification`.

---

## Document Adapters

`redacted` can also run an optional document extraction step for supported non-text files.

- Feature flag: `--document-adapter`
- Current built-in aliases: `pdf`, `firecrawl-pdf`
- Current exact targets: `poppler/pdftotext-v1`, `firecrawl/pdf-inspector-v1`
- Runtime: local `pdftotext` or local Firecrawl `pdf2md`

The short `pdf` alias is the human path for the PDF document type. Exact targets
name the adapter implementation, so the PDF adapter can be switched later
without making humans type long names.

When `--document-adapter` is enabled and the input is a supported document type (`.pdf` in v1), `redacted` extracts text first and then applies the same detector, merge, retain/except, reporting, and redaction pipeline.

Setup flow:

```bash
redacted document enable pdf
redacted --input report.pdf --document-adapter
```

Switch to Firecrawl PDF Inspector when its `pdf2md` CLI is installed locally:

```bash
redacted document enable firecrawl-pdf
redacted --input report.pdf --document-adapter
```

Switching and lifecycle:

```bash
redacted document list
redacted document current
redacted document use poppler/pdftotext-v1
redacted document use firecrawl/pdf-inspector-v1
redacted document verify --all
redacted document disable
```

Important behavior:

- Document adapters are off by default.
- Scans do not auto-install adapters.
- `--document-adapter` fails fast if no active adapter is configured.
- In-place rewrite is blocked for document-adapter extracted files; use `--output` instead.

---

## CLI Reference

### Input

| Flag | Description |
|------|-------------|
| `--text <TEXT>` | Literal text to redact |
| `--input <PATH>` | File or directory to process |
| *(stdin)* | Reads piped stdin if no `--text` or `--input` |

### Output

| Flag | Description |
|------|-------------|
| `--output <PATH>` | Write output to file or directory |
| `--in-place` | Rewrite input file(s) atomically |
| `--format text\|json` | Output format (default: `text`) |
| `--report-json` | Write structured JSON report to stderr |

### Detector Control

| Flag | Description |
|------|-------------|
| `--pattern <NAME=REGEX>` | Add a custom pattern (repeatable) |
| `--allow-pattern <NAME>` | Enable only this detector (repeatable) |
| `--deny-pattern <NAME>` | Disable this detector (repeatable) |
| `--replacement <STRING>` | Custom replacement text (default: `[REDACTED:<TYPE>]`) |

### Traversal

| Flag | Description |
|------|-------------|
| `--recursive` | Recurse into directories (default: on) |
| `--include-hidden` | Process hidden files and directories |
| `--follow-symlinks` | Follow symlinks (default: off) |
| `--no-follow-symlinks` | Do not follow symlinks |
| `--binary skip\|fail\|best-effort` | Binary file handling (default: `skip`) |
| `--max-file-size <BYTES>` | Max file size in bytes (default: 26214400) |

### Modes

| Flag | Description |
|------|-------------|
| `--dry-run` | Show what would be redacted without writing |
| `--fail-on-find` | Exit non-zero if any findings detected |
| `--summary` | Print summary to stderr |
| `--config <PATH>` | TOML configuration file |
| `--privacy-filter` | Run the active privacy-filter provider as one extra detection pass |
| `--detectors` | Run active external detector engines for this scan |
| `--no-detectors` | Disable external detector engines for this scan |
| `--document-adapter` | Run the active document adapter for supported non-text inputs |

### Other

| Flag | Description |
|------|-------------|
| `--threads <N>` | Worker threads for directory mode |
| `--help` | Show help |
| `--version` | Show version |

### Provider Commands

```bash
redacted provider enable <provider-or-target>
redacted provider install <provider-or-target>
redacted provider use <provider-or-target>
redacted provider current
redacted provider list
redacted provider verify [<provider-or-target> | --all]
redacted provider disable
```

Examples:

```bash
redacted provider enable openai
redacted provider enable mlx
redacted provider install openai/privacy-filter-v1
redacted provider install openai/privacy-filter-v1-mlx
redacted provider use openai
redacted provider verify --all
```

### Detector Commands

```bash
redacted detector install <detector-or-target>
redacted detector use <detector-or-target>
redacted detector current
redacted detector list
redacted detector verify [<detector-or-target> | --all]
redacted detector disable [<detector-or-target> | --all]
redacted detector default <on|off>
```

Examples:

```bash
redacted detector install trufflehog
redacted detector use trufflehog
redacted detector default on
redacted detector verify --all
redacted --detectors --input repo/
```

### Document Commands

```bash
redacted document enable <adapter-or-target>
redacted document install <adapter-or-target>
redacted document use <adapter-or-target>
redacted document current
redacted document list
redacted document verify [<adapter-or-target> | --all]
redacted document disable
```

Examples:

```bash
redacted document enable pdf
redacted document enable firecrawl-pdf
redacted document install poppler/pdftotext-v1
redacted document use pdf
redacted document verify --all
```

### Benchmark Command

```bash
redacted benchmark --input <PATH> [--iterations <N>] [--privacy-filter] [--document-adapter] [--format text|json]
```

Examples:

```bash
redacted benchmark --input logs/
redacted benchmark --input logs/ --iterations 10 --privacy-filter
redacted benchmark --input report.pdf --document-adapter --format json
```

---

## Config File

Create a TOML file and pass it with `--config`:

```toml
# redact.toml
replacement = "[SCRUBBED]"
max_file_size = 1048576
include_hidden = false
follow_symlinks = false
binary = "skip"

# Selective detectors
# allow_patterns = "EMAIL,AWS_KEY,IP,PATH"
# deny_patterns = "PHONE"

# Custom patterns
[pattern]
internal_id = "PROJ-\\d+"
session_token = "sess_[a-zA-Z0-9]+"
```

CLI flags always take precedence over config file values.

---

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Success — operation completed |
| `1` | Operational error (I/O failure, config error, etc.) |
| `2` | Usage error (invalid arguments, missing input) |
| `3` | Findings detected (only with `--fail-on-find`) |

---

## Security Model

- **No secrets in output.** Reports use `masked_sample` (first ≤4 chars + `***`). Full matches are never logged, printed, or serialised.
- **No external dependencies in the core binary.** The default scan path stays in the Rust standard library.
- **No regex engine.** All pattern matching uses purpose-built, O(n), non-backtracking scanners — immune to ReDoS.
- **No `unsafe` code.** Safe Rust throughout.
- **Atomic file writes.** Output is written to a temp file (`0600` permissions) then atomically renamed.
- **Symlink containment.** Symlink targets are canonicalised and rejected if they escape the input root directory.
- **Binary detection.** Files containing null bytes or a high ratio of non-text bytes are skipped by default.
- **Bounded custom patterns.** The built-in mini-regex engine caps quantifier repetitions at 4096.
- **Explicit provider boundary.** Optional provider bundles are installed separately, selected explicitly, and only run when `--privacy-filter` is present.
- **Explicit document-adapter boundary.** Optional document adapter bundles are installed separately, selected explicitly, and only run when `--document-adapter` is present.

---

## Development

```bash
cargo build          # Debug build
cargo test           # Run all tests (unit + integration)
cargo clippy         # Lint
cargo fmt --check    # Format check
cargo run -- --help
```

See `docs/` for full documentation and `skills/redaction-cli/SKILL.md` for contributor guidance.

---

## Attribution

`redacted` itself is MIT licensed and the core CLI uses only the Rust standard
library. Optional providers, document adapters, and external detectors carry
their own license metadata and remain separate from the MIT core.

| Area | Used for | License | Distribution | Upstream |
|------|----------|---------|--------------|----------|
| Core CLI | Built-in detectors, masking, reports, file traversal, and writes | MIT | bundled core | Rust standard library |
| OpenAI provider | Optional `openai/privacy-filter-v1` local privacy-filter pass | Apache-2.0 | downloaded artifact | [OpenAI Privacy Filter source](https://github.com/openai/privacy-filter/tree/2e8c95b9771eec29ef61012f6e5e836f9bad7635), [model artifacts](https://huggingface.co/openai/privacy-filter/tree/main/original), and key Python packages such as `torch`, `tiktoken`, `safetensors`, `numpy`, and `huggingface_hub` pinned in `provider-locks/openai-privacy-filter-v1-requirements.txt` |
| MLX provider | Optional `openai/privacy-filter-v1-mlx` Apple Silicon privacy-filter pass | Apache-2.0 | downloaded artifact | [mlx-community/openai-privacy-filter-4bit](https://huggingface.co/mlx-community/openai-privacy-filter-4bit/tree/8b784df48dd38a36b757f50c73d23e5bd38f3db0), and key Python packages such as `mlx`, `mlx-lm`, `tokenizers`, `safetensors`, `transformers`, `numpy`, and `huggingface_hub` pinned in `provider-locks/openai-privacy-filter-v1-mlx-requirements.txt` |
| Provider Python environments | Local model loading and span detection inside provider bundles | package-specific | downloaded artifacts | Hash-locked packages listed in `provider-locks/` |
| External detector engine | Optional `trufflehog/secrets-v1` secret-scanner pass | AGPL-3.0 | external binary | Local [TruffleHog](https://github.com/trufflesecurity/trufflehog/tree/main) CLI, not vendored |
| PDF document adapter | Optional PDF text extraction before the normal scan pipeline | GPL-2.0-or-later | external binary | Local `pdftotext` from [Poppler](https://poppler.freedesktop.org/) |
| Firecrawl PDF adapter | Optional PDF-to-Markdown extraction before the normal scan pipeline | MIT | external binary | Local `pdf2md` from [Firecrawl PDF Inspector](https://github.com/firecrawl/pdf-inspector), not linked or vendored |

Third-party models, tools, and Python packages keep their own upstream licenses.
The checked-in lock files and provider catalog pin the exact downloaded artifacts
with URLs, byte sizes, and SHA-256 hashes.

The extension license policy and contribution checklist live in
[docs/extension-licenses.md](docs/extension-licenses.md). The `pdf` alias names
the document type; exact targets name the active adapter implementation.

---

## License

`redacted` is released under the [MIT License](LICENSE).
