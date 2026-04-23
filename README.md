# redacted

**Production-grade CLI for redacting secrets and PII from text and files.**

Core binary: zero external dependencies, offline by default, safe by default.
Optional privacy-filter providers: explicit local model bundles you install and enable yourself.

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

---

## Extensibility Guidance

- Prefer **detectors** for new first-class scanning logic. A detector is native to `redacted`: it scans text, emits findings, and participates in the built-in reporting/redaction pipeline.
- Reserve **bridges/adapters** for rare external integrations where `redacted` needs to wrap another engine or protocol.
- If you are borrowing ideas from tools like TruffleHog, implement them as native detectors in this repository rather than invoking the external tool at runtime.
- If you are extending the product for normal use cases, contributors should build **detectors** rather than adapters.

---

## Installation

```bash
# Clone and build
git clone <repo-url>
cd redacted
cargo build --release

# The binary is at:
./target/release/redacted
```

Or build in debug mode for development:

```bash
cargo build
cargo run -- --help
```

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

# Enable the default privacy-filter provider once
redacted provider enable openai

# Run the extra provider-backed pass
redacted --input logs/ --output cleaned/ --summary --privacy-filter

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

- Alias: `openai`
- Exact target: `openai/privacy-filter-v1`
- Adapter: local OPF runner around the OpenAI Privacy Filter model

- Alias: `ollama`
- Exact target: `ollama/structured-v1`
- Adapter: local Ollama API runner using structured JSON extraction
- Support level: experimental

### What It Does

When you add `--privacy-filter`, `redacted`:

1. Runs the normal built-in detectors.
2. Runs the active local provider bundle once more over the same text.
3. Merges both sets of findings.
4. Applies the usual retain, except, report, and redact logic once.

So the feature is an **extra pass**, not a second output mode and not a provider-owned redaction pipeline.

### Human Onboarding

```bash
# Install, verify, and activate the default provider alias
redacted provider enable openai

# Or use the Ollama-backed adapter
redacted provider enable ollama --runtime-model qwen3-coder:30b

# Scan with the extra pass enabled
redacted --privacy-filter --input logs/
```

The command prints the exact resolved target, for example:

```text
resolved target: openai/privacy-filter-v1
```

or:

```text
resolved target: ollama/structured-v1
```

### Switching Later

```bash
redacted provider list
redacted provider current
redacted provider use openai
redacted provider use ollama --runtime-model qwen3-coder:30b
redacted provider disable
```

### Important Behavior

- `--privacy-filter` never downloads anything during a scan.
- Provider downloads happen only through `redacted provider install ...` or `redacted provider enable ...`.
- If no active provider is configured, `--privacy-filter` fails fast with the next exact setup command.
- The provider bundle is verified when installed and can be re-checked later with `redacted provider verify`.
- `openai` and `ollama` are both adapter modes, not extensions of the hardened core guarantee.
- The Ollama target requires a running local Ollama API and uses a chosen local model rather than a hardcoded default model identity.
- `redacted provider enable ollama` will auto-pick the model only when Ollama has exactly one local model; otherwise pass `--runtime-model <NAME>`.
- `install` or `enable` may pull the configured Ollama model if it is not already available locally.
- The Ollama target is an experimental generative-extraction path, not a native token-span runtime like the OpenAI Privacy Filter path.

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
redacted provider install openai/privacy-filter-v1
redacted provider use openai
redacted provider verify --all
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

## License

[MIT](LICENSE)
