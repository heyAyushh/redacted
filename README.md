# redact

**Production-grade CLI for redacting secrets and PII from text and files.**

Zero external dependencies. Offline. Safe by default.

---

## Key Features

- **Zero dependencies** — uses only the Rust standard library; no supply-chain risk.
- **Fully offline** — never phones home, no network access required.
- **Safe by default** — skips binary files, ignores hidden dirs, refuses to follow symlinks, caps file size at 25 MiB.
- **Atomic writes** — output is written to a temp file then renamed, so partial writes never corrupt data.
- **Purpose-built scanners** — every detector is a hand-written, O(n), non-backtracking scanner. No regex engine, no ReDoS risk.
- **CI-friendly** — `--fail-on-find` exits non-zero when secrets are detected; `--dry-run` previews without modifying files.
- **Structured output** — `--format json` and `--report-json` produce machine-readable reports with masked samples (secrets are never leaked in reports).
- **Extensible** — add custom patterns via `--pattern NAME=REGEX` or a TOML config file.

---

## Installation

```bash
# Clone and build
git clone <repo-url>
cd redact
cargo build --release

# The binary is at:
./target/release/redact
```

Or build in debug mode for development:

```bash
cargo build
cargo run -- redact --help
```

---

## Quick Start

```bash
# Redact a string
redact redact --text "email me at user@example.com"
# → email me at [REDACTED:EMAIL]

# Pipe from stdin
echo "AWS key: AKIAIOSFODNN7EXAMPLE" | redact redact
# → AWS key: [REDACTED:AWS_KEY]

# Redact a file and write output
redact redact --input secrets.log --output clean.log

# Redact a directory tree
redact redact --input logs/ --output cleaned/ --summary

# Dry-run in CI (exit code 3 if secrets found)
redact redact --input . --fail-on-find --dry-run

# In-place redaction
redact redact --input config.env --in-place
```

---

## Detectors

### Secrets

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

### PII

| Detector | Name | Matches |
|----------|------|---------|
| Email | `EMAIL` | RFC-style email addresses |
| Phone | `PHONE` | Phone numbers (7–15 digits, optional `+`, parens, dashes) |
| IPv4 | `IPV4` | Dotted-quad IPv4 addresses with octet validation |
| IPv6 | `IPV6` | Colon-separated IPv6 addresses including `::` shorthand |
| Credit Card | `CREDIT_CARD` | 13–19 digit card numbers with Luhn checksum validation |
| SSN | `SSN` | US Social Security Numbers (`NNN-NN-NNNN` with area/group/serial validation) |

---

## CLI Flags Reference

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

### Other

| Flag | Description |
|------|-------------|
| `--threads <N>` | Worker threads for directory mode |
| `--help` | Show help |
| `--version` | Show version |

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
# allow_patterns = "EMAIL,AWS_KEY"
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
- **No external dependencies.** Zero supply-chain surface. The entire codebase is auditable.
- **No regex engine.** All pattern matching uses purpose-built, O(n), non-backtracking scanners — immune to ReDoS.
- **No `unsafe` code.** Safe Rust throughout.
- **Atomic file writes.** Output is written to a temp file (`0600` permissions) then atomically renamed.
- **Symlink containment.** Symlink targets are canonicalised and rejected if they escape the input root directory.
- **Binary detection.** Files containing null bytes or a high ratio of non-text bytes are skipped by default.
- **Bounded custom patterns.** The built-in mini-regex engine caps quantifier repetitions at 4096.

---

## Development

```bash
cargo build          # Debug build
cargo test           # Run all tests (unit + integration)
cargo clippy         # Lint
cargo fmt --check    # Format check
cargo run -- redact --help
```

---

## License

[MIT](LICENSE)
