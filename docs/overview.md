# Overview

`redact` is a command-line tool that scans text and files for secrets and personally identifiable information (PII), replacing matches with safe redaction markers.

## Philosophy

1. **Zero dependencies.** The entire tool is built on Rust's standard library. No third-party crates, no regex engine, no transitive supply-chain risk. Every line of code is auditable in a single repository.

2. **Purpose-built scanners.** Instead of compiling regular expressions at runtime, each detector is a hand-written, linear-time scanner with bounded scan windows. This eliminates an entire class of denial-of-service attacks (regex catastrophic backtracking / ReDoS).

3. **No network, no telemetry.** The binary never opens a socket. It reads local input, writes local output, and exits. There is nothing to phone home and no update check.

4. **Safe defaults.** Binary files are skipped, hidden files are excluded, symlinks are not followed, and file size is capped at 25 MiB. Every default is the conservative choice.

5. **Atomic writes.** When redacting files in place, `redact` writes to a temporary file in the same directory and renames it over the original. A crash or power loss will never leave a half-written file.

6. **No `unsafe` code.** The codebase compiles with default Rust safety guarantees. There are no `unsafe` blocks.

## Key Features

| Feature | Description |
|---------|-------------|
| Secret detection | AWS keys, Bearer tokens, JWTs, private key blocks, API keys, database URLs, passwords, webhook secrets, Slack tokens, GitHub tokens, Stripe keys, generic secrets |
| PII detection | Email addresses, phone numbers, IPv4/IPv6 addresses, credit card numbers (Luhn-validated), US Social Security Numbers (format-validated) |
| Custom patterns | Define your own detectors with a safe pattern-matching syntax (bounded repetition, no backtracking) |
| Multiple input modes | Literal text (`--text`), file/directory (`--input`), or piped stdin |
| Multiple output modes | Stdout, file (`--output`), in-place (`--in-place`), JSON report (`--report-json`), structured JSON (`--format json`) |
| Dry-run | Preview what would be redacted without writing anything |
| CI gate | `--fail-on-find` exits with code 3 when findings are detected — plug it into any CI pipeline |
| Allow/deny lists | Selectively enable or disable individual detectors |
| TOML configuration | Persist settings and custom patterns in a config file |
| Directory traversal | Recursively process entire directory trees, preserving structure in the output directory |

## Quick Start

```bash
# Redact a string
redact redact --text "email me at user@example.com"

# Redact a file, write to a new file
redact redact --input secrets.txt --output redacted.txt

# Pipe through stdin
echo "token=sk_live_abc123xyz789def456" | redact redact

# Scan a directory, write cleaned output
redact redact --input logs/ --output cleaned/ --summary

# Dry-run: see what would be found without changing anything
redact redact --input .env --dry-run

# CI gate: fail the build if secrets are found
redact redact --input src/ --dry-run --fail-on-find
```

## How It Works

1. **Parse input.** CLI arguments are parsed by a hand-rolled parser (no external CLI framework). A TOML config file is optionally merged.
2. **Build detector registry.** All built-in detectors are instantiated. Allow/deny lists and custom patterns are applied to filter the set.
3. **Detect.** Each detector scans the input text in a single linear pass. Findings are collected, sorted by position, and overlapping matches are merged (higher-confidence match wins).
4. **Redact.** Each finding's span is replaced with a marker like `[REDACTED:EMAIL]`, or a custom replacement string.
5. **Report.** Depending on flags, the tool writes redacted text to stdout/file, prints a summary to stderr, and/or emits a structured JSON report.
