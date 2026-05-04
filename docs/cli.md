# CLI Reference

## Synopsis

``` 
redacted [OPTIONS]
redacted provider <COMMAND> [OPTIONS]
redacted detector <COMMAND> [OPTIONS]
redacted document <COMMAND> [OPTIONS]
redacted benchmark --input <PATH> [OPTIONS]
echo "text" | redacted [OPTIONS]
```

The binary is called `redacted`. Normal scans still use flags directly.
`redacted provider ...` manages optional privacy-filter bundles.
`redacted detector ...` manages optional external detector engines.
`redacted document ...` manages optional document adapters.
`redacted benchmark ...` runs repeatable local benchmark scans.

---

## Input Options

Input is resolved in priority order: `--text` > `--input` > stdin.

| Flag | Argument | Description |
|------|----------|-------------|
| `--text` | `<TEXT>` | Literal text string to redact |
| `--input` | `<PATH>` | File or directory to process |
| *(stdin)* | — | Reads piped stdin when no `--text` or `--input` is provided |

If none of the above are provided and stdin is a terminal (not piped), the tool exits with a usage error (exit code 2).

---

## Output Options

| Flag | Argument | Description |
|------|----------|-------------|
| `--output` | `<PATH>` | Write redacted output to a file or directory |
| `--in-place` | — | Rewrite input file(s) atomically in place |
| `--format` | `text\|json` | Output format. `text` (default) writes redacted content. `json` writes a structured JSON report to stdout |
| `--report-json` | — | Write redacted content normally **and** emit a structured JSON report to stderr |
| `--replacement` | `<STRING>` | Custom replacement string instead of the default `[REDACTED:<TYPE>]` marker |
| `--privacy-filter` | — | Run the active privacy-filter provider as one extra optional detection pass |
| `--detectors` | — | Run active external detector engines for this `--input` scan |
| `--no-detectors` | — | Disable external detector engines for this scan, even when the detector default is on |
| `--document-adapter` | — | Run the active document adapter for supported non-text files (`.pdf` in v1) |

### Default Replacement Format

When no `--replacement` is specified, each redacted span is replaced with:

```
[REDACTED:<DETECTOR_NAME>]
```

For example: `[REDACTED:EMAIL]`, `[REDACTED:AWS_KEY]`, `[REDACTED:SSN]`.

### Output Behavior by Mode

| Input | Flags | Behavior |
|-------|-------|----------|
| `--text` or stdin | *(none)* | Redacted text to stdout |
| `--text` or stdin | `--output` | Redacted text to file |
| `--input <FILE>` | *(none)* | Redacted text to stdout |
| `--input <FILE>` | `--output` | Redacted text to output file |
| `--input <FILE>` | `--in-place` | Overwrites original file atomically |
| `--input <DIR>` | `--output <DIR>` | Writes redacted files preserving directory structure |
| `--input <DIR>` | `--dry-run` | No output written; summary to stderr |
| `--input <DIR>` | *(none)* | **Error** (exit code 2) — directory mode requires `--output`, `--dry-run`, `--summary`, or `--report-json` |

---

## Detector Options

| Flag | Argument | Description |
|------|----------|-------------|
| `--pattern` | `<NAME=PATTERN>` | Add a custom pattern detector. May be repeated. Pattern uses a safe subset of regex syntax (see [detection.md](detection.md)) |
| `--allow-pattern` | `<NAME>` | Only enable this detector. May be repeated. When specified, all detectors **not** in the allow list are disabled |
| `--deny-pattern` | `<NAME>` | Disable this detector. May be repeated |

`--allow-pattern` and `--deny-pattern` accept detector names such as `EMAIL`, `AWS_KEY`, `SSN`, etc.

---

## Traversal Options

| Flag | Argument | Default | Description |
|------|----------|---------|-------------|
| `--recursive` | — | On | Recurse into subdirectories |
| `--include-hidden` | — | Off | Process hidden files and directories (names starting with `.`) |
| `--follow-symlinks` | — | Off | Follow symbolic links. Symlink targets outside the root directory are rejected (path traversal protection) |
| `--no-follow-symlinks` | — | *(default)* | Explicitly do not follow symlinks |
| `--binary` | `skip\|fail\|best-effort` | `skip` | How to handle binary files |
| `--max-file-size` | `<BYTES>` | `26214400` (25 MiB) | Maximum file size to process. Files exceeding this are skipped |

### Binary File Handling

| Mode | Behavior |
|------|----------|
| `skip` | Silently skip binary files (default) |
| `fail` | Report binary files as errors |
| `best-effort` | Attempt to process binary files as text |

Binary detection samples the first 8192 bytes and checks for null bytes or a high ratio of non-text bytes.

---

## Mode Options

| Flag | Description |
|------|-------------|
| `--dry-run` | Show what would be redacted without writing any output. Prints a summary to stderr |
| `--fail-on-find` | Exit with code 3 if any findings are detected. Useful for CI pipelines |
| `--summary` | Print a human-readable summary to stderr |
| `--config` | Path to a TOML configuration file (see [config.md](config.md)) |

---

## Other Options

| Flag | Argument | Description |
|------|----------|-------------|
| `--threads` | `<N>` | Number of worker threads for directory mode |
| `--help`, `-h` | — | Show help text and exit |
| `--version`, `-V` | — | Show version and exit |

---

## Provider Commands

Use `redacted provider ...` to install, verify, and switch optional
privacy-filter bundles. This provider path is explicit and lower-trust than the
default Rust-only detector path because it wraps external runtimes.

Current support levels:

- `openai/privacy-filter-v1` is the supported token-span path
- `openai/privacy-filter-v1-mlx` is the experimental local MLX path for Apple
  Silicon. It uses the same privacy-filter label contract, but a different
  runner and model format.

| Command | Description |
|---------|-------------|
| `redacted provider enable <provider-or-target>` | Easy onboarding: install if missing, verify, and activate |
| `redacted provider install <provider-or-target>` | Download and verify a bundle without activating it |
| `redacted provider use <provider-or-target>` | Switch the active provider to an installed, verified bundle |
| `redacted provider current` | Show the active exact target |
| `redacted provider list` | Show aliases, exact targets, license metadata, and local install state |
| `redacted provider verify [<provider-or-target> \| --all]` | Re-hash installed bundle artifacts |
| `redacted provider disable` | Clear the active provider selection |

Aliases are human-friendly shortcuts such as `openai` and `mlx`. Exact targets
are stable IDs such as `openai/privacy-filter-v1` and
`openai/privacy-filter-v1-mlx`. When an alias is used, the CLI prints the
resolved exact target before changing local state.

Examples:

```bash
redacted provider enable openai
redacted provider enable mlx
redacted provider install openai/privacy-filter-v1
redacted provider install openai/privacy-filter-v1-mlx
redacted provider use openai
redacted provider use mlx
redacted provider current
redacted provider verify --all
redacted provider disable
```

Notes:

- `openai` resolves to `openai/privacy-filter-v1`
- `mlx` resolves to `openai/privacy-filter-v1-mlx`
- MLX setup requires Python 3.10 or newer and downloads the pinned
  `mlx-community/openai-privacy-filter-4bit` model conversion
- `redacted --privacy-filter ...` never downloads anything during a scan
- Generative runtimes are not privacy-filter providers unless they run a real detector with verified span output

---

## Detector Commands

Use `redacted detector ...` to bind, verify, and activate optional external
secret detector engines. Native detectors always run; `--detectors` adds active
external engines for `--input` scans.

Current built-in target:

- `trufflehog/secrets-v1` backed by the local TruffleHog CLI

| Command | Description |
|---------|-------------|
| `redacted detector install <detector-or-target>` | Bind to a local executable and verify its SHA-256 |
| `redacted detector use <detector-or-target>` | Add an installed detector engine to the active set |
| `redacted detector current` | Show active external detectors and default mode |
| `redacted detector list` | Show aliases, exact targets, license metadata, and local install state |
| `redacted detector verify [<detector-or-target> \| --all]` | Re-check installed detector executables |
| `redacted detector disable [<detector-or-target> \| --all]` | Remove detector engines from the active set |
| `redacted detector default <on\|off>` | Persist whether active external detectors run by default for `--input` scans |

Examples:

```bash
redacted detector install trufflehog
redacted detector use trufflehog
redacted --detectors --input repo/
redacted detector default on
redacted --input repo/
redacted --no-detectors --input repo/
```

Notes:

- `trufflehog` resolves to `trufflehog/secrets-v1`.
- `install` does not download TruffleHog; install it separately and keep it in `PATH`.
- Scans run `trufflehog filesystem <path> --json --no-verification --no-update --no-color`.
- External detectors require `--input`; they do not run for `--text` or stdin.
- TruffleHog is AGPL-3.0 and remains an external tool, not vendored into the MIT core.

---

## Document Commands

Use `redacted document ...` to install, verify, and switch optional
document adapters. This path is explicit and lower-trust than the
default Rust-only detector path because it wraps an external extraction runtime.

Current built-in targets:

- `poppler/pdftotext-v1` backed by local `pdftotext`
- `firecrawl/pdf-inspector-v1` backed by local Firecrawl `pdf2md`

| Command | Description |
|---------|-------------|
| `redacted document enable <adapter-or-target>` | Easy onboarding: install if missing, verify, and activate |
| `redacted document install <adapter-or-target>` | Install and verify without activating |
| `redacted document use <adapter-or-target>` | Switch the active adapter to an installed, verified target |
| `redacted document current` | Show the active exact target |
| `redacted document list` | Show aliases, exact targets, license metadata, and local install state |
| `redacted document verify [<adapter-or-target> \| --all]` | Re-verify installed adapter assets and runtime prerequisites |
| `redacted document disable` | Clear the active adapter selection |

Examples:

```bash
redacted document enable pdf
redacted document enable firecrawl-pdf
redacted document install poppler/pdftotext-v1
redacted document use pdf
redacted document current
redacted document verify --all
redacted document disable
```

Notes:

- `pdf` resolves to `poppler/pdftotext-v1`
- `firecrawl-pdf` resolves to `firecrawl/pdf-inspector-v1`
- `pdf` is the short human alias for the PDF document type; exact targets name
  the adapter implementation.
- `redacted --document-adapter ...` never installs adapters during a scan
- if no active adapter is configured, `--document-adapter` fails fast with the next setup command
- `--in-place` is blocked for document-adapter extracted files; use `--output` for persisted output

---

## Benchmark Command

Use `redacted benchmark ...` for repeatable local dry-run measurements.

```bash
redacted benchmark --input <PATH> [--iterations <N>] [--privacy-filter] [--document-adapter] [--format text|json]
```

Examples:

```bash
redacted benchmark --input logs/
redacted benchmark --input logs/ --iterations 10 --privacy-filter
redacted benchmark --input report.pdf --document-adapter --format json
```

Notes:

- benchmark runs do not write output files (`--dry-run` under the hood)
- benchmark output includes per-run timing and summary metrics
- the same provider/document adapter preconditions apply when those flags are enabled

---

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Success. Processing completed without error |
| `1` | Operational error. I/O failure, config parse error, traversal error, etc. |
| `2` | Usage error. Invalid arguments, missing required flags, unknown flags |
| `3` | Findings detected. Only returned when `--fail-on-find` is active and at least one finding was found |

---

## Examples

### Basic Text Redaction

```bash
# Redact an email from a literal string
redacted --text "Contact user@example.com for help"
# Output: Contact [REDACTED:EMAIL] for help

# Redact with a custom replacement
redacted --text "key=AKIAIOSFODNN7EXAMPLE" --replacement "***"
# Output: key=***
```

### Piped Input

```bash
# Pipe a file through redacted
cat .env | redacted

# Pipe command output
git log --oneline | redacted

# Chain with other tools
curl -s https://api.example.com/config | redacted > safe-config.txt
```

### File Processing

```bash
# Redact a single file to stdout
redacted --input secrets.log

# Redact a file to a new file
redacted --input secrets.log --output clean.log

# Redact a file in place (atomic write)
redacted --input .env --in-place
```

### Directory Processing

```bash
# Redact an entire directory
redacted --input logs/ --output cleaned-logs/

# Dry-run a directory scan
redacted --input src/ --dry-run

# Directory scan with JSON report on stderr
redacted --input repo/ --output repo-clean/ --report-json 2>report.json
```

### CI Pipeline Integration

```bash
# Fail the build if secrets are found in source
redacted --input src/ --dry-run --fail-on-find

# Scan with only specific detectors
redacted --input . --dry-run --fail-on-find \
  --allow-pattern AWS_KEY \
  --allow-pattern PRIVATE_KEY \
  --allow-pattern DATABASE_URL

# Exclude noisy detectors
redacted --input . --dry-run --fail-on-find \
  --deny-pattern PHONE \
  --deny-pattern IP
```

### Custom Patterns

```bash
# Add a custom detector for internal project IDs
redacted --text "ticket PROJ-1234" --pattern "PROJECT_ID=PROJ-\\d+"

# Multiple custom patterns
redacted --input config.yml \
  --pattern "INTERNAL_KEY=int_[a-zA-Z0-9]+" \
  --pattern "BUILD_ID=build-\\d+"
```

### JSON Output

```bash
# Full JSON output (structured report instead of redacted text)
redacted --text "user@example.com" --format json

# Redacted text + JSON report to stderr
redacted --text "user@example.com" --report-json 2>report.json

# Run the extra provider-backed pass with the active provider
redacted --privacy-filter --input logs/

# Switch to the supported OpenAI Privacy Filter provider first
redacted provider enable openai
redacted --privacy-filter --input logs/

# Or use the experimental local MLX runtime on Apple Silicon
redacted provider enable mlx
redacted --privacy-filter --input logs/
```

### Configuration File

```bash
# Use a TOML config file
redacted --input logs/ --output cleaned/ --config redact.toml
```

See [config.md](config.md) for the configuration file format.
