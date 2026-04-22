# CLI Reference

## Synopsis

``` 
redacted [OPTIONS]
redacted provider <COMMAND> [OPTIONS]
echo "text" | redacted [OPTIONS]
```

The binary is called `redacted`. Normal scans still use flags directly. The only
subcommand family is `redacted provider ...`, which manages optional
privacy-filter bundles outside the hardened Rust-only core scan path.

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
- `ollama/gpt-oss-v1` is an experimental generative-extraction path

| Command | Description |
|---------|-------------|
| `redacted provider enable <provider-or-target>` | Easy onboarding: install if missing, verify, and activate |
| `redacted provider install <provider-or-target>` | Download and verify a bundle without activating it |
| `redacted provider use <provider-or-target>` | Switch the active provider to an installed, verified bundle |
| `redacted provider current` | Show the active exact target |
| `redacted provider list` | Show aliases, exact targets, and local install state |
| `redacted provider verify [<provider-or-target> \| --all]` | Re-hash installed bundle artifacts |
| `redacted provider disable` | Clear the active provider selection |

Aliases are human-friendly shortcuts such as `openai` and `ollama`. Exact
targets are stable IDs such as `openai/privacy-filter-v1` and
`ollama/gpt-oss-v1`. When an alias is used, the CLI prints the resolved exact
target before changing local state.

Examples:

```bash
redacted provider enable openai
redacted provider enable ollama
redacted provider install openai/privacy-filter-v1
redacted provider install ollama/gpt-oss-v1
redacted provider use openai
redacted provider use ollama
redacted provider current
redacted provider verify --all
redacted provider disable
```

Notes:

- `openai` resolves to `openai/privacy-filter-v1`
- `ollama` resolves to `ollama/gpt-oss-v1`
- `redacted --privacy-filter ...` never downloads anything during a scan
- `redacted provider enable ollama` requires a running local Ollama API
- `ollama` relies on structured JSON generation rather than a native token-classification runtime

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

# Switch to the Ollama-backed provider first
redacted provider enable ollama
redacted --privacy-filter --input logs/
```

### Configuration File

```bash
# Use a TOML config file
redacted --input logs/ --output cleaned/ --config redact.toml
```

See [config.md](config.md) for the configuration file format.
