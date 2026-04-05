# Configuration

`redact` supports an optional TOML configuration file, loaded via the `--config <PATH>` flag. Configuration file values are merged with CLI arguments, with **CLI arguments always taking precedence**.

---

## File Format

The config file uses a simplified TOML format supporting:

- Flat `key = value` pairs
- `[section]` headers (one level deep)
- `# comments`
- Quoted and unquoted string values

**Not** supported (intentionally, to keep the parser simple and auditable):

- Arrays
- Inline tables
- Multi-line strings
- Nested sections
- TOML datetime types

---

## Configuration Keys

### Top-Level Keys

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `replacement` | string | `[REDACTED:<TYPE>]` | Custom replacement string for all redacted spans |
| `max_file_size` | integer | `26214400` (25 MiB) | Maximum file size in bytes. Files larger than this are skipped |
| `include_hidden` | boolean | `false` | Include hidden files/directories in directory traversal |
| `follow_symlinks` | boolean | `false` | Follow symbolic links during directory traversal |
| `binary` | string | `skip` | Binary file handling mode: `skip`, `fail`, or `best-effort` |
| `allow_patterns` | string | *(empty)* | Comma-separated list of detector names to enable exclusively |
| `deny_patterns` | string | *(empty)* | Comma-separated list of detector names to disable |

### Custom Patterns Section

Custom patterns are defined under the `[pattern]` section. Each entry maps a detector name to a pattern string.

```toml
[pattern]
detector_name = "pattern_string"
```

---

## Precedence Rules

1. **CLI flags always win.** If a value is set on the command line, the config file value is ignored for that setting.
2. **Config file provides defaults.** Values not explicitly set on the CLI are populated from the config file.
3. **Custom patterns are additive.** Patterns from the config file are appended to patterns from `--pattern` flags. They do not replace each other.
4. **Allow/deny lists are additive.** Lists from the config file are merged with CLI lists. Duplicates are ignored.

---

## Examples

### Minimal Config

```toml
# Use a custom replacement string
replacement = "[SCRUBBED]"
```

### Full Config

```toml
# Replacement string for all redactions
replacement = "[REDACTED]"

# File size limit (10 MiB)
max_file_size = 10485760

# Include hidden files in directory scans
include_hidden = true

# Follow symlinks (with path traversal protection)
follow_symlinks = false

# Binary file handling: skip | fail | best-effort
binary = "skip"

# Only enable these detectors (comma-separated)
# allow_patterns = "AWS_KEY, PRIVATE_KEY, DATABASE_URL"

# Disable these detectors (comma-separated)
deny_patterns = "PHONE, IPV6"

# Custom patterns
[pattern]
INTERNAL_API_KEY = "int_[a-zA-Z0-9]+"
PROJECT_ID = "PROJ-\\d+"
BUILD_TOKEN = "build_[a-zA-Z0-9_]+"
```

### Secrets-Only Config

Only detect secrets, not PII:

```toml
deny_patterns = "EMAIL, PHONE, IPV4, IPV6, CREDIT_CARD, SSN"
```

### PII-Only Config

Only detect PII, not secrets:

```toml
allow_patterns = "EMAIL, PHONE, IPV4, IPV6, CREDIT_CARD, SSN"
```

### CI Pipeline Config

Strict configuration for CI scanning:

```toml
replacement = "[SECRET_DETECTED]"
max_file_size = 5242880
include_hidden = false
follow_symlinks = false
binary = "fail"
```

Use with:

```bash
redact redact --input src/ --dry-run --fail-on-find --config ci-redact.toml
```

### Custom Patterns for Internal Services

```toml
[pattern]
# Internal service tokens
AUTH_SERVICE_TOKEN = "auth_tk_[a-zA-Z0-9]+"
SESSION_ID = "sess_[a-zA-Z0-9]+"

# Internal identifiers
EMPLOYEE_ID = "EMP-\\d+"
TICKET_ID = "TICKET-\\d+"
```

---

## Using Config with CLI Overrides

CLI flags override config file values. This lets you define a base config and adjust per invocation:

```bash
# Config sets replacement="[SCRUBBED]", but CLI overrides it
redact redact --input logs/ --output cleaned/ \
  --config base.toml \
  --replacement "[REMOVED]"

# Config denies PHONE, but CLI adds extra deny
redact redact --input data/ --dry-run \
  --config base.toml \
  --deny-pattern IPV4

# Config defines patterns; CLI adds one more
redact redact --input src/ --dry-run \
  --config base.toml \
  --pattern "EXTRA=extra_[a-z]+"
```

---

## Config File Location

There is no default config file location. The config file must be explicitly specified with `--config <PATH>`. This is a deliberate design choice: the tool should behave identically regardless of the working directory unless you explicitly opt into configuration.
