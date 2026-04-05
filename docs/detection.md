# Detection Reference

`redacted` ships with 18 built-in detectors organized into two categories — **secrets** and **PII** — plus support for user-defined **custom** patterns.

Every built-in detector is a purpose-built, linear-time scanner. There is no regex engine; each detector walks the input byte-by-byte with bounded scan windows, making ReDoS impossible.

---

## Detector Summary

| Detector Name | Category | What It Detects | Confidence |
|---------------|----------|-----------------|------------|
| `AWS_KEY` | secret | AWS access key IDs | High |
| `BEARER_TOKEN` | secret | Bearer authentication tokens | High |
| `JWT` | secret | JSON Web Tokens | High |
| `PRIVATE_KEY` | secret | PEM-encoded private key blocks | High / Medium |
| `API_KEY` | secret | Generic API key assignments | Medium |
| `DATABASE_URL` | secret | Database connection strings with credentials | High / Medium |
| `PASSWORD` | secret | Password assignments in config/env files | Medium |
| `WEBHOOK_SECRET` | secret | Webhook signing secrets | High |
| `SLACK_TOKEN` | secret | Slack API tokens | High |
| `GITHUB_TOKEN` | secret | GitHub personal access tokens and app tokens | High |
| `STRIPE_KEY` | secret | Stripe API keys (secret, publishable, restricted) | High |
| `GENERIC_SECRET` | secret | Generic secret/token/credential assignments | Medium |
| `EMAIL` | pii | Email addresses | High |
| `PHONE` | pii | Phone numbers (international formats) | High / Medium |
| `IP` | pii | IPv4 and IPv6 addresses (both reported as `[REDACTED:IP]`) | High / Medium |
| `PATH` | pii | Filesystem paths (absolute, relative, `~`, Windows drive paths) | High / Medium |
| `CREDIT_CARD` | pii | Credit card numbers (Luhn-validated) | High |
| `SSN` | pii | US Social Security Numbers | High |

---

## Secret Detectors

### AWS_KEY

Detects AWS access key IDs by matching the known 20-character prefix patterns.

- **Prefixes:** `AKIA`, `ABIA`, `ACCA`, `ASIA`
- **Length:** Exactly 20 alphanumeric characters
- **Boundary check:** Must appear at a word boundary
- **Confidence:** High

```
AKIAIOSFODNN7EXAMPLE       -> detected
ASIA1234567890123456       -> detected
```

### BEARER_TOKEN

Detects Bearer authentication tokens in HTTP-style headers.

- **Trigger:** Case-insensitive `Bearer ` prefix
- **Token body:** Base64url characters and dots, minimum 20 characters
- **Max scan:** 2048 characters
- **Confidence:** High

```
Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig   -> detected
bearer short_tok                                           -> not detected (too short)
```

### JWT

Detects JSON Web Tokens by their characteristic structure.

- **Trigger:** `eyJ` prefix (base64-encoded `{"` — the start of every JWT header)
- **Structure:** Three base64url segments separated by exactly two dots
- **Minimum length:** 36 characters
- **Max scan:** 4096 characters
- **Boundary check:** Must start at a word boundary
- **Confidence:** High

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.sig   -> detected
```

### PRIVATE_KEY

Detects PEM-encoded private key blocks by their begin/end markers.

- **Supported key types:**
  - RSA Private Key
  - Private Key (PKCS#8)
  - EC Private Key
  - OpenSSH Private Key
  - DSA Private Key
  - PGP Private Key Block
- **Confidence:** High when both BEGIN and END markers are found; Medium for partial (unclosed) blocks

```
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA...
-----END RSA PRIVATE KEY-----
```

### API_KEY

Detects generic API key assignments in configuration-style lines.

- **Keywords (case-insensitive):** `api_key`, `apikey`, `api-key`, `access_key`, `secret_key`
- **Format:** `keyword=value`, `keyword: value`, or `keyword = "value"`
- **Minimum value length:** 4 characters
- **Strips quotes** around values
- **Confidence:** Medium

```
API_KEY=sk_abcdef123456    -> detected
api-key: my_secret_value   -> detected
```

### DATABASE_URL

Detects database connection strings, particularly those containing credentials.

- **Schemes:** `postgres://`, `postgresql://`, `mysql://`, `mongodb://`, `mongodb+srv://`, `redis://`, `rediss://`, `amqp://`, `amqps://`
- **Minimum length:** 15 characters
- **Confidence:** High if the URL contains `@` (indicating credentials); Medium otherwise

```
postgres://admin:s3cret@db.host:5432/mydb   -> detected (High)
redis://cache:6379                           -> detected (Medium)
```

### PASSWORD

Detects password assignments in configuration files and environment variables.

- **Keywords (case-insensitive):** `password`, `passwd`, `pass`
- **Format:** `keyword=value` or `keyword: value`
- **Minimum value length:** 4 characters
- **Confidence:** Medium

```
password=hunter2                 -> detected
DB_PASSWD: "my_secret_pass"     -> detected
```

### WEBHOOK_SECRET

Detects webhook signing secrets by known prefixes.

- **Prefixes:** `whsec_`, `whsk_`
- **Body:** Base64url characters
- **Minimum total length:** 20 characters
- **Confidence:** High

```
whsec_abcdefghijklmnopqrstuvwxyz   -> detected
```

### SLACK_TOKEN

Detects Slack API tokens by their characteristic prefixes.

- **Prefixes:** `xoxb-`, `xoxp-`, `xoxs-`, `xoxa-`, `xoxo-`, `xoxr-`
- **Body:** Alphanumeric characters and hyphens
- **Minimum total length:** 15 characters
- **Confidence:** High

```
xoxb-1234-5678-abcdefghijkl   -> detected
```

### GITHUB_TOKEN

Detects GitHub personal access tokens and app tokens.

- **Prefixes:** `ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_`, `github_pat_`
- **Body:** Alphanumeric characters and underscores
- **Minimum total length:** 15 characters
- **Confidence:** High

```
ghp_abcdefghijklmnop1234567890abcd   -> detected
github_pat_abc123def456ghi789         -> detected
```

### STRIPE_KEY

Detects Stripe API keys (secret, publishable, and restricted).

- **Prefixes:** `sk_live_`, `sk_test_`, `pk_live_`, `pk_test_`, `rk_live_`, `rk_test_`
- **Body:** Alphanumeric characters and underscores
- **Minimum total length:** 15 characters
- **Confidence:** High

```
sk_live_abcdef1234567890   -> detected
pk_test_xyz789             -> detected (if >= 15 chars)
```

### GENERIC_SECRET

Catches miscellaneous secret assignments that don't match a more specific detector.

- **Keywords (case-insensitive):** `secret`, `token`, `credential`, `auth_key`
- **Anti-false-positive:** Rejects matches where the keyword is part of a longer word (e.g., "secretary")
- **Format:** `keyword=value` or `keyword: value`
- **Minimum value length:** 4 characters
- **Confidence:** Medium

```
MY_SECRET=abcdef123456   -> detected
AUTH_TOKEN: xyz789abc    -> detected
The secretary left.     -> NOT detected
```

---

## PII Detectors

### EMAIL

Detects email addresses by scanning for `@` symbols and validating both local and domain parts.

- **Local part:** Alphanumeric, `.`, `+`, `-`, `_`
- **Domain part:** Alphanumeric, `.`, `-`
- **Validation:** Domain must contain at least one dot; TLD must be at least 2 characters
- **Length:** 5–320 characters total
- **Confidence:** High

```
user@example.com        -> detected
name+tag@sub.domain.co  -> detected
user@localhost           -> NOT detected (no TLD)
```

### PHONE

Detects phone numbers in various international formats.

- **Accepted characters:** Digits, `+` (leading only), spaces, hyphens, dots, parentheses
- **Digit count:** 7–15 digits
- **Minimum span:** 7 characters
- **Anti-false-positive:** Rejects sequences that look like IP addresses (digits separated only by dots)
- **Confidence:** High if >= 10 digits; Medium if 7–9 digits

```
+1-555-867-5309          -> detected (High)
+44 20 7946 0958         -> detected (High)
555-1234                 -> detected (Medium)
192.168.1.1              -> NOT detected (looks like IP)
```

### IP

Detects both **IPv4** and **IPv6** addresses. Both kinds of match are reported with the same detector name `IP` and replacement marker `[REDACTED:IP]`.

**IPv4**

- **Format:** Four decimal octets separated by dots
- **Validation:** Each octet 0–255, no leading zeros (except `0` itself), word boundary checks
- **Confidence:** High

```
192.168.1.100   -> detected
10.0.0.1        -> detected
300.1.2.3       -> NOT detected (octet > 255)
01.2.3.4        -> NOT detected (leading zero)
```

**IPv6**

- **Format:** Hex groups separated by colons
- **Supports:** Full addresses (8 groups) and compressed addresses with `::`
- **Validation:** At most one `::`, at least 3 groups (or 1 with `::`)
- **Minimum length:** 6 characters
- **Max scan:** 45 characters
- **Confidence:** Medium

```
2001:0db8:85a3:0000:0000:8a2e:0370:7334   -> detected
::1                                         -> detected (if >= 6 chars)
fe80::1%eth0                                -> partially detected
```

### PATH

Detects filesystem paths that look like real directory/file locations (not bare `a/b` option-style text).

- **Starts:** Absolute (`/…`, `C:\…`), relative (`./…`, `../…`), or home (`~/…`)
- **Scan:** Path characters are collected up to a bounded length (4096 bytes)
- **Heuristic:** Requires minimum length and multiple path separators so short ambiguous spans are skipped
- **Confidence:** High when the path has many segments; Medium for shorter multi-segment paths

```
config at /etc/nginx/nginx.conf     -> detected
file: /home/user/.ssh/id_rsa        -> detected
log at ./logs/app/server.log        -> detected
use a/b for the option              -> typically NOT detected (too few separators)
```

### CREDIT_CARD

Detects credit card numbers with Luhn algorithm validation.

- **Digit count:** 13–19 digits
- **Accepted separators:** Spaces and hyphens between groups
- **Validation:** Luhn checksum must pass
- **Boundary check:** Must start and end at non-alphanumeric boundaries
- **Confidence:** High

```
4111 1111 1111 1111    -> detected (valid Luhn)
4111-1111-1111-1111    -> detected
4111111111111111       -> detected
1234567890123456       -> NOT detected (fails Luhn)
```

### SSN

Detects US Social Security Numbers in the standard formatted pattern.

- **Format:** `NNN-NN-NNNN` (exactly, with hyphens)
- **Validation rules:**
  - Area number (first 3 digits) cannot be `000`, `666`, or `900`–`999`
  - Group number (middle 2 digits) cannot be `00`
  - Serial number (last 4 digits) cannot be `0000`
- **Boundary check:** Must not be preceded or followed by a digit
- **Confidence:** High

```
123-45-6789   -> detected
000-45-6789   -> NOT detected (invalid area)
666-45-6789   -> NOT detected (invalid area)
900-45-6789   -> NOT detected (area starts with 9)
123-00-6789   -> NOT detected (invalid group)
123-45-0000   -> NOT detected (invalid serial)
```

---

## Custom Patterns

Custom patterns are added via `--pattern NAME=PATTERN` on the command line or in a TOML config file under the `[pattern]` section.

### Supported Syntax

Custom patterns use a safe subset of regex-like syntax. The matcher is non-backtracking and bounds all repetitions to 4096 iterations.

| Syntax | Meaning |
|--------|---------|
| Literal characters | Match exactly |
| `.` | Any character except newline |
| `[a-zA-Z0-9]` | Character class with ranges |
| `[^0-9]` | Negated character class |
| `\d`, `\D` | Digit / non-digit |
| `\w`, `\W` | Word character / non-word character |
| `\s`, `\S` | Whitespace / non-whitespace |
| `+` | One or more (greedy, bounded to 4096) |
| `*` | Zero or more (greedy, bounded to 4096) |
| `?` | Zero or one |
| `^`, `$` | Anchors (parsed but act as no-ops in substring matching mode) |

### Not Supported (By Design)

These features are intentionally omitted to prevent catastrophic backtracking:

- Backreferences
- Lookahead / lookbehind
- Nested quantifiers
- Unbounded repetition of complex groups
- Alternation (`|`)
- Capture groups

### Examples

```bash
# Match internal project IDs
--pattern "PROJECT_ID=PROJ-\\d+"

# Match hex values
--pattern "HEX_VALUE=0x[0-9a-fA-F]+"

# Match a custom API key format
--pattern "INTERNAL_KEY=int_[a-zA-Z0-9]+"
```

Custom detectors always report with:
- **Category:** `custom`
- **Confidence:** Medium

---

## Confidence Levels

Each finding is assigned a confidence level that indicates how likely it is to be a true positive.

| Level | Meaning |
|-------|---------|
| **High** | Strong structural match. The pattern is highly specific (e.g., AWS key prefix + exact length, Luhn-validated credit card, SSN with validation) |
| **Medium** | Plausible match that may have false positives. Typically key-value assignment patterns, IPv6 addresses (under the unified `IP` detector), shorter filesystem paths, or custom patterns |
| **Low** | Defined but not currently assigned by any built-in detector. Available for future use or custom detectors |

---

## Overlapping Findings

When multiple detectors match overlapping spans of text, `redacted` keeps only the best match:

1. Findings are sorted by start position.
2. When two findings overlap, the one with **higher confidence** wins.
3. If confidence is equal, the **longer match** wins.

This prevents double-redaction and ensures the most specific detector takes precedence.

---

## Masked Samples in Reports

JSON reports include a `masked_sample` field for each finding. This is a partially masked version of the matched text, designed so that reports never leak full secret values.

- For matches <= 4 characters: entirely replaced with `*`
- For longer matches: the first 25% of characters (up to 4) are visible, followed by `***`

```
# Example masked samples
"password_value_123"  -> "pass***"
"abc"                 -> "***"
"AKIAIOSFODNN7EXAMPLE" -> "AKIA***"
```
