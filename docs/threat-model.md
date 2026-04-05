# Threat Model

This document describes the threat model for `redacted`: which attack vectors are considered, which are mitigated, and which are explicitly out of scope.

---

## Scope

`redacted` is a **local, offline text-processing tool**. It reads input from local files or stdin, processes it in memory, and writes output to local files or stdout. It has no network component, no server mode, and no persistence beyond the filesystem.

The primary use cases are:

1. **Pre-commit scanning** — Detect secrets before they reach version control.
2. **Log sanitization** — Redact PII and secrets from log files before storage or sharing.
3. **CI/CD gating** — Fail builds that contain detectable secrets.
4. **Ad-hoc redaction** — Clean up text or files for sharing.

---

## Assets to Protect

| Asset | Description |
|-------|-------------|
| Input data | The text/files being scanned, which may contain real secrets and PII |
| Redacted output | The output files, which should contain no raw secret/PII values |
| JSON reports | Structured reports, which contain masked (not full) samples |
| The tool itself | The binary should not be subvertible to produce incorrect output |

---

## Threat Actors

| Actor | Capability | Goal |
|-------|-----------|------|
| Malicious input author | Can craft input text/files processed by `redacted` | Cause DoS, bypass detection, crash the tool, or corrupt output |
| Supply-chain attacker | Can compromise upstream dependencies | Inject malicious code into the binary |
| Curious report reader | Has access to JSON reports | Extract full secret values from reports |
| Symlink attacker | Can create symlinks on the filesystem | Read or modify files outside the intended scan scope |

---

## Attack Vectors and Mitigations

### 1. Regular Expression Denial of Service (ReDoS)

**Vector:** Attacker provides input designed to cause catastrophic backtracking in a regex engine, leading to CPU exhaustion.

**Mitigation:** There is no regex engine. All built-in detectors are hand-written linear-time scanners. Custom patterns use a bounded repetition matcher with a hard cap of 4096 iterations per quantifier and no backtracking. Processing time is O(n) per detector, where n is the input size.

**Residual risk:** None for this vector.

### 2. Memory Exhaustion via Large Input

**Vector:** Attacker provides an extremely large file to exhaust available memory.

**Mitigation:**
- Files exceeding `--max-file-size` (default 25 MiB) are skipped entirely.
- The file is read into memory once; detectors scan it without copying.
- Directory depth is capped at 256 levels.

**Residual risk:** An attacker who controls `--max-file-size` or provides many files just under the limit could still consume significant memory. This is acceptable for a local tool.

### 3. Supply-Chain Attack

**Vector:** A compromised dependency introduces malicious code into the binary.

**Mitigation:** Zero external dependencies. The `[dependencies]` section is empty. There is nothing to compromise.

**Residual risk:** The Rust standard library and compiler are trusted. A compromised Rust toolchain could theoretically inject malicious code, but this is outside the scope of this project's threat model.

### 4. Path Traversal via Symlinks

**Vector:** A crafted symlink inside the scan directory points to a sensitive file outside it (e.g., `/etc/shadow`). If the tool follows the symlink, it could read or overwrite the target.

**Mitigation:**
- Symlinks are **not followed by default**.
- When `--follow-symlinks` is enabled, every resolved symlink target is checked against the canonicalized root directory. Targets outside the root are rejected.
- Atomic writes create temp files in the target's own directory, so a symlink pointing elsewhere won't cause writes to unexpected locations.

**Residual risk:** TOCTOU (time-of-check-time-of-use) race conditions are theoretically possible if the filesystem is modified between the symlink check and the file read. This is a fundamental limitation of filesystem operations and is not specific to `redacted`.

### 5. Secret Leakage in Reports

**Vector:** A JSON report is stored or transmitted, and an attacker extracts full secret values from it.

**Mitigation:** The `masked_sample` field in reports shows only the first few characters (up to 4) followed by `***`. The full matched text is never included in reports.

**Residual risk:** For very short secrets (1–4 characters), the masked sample reveals the entire value. However, secrets this short are unlikely to be meaningful. The `[REDACTED:<TYPE>]` marker in redacted output reveals the detector name, which discloses what *kind* of secret was present, but not its value.

### 6. Incomplete Redaction (Bypass)

**Vector:** Attacker crafts secrets in formats that evade detection, causing them to survive the redaction process.

**Mitigation:** Each detector targets specific, well-known formats with structural validation (prefix matching, length checks, Luhn validation, SSN rules). The allow/deny system lets users tune detection.

**Residual risk:** This is inherently an open problem. No scanner can guarantee detection of all possible secret formats. Specific bypass scenarios include:

- Secrets in formats without a matching detector.
- Base64-encoded or otherwise obfuscated secrets.
- Secrets split across multiple lines (except PEM key blocks).
- Secrets embedded in binary content (skipped by default).
- Zero-width characters or homoglyphs inserted into secrets.
- Novel key formats from new services.

**Recommendation:** Use `redacted` as one layer in a defense-in-depth strategy. Combine with pre-commit hooks, secret rotation, and access control.

### 7. Output Corruption

**Vector:** A crash during file writing leaves the output file in a partially-written state.

**Mitigation:** All file writes use atomic write semantics (write to temp file, fsync, rename). A crash at any point leaves either the original file or the fully-written new file. There is no partial-write window.

**Residual risk:** None for this vector on POSIX-compliant filesystems.

### 8. Binary File Misprocessing

**Vector:** A binary file is processed as text, leading to corrupted output or incorrect findings.

**Mitigation:** Binary detection is performed before processing. Files with null bytes or >30% non-text bytes in the first 8192 bytes are classified as binary and handled according to `--binary` mode (default: skip).

**Residual risk:** Files that pass the binary check but contain non-UTF-8 sequences will fail with a clear error. The 8192-byte sample could miss binary content that starts after the sample window, but this is extremely rare in practice.

### 9. Custom Pattern DoS

**Vector:** A user-supplied custom pattern (via `--pattern` or config file) causes excessive CPU usage.

**Mitigation:** The custom pattern matcher uses greedy, non-backtracking matching with all quantifiers (`+`, `*`, `?`) capped at 4096 repetitions. Features that enable catastrophic backtracking (backreferences, lookahead, nested quantifiers) are not supported.

**Residual risk:** A custom pattern with many alternations or complex character classes still runs in linear time per input byte, but the constant factor increases. This is bounded and predictable.

---

## Explicitly Out of Scope

The following are **not** part of the threat model:

| Concern | Reason |
|---------|--------|
| Compromised Rust toolchain | Trusted base; not mitigatable by this project |
| Malicious local user with same privileges | They can already read the files directly |
| Secure memory wiping | Not a goal; use dedicated tools for data remanence |
| Encrypted input processing | Decryption is a separate concern; `redacted` operates on plaintext |
| Network-based attacks | There is no network component |
| Side-channel attacks | Local tool; timing/power analysis not relevant |
| Malicious `--config` file | Config files are provided by the user; a malicious config could disable detection, but the user controls this |
