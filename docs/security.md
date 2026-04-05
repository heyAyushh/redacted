# Security Guarantees

This document describes what `redacted` guarantees, what it does not guarantee, and the security-relevant design decisions behind the tool.

---

## What Is Guaranteed

### No External Dependencies

The `Cargo.toml` has **zero entries** under `[dependencies]`. The entire binary is built from Rust's standard library and the project's own code. This means:

- No transitive dependency tree to audit.
- No supply-chain attacks via compromised crates.
- No unexpected native library linkage.
- The entire codebase is auditable in one repository.

### No `unsafe` Code

There are no `unsafe` blocks anywhere in the codebase. All memory safety guarantees of the Rust compiler apply.

### No Network Access

`redacted` never opens a network socket. It does not:

- Phone home.
- Check for updates.
- Send telemetry.
- Resolve DNS.
- Make HTTP requests.

Input is read from local files or stdin. Output is written to local files or stdout/stderr. That's it.

### No Regex Engine

Every detector is a hand-written, linear-time scanner. There is no regex compilation, no NFA/DFA construction, and no backtracking. This eliminates:

- **ReDoS (Regular Expression Denial of Service):** Crafted input cannot cause exponential runtime.
- **Regex compilation overhead:** Detectors are ready immediately.
- **Regex engine vulnerabilities:** There is no regex engine to have vulnerabilities.

Custom patterns use a bounded repetition matcher capped at 4096 iterations per quantifier, with no backtracking.

### Atomic File Writes

When writing output files (including `--in-place`), `redacted` uses atomic write semantics:

1. Write content to a temporary file (`.redact_tmp_<PID>_<filename>`) in the same directory as the target.
2. Call `fsync` to flush to disk.
3. Rename the temp file over the target (atomic on POSIX filesystems).

If the process crashes or is killed at any point, the original file remains intact. There is no window where the target file is partially written.

On Unix, temporary files are created with mode `0600` (owner read/write only). Original file permissions are preserved after the rename.

### Binary File Safety

By default, binary files are detected and skipped. Binary detection samples the first 8192 bytes and checks for:

- Null bytes (immediate binary classification).
- High ratio (>30%) of non-text control characters.

This prevents the tool from attempting to parse and potentially corrupting binary files.

### Symlink Traversal Protection

When following symlinks (`--follow-symlinks`), every resolved target is checked against the root directory. Symlinks that resolve outside the root are rejected with a clear message. This prevents path traversal attacks where a symlink could point to sensitive files outside the intended scan scope.

By default, symlinks are **not** followed at all.

### File Size Limits

Files exceeding `--max-file-size` (default 25 MiB) are skipped. This prevents:

- Memory exhaustion from processing extremely large files.
- Long processing times on files that are unlikely to contain typical secrets/PII patterns.

### Report Masking

JSON reports (from `--report-json` or `--format json`) include a `masked_sample` field that never contains the full matched value. Only the first few characters are visible, followed by `***`. This means:

- Reports can be stored, transmitted, or reviewed without leaking the secrets they describe.
- The masked sample provides enough context to identify the finding without exposing the full value.

### Hidden File Exclusion

By default, hidden files and directories (names starting with `.`) are excluded from directory traversal. This prevents accidentally processing `.git`, `.env`, `.ssh`, and similar sensitive directories unless explicitly requested with `--include-hidden`.

---

## What Is NOT Guaranteed

### Completeness of Detection

`redacted` is **not** a guarantee that all secrets or PII have been found. It detects known patterns with known structures. It will miss:

- Secrets in formats it doesn't have a detector for.
- Obfuscated or encoded secrets (base64-wrapped, encrypted, hex-encoded).
- Secrets split across multiple lines (except private key blocks).
- Natural-language PII that doesn't match structured patterns (e.g., "My name is John Doe").
- Secrets in binary files (skipped by default).
- Passwords that aren't in an assignment pattern (e.g., just the word "hunter2" on its own).

### Zero False Positives

Some detectors (particularly `GENERIC_SECRET`, `API_KEY`, and `PHONE`) may produce false positives. The tool includes heuristics to reduce them (e.g., rejecting "secretary" for the `GENERIC_SECRET` detector, rejecting IP-like sequences for `PHONE`), but false positives are possible.

Use `--allow-pattern` and `--deny-pattern` to tune detection for your use case.

### Cryptographic Erasure

Redacted content is replaced with marker strings in memory and written to new files. `redacted` does not:

- Securely wipe the original file's disk blocks.
- Overwrite freed memory.
- Provide any guarantees about data remanence on storage media.

If cryptographic erasure is required, use dedicated secure-deletion tools on the original files after redaction.

### Thread Safety of File Operations

Directory mode processes files sequentially in the current implementation. The `--threads` flag is accepted but threading is reserved for future implementation.

---

## Security-Relevant Defaults

| Setting | Default | Why |
|---------|---------|-----|
| Binary mode | `skip` | Prevents corrupting binary files and avoids processing non-text data |
| Hidden files | Excluded | Avoids accidental processing of `.git`, `.env`, `.ssh` |
| Symlinks | Not followed | Prevents path traversal via crafted symlinks |
| Max file size | 25 MiB | Prevents memory exhaustion |
| Max directory depth | 256 | Prevents stack overflow from deeply nested or circular directory structures |
| Max repetitions (custom patterns) | 4096 | Prevents DoS via crafted custom patterns |
| Max JWT scan | 4096 chars | Bounds scan window for JWT detection |
| Max URL scan | 2048 chars | Bounds scan window for database URL and bearer token detection |
