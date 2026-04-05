# Skill: redacted CLI — Secret & PII Redaction Tool

## When to use this skill

Use this skill whenever you are working on the `redacted` binary crate — adding detectors, fixing bugs, modifying CLI behaviour, changing output formats, or reviewing code in this repository.

---

## 1. Purpose

`redacted` is a production-grade, zero-dependency Rust CLI that scans text and files for secrets and personally identifiable information (PII), replaces matches with safe placeholders, and optionally produces structured JSON reports. It is designed for CI pipelines, log sanitisation, and pre-publish checks.

---

## 2. Security-First Development Rules

These rules are non-negotiable. Every change must satisfy all of them.

| # | Rule |
|---|------|
| S1 | **Never print, log, or include a raw secret value.** Use `Finding::masked_sample()` (shows at most the first 4 characters plus `***`). |
| S2 | **Never add external crates.** The project has zero dependencies on purpose — fewer supply-chain vectors, full auditability. Use `std` only. |
| S3 | **No `unsafe` blocks.** Every function must be safe Rust. |
| S4 | **All public functions return `Result`.** Panics (`unwrap`, `expect`) are forbidden outside tests. |
| S5 | **Atomic writes only.** All file output goes through `io_safe::atomic_write` (temp file → rename) so partial writes never corrupt data. |
| S6 | **Temp files are `0600`.** See `io_safe::atomic_write`. |
| S7 | **Symlinks must not escape the root.** `traverse.rs` canonicalises symlink targets and rejects any that resolve outside the input root. |
| S8 | **Binary files are skipped by default.** `BinaryMode::Skip` is the default; detection uses null-byte and non-text-byte heuristics in `io_safe::is_binary`. |
| S9 | **Error messages must never contain secret values.** Paths and byte counts are fine; matched content is not. |
| S10 | **Custom patterns are bounded.** The mini-regex engine in `detector/custom.rs` caps repetitions at 4096 and uses non-backtracking greedy matching to prevent ReDoS. |

---

## 3. Code Structure

```
src/
├── main.rs            Entry point — run() → process_text / process_single_file / process_directory
├── lib.rs             Re-exports all modules (for integration tests / library use)
├── cli.rs             Hand-rolled arg parser, CliArgs struct, help text, defaults
├── config.rs          Config struct, TOML config file loader, CLI → Config merge
├── detector/
│   ├── mod.rs         Finding, Confidence, Detector trait, DetectorRegistry, overlap merging
│   ├── secrets.rs     Built-in secret detectors (AWS, JWT, Bearer, Stripe, GitHub, Slack, etc.)
│   ├── pii.rs         Built-in PII detectors (Email, Phone, IPv4/IPv6 scanners → unified `IP` / `[REDACTED:IP]`, Path, CreditCard, SSN)
│   └── custom.rs      User-supplied patterns via --pattern; mini-regex compiler + matcher
├── redact.rs          apply_redactions() — replaces finding spans with placeholders
├── io_safe.rs         Atomic writes, binary detection, stdin piping, file reads with size limits
├── traverse.rs        Recursive directory walker with symlink, hidden-file, and depth guards
├── report.rs          Summary, FindingReport, JSON report writer, line-number calculation
└── errors.rs          RedactError enum, exit codes (0/1/2/3), Result type alias
```

### Integration tests

```
tests/
├── integration.rs     End-to-end tests against the compiled binary
└── fixtures/          (reserved for test fixture files)
```

---

## 4. Safe Defaults

These defaults are baked into `CliArgs::default()` and must not be weakened:

| Setting | Default | Why |
|---------|---------|-----|
| `recursive` | `true` | Processes all files in subdirectories |
| `follow_symlinks` | `false` | Prevents traversal attacks |
| `include_hidden` | `false` | Avoids scanning `.git`, `.env` etc. unintentionally |
| `binary` | `Skip` | Avoids corrupting binary files |
| `max_file_size` | 25 MiB | Prevents OOM on huge files |
| `max_depth` | 256 | Prevents infinite recursion from symlink loops |
| Replacement | `[REDACTED:<TYPE>]` | Makes it clear what was removed and why |

---

## 5. How to Add a New Detector

### 5a. Adding a built-in secret detector

1. Open `src/detector/secrets.rs`.
2. Create a new unit struct (e.g. `pub struct MyServiceKeyDetector;`).
3. Implement the `Detector` trait — `name()` returns a unique `&'static str` identifier, `category()` returns `"secret"`, `detect()` scans text and returns `Vec<Finding>`.
4. Use **linear-time, purpose-built scanning** — no regex, no backtracking. See existing detectors for patterns.
5. Add unit tests in the `#[cfg(test)] mod tests` block at the bottom of the file.
6. **Register the detector** in `DetectorRegistry::build_default()` in `src/detector/mod.rs` — add a `Box::new(secrets::MyServiceKeyDetector)` entry in the `all_builtins` vec, inside the `// Secrets` section.

### 5b. Adding a built-in PII detector

Same steps as above, but in `src/detector/pii.rs` with `category()` returning `"pii"`. Register in the `// PII` section of `build_default()`.

### 5c. Checklist for every new detector

- [ ] `name()` is SCREAMING_SNAKE_CASE, unique across all detectors
- [ ] `category()` is `"secret"`, `"pii"`, or `"custom"`
- [ ] `detect()` is O(n) — no nested loops over the full text, no backtracking
- [ ] Scan windows are bounded (`scan_while` with a `max_len`, or equivalent)
- [ ] At least one positive-match test and one false-positive-rejection test
- [ ] Finding spans are byte-accurate (`start..end` indexes into the input `&str`)
- [ ] `confidence` is set appropriately (High for prefix-based, Medium for heuristic)
- [ ] Registered in `build_default()` so allow/deny filtering works
- [ ] Integration test added in `tests/integration.rs`

---

## 6. Testing Requirements

Run all three before every commit:

```bash
cargo test            # Unit + integration tests
cargo clippy          # Lint — must pass with zero warnings
cargo fmt --check     # Format check — must pass
```

### Test conventions

- **Unit tests** live in `#[cfg(test)] mod tests` at the bottom of each source file.
- **Integration tests** live in `tests/integration.rs` and exercise the compiled binary via `std::process::Command`.
- Integration tests use `temp_dir()` for file I/O and clean up after themselves.
- Every detector must have at least one positive-detection test and one false-positive test.
- The test `reports_never_leak_full_secrets` verifies that JSON reports contain only masked samples.

---

## 7. No Secret Leakage — Detailed Rules

| Context | What to show | What to hide |
|---------|-------------|-------------|
| `--report-json` output | `masked_sample` (first ≤4 chars + `***`) | Full matched text |
| `--summary` stderr | Counts, detector names, file paths | Any matched content |
| Error messages | File paths, byte counts, detector names | Matched text, secret values |
| Debug logging | Not implemented (by design) | N/A |
| `--format json` | Report metadata only | Full matched text |

`Finding::masked_sample()` is the **only** approved way to represent matched content in reports. If you need to change reporting, route through this method.

---

## 8. File / Folder Traversal Constraints

All traversal logic lives in `src/traverse.rs`.

- **Symlink targets are canonicalised** and rejected if they resolve outside the input root.
- **Hidden files/dirs** (name starts with `.`) are skipped unless `--include-hidden` is set.
- **Depth is capped** at `max_depth` (default 256).
- **File size is checked** before reading; files over `max_file_size` are skipped.
- **Binary detection** happens after reading but before scanning; binary files are skipped by default.
- Results are sorted by path for deterministic output.

---

## 9. Documentation Expectations

- Every public struct, enum, trait, and function has a `///` doc comment.
- Detector structs document what pattern they match and at what confidence level.
- Non-obvious helper functions (e.g. `scan_key_value_pair`, `luhn_check`) have inline comments explaining the algorithm.
- CLI `--help` text is the canonical reference for all flags and is maintained in `cli::print_help()`.

---

## 10. Common Tasks — Examples

### Redact a single string

```bash
cargo run -- --text "email me at user@example.com"
# Output: email me at [REDACTED:EMAIL]
```

### Pipe from stdin

```bash
echo "token=sk_live_abc123def456" | cargo run --
```

### Scan a directory, write redacted copies

```bash
cargo run -- --input logs/ --output cleaned/ --summary
```

### Dry-run with fail-on-find (CI gate)

```bash
cargo run -- --input . --fail-on-find --dry-run
# Exits 3 if any secrets/PII found; exits 0 if clean.
```

### Use a config file

```bash
cargo run -- --input data/ --output clean/ --config redact.toml
```

### Add a one-off custom pattern

```bash
cargo run -- --text "code PROJ-9999" --pattern "PROJECT=PROJ-\\d+"
```

---

## 11. Repository Conventions

| Convention | Detail |
|-----------|--------|
| **Zero external dependencies** | `[dependencies]` in `Cargo.toml` is empty. All logic uses `std`. |
| **No `unsafe`** | Safe Rust only. |
| **`Result`-based errors** | All fallible functions return `errors::Result<T>`. No panics outside tests. |
| **Purpose-built scanners** | Each detector is a hand-written O(n) scanner. No regex crate, no PCRE. |
| **Atomic file writes** | `io_safe::atomic_write` — temp file with `0600` perms → `rename`. |
| **Hand-rolled JSON** | `report::write_json_report` writes JSON without serde. Strings are escaped via `json_escape`. |
| **Hand-rolled TOML** | `config::parse_simple_toml` supports flat `key = value` and `[section]` headers only. |
| **Hand-rolled arg parser** | `cli::parse_args_from` — no clap, no structopt. |
| **Exit codes** | `0` success, `1` operational error, `2` usage error, `3` findings detected (with `--fail-on-find`). |

---

## 12. Crate Selection Guidance

**Do not add crates.** This is a deliberate security decision.

If you are tempted to reach for a dependency, here is how the codebase solves common needs:

| Need | Solution in this codebase |
|------|--------------------------|
| Regex matching | Purpose-built byte scanners in `secrets.rs` / `pii.rs`; mini-regex in `custom.rs` |
| Argument parsing | Hand-rolled in `cli.rs` |
| JSON serialisation | Hand-rolled in `report.rs` |
| TOML parsing | `config::parse_simple_toml` |
| File walking | `traverse::collect_files` using `std::fs::read_dir` |
| Atomic file I/O | `io_safe::atomic_write` |
| Error handling | `errors::RedactError` enum + `Result<T>` alias |
| Checksums (Luhn) | `pii::luhn_check` |

---

## 13. Release Checklist

1. Update `version` in `Cargo.toml`.
2. Run the full test suite: `cargo test`.
3. Run lints: `cargo clippy`.
4. Run format check: `cargo fmt --check`.
5. Build the release binary: `cargo build --release`.
6. Verify `--help` and `--version` output the correct version.
7. Run a quick smoke test: `echo "user@example.com" | ./target/release/redacted`.
8. Confirm the binary has zero dynamic dependencies beyond libc: `ldd target/release/redacted`.
9. Tag the release: `git tag -a v<VERSION> -m "Release v<VERSION>"`.
10. Update the README if any CLI flags or detectors changed.
