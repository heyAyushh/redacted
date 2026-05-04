# Skill: redacted CLI — Secret & PII Redaction Tool

## When to use this skill

Use this skill whenever you are working on the `redacted` binary crate — adding detectors, fixing bugs, modifying CLI behaviour, changing output formats, or reviewing code in this repository.

---

## 1. Purpose

`redacted` is a production-grade, zero-dependency Rust CLI that scans text and files for secrets and personally identifiable information (PII), replaces matches with safe placeholders, and optionally produces structured JSON reports. It is designed for CI pipelines, log sanitisation, and pre-publish checks.

The default scan path is Rust-only, offline, dependency-free, and does not download models. Optional privacy-filter providers, external detectors, and document adapters are explicit external runtime boundaries. They are installed separately, verified separately, and only run when their feature flag or persisted default is enabled.

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
| S11 | **Scans never install or download providers/adapters/detectors.** Downloads only happen through explicit setup commands such as `redacted provider install ...`, `redacted provider enable ...`, or document-adapter equivalents. External detectors bind to local executables and must not download during scans. |
| S12 | **Provider, external detector, and document runners are lower-trust external boundaries.** Validate paths, verify artifacts or executables by size/SHA-256 where applicable, keep stderr hidden by default, and never let external runners own final redaction output. |

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
├── provider.rs        Optional privacy-filter provider catalog, install/verify/use, runner session ABI
├── external_detector.rs Optional external detector engines such as TruffleHog
├── document.rs        Optional document-adapter catalog, install/verify/use, document extraction
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
| Privacy filter | `false` | Optional provider pass is off unless `--privacy-filter` is passed |
| External detectors | `false` | Optional external detector engines are off unless `--detectors` is passed or `redacted detector default on` is set |
| Document adapter | `false` | Optional document extraction is off unless `--document-adapter` is passed |

Provider, external-detector, and document-adapter setup state is persistent. External detectors can also have a persistent default, but only after explicit `redacted detector default on`.

---

## 5. How to Add a New Detector

Use `detector` as the contributor-facing word for new native scan logic. Reserve
`bridge` / `adapter` for rare integrations that wrap an external engine or tool
instead of participating directly in the in-process `Detector` pipeline.

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
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --locked
```

For release or CI workflow changes, also run:

```bash
cargo build --release --locked
git diff --check
```

The regular test suite uses fake provider/document runners. It must not download OPF, MLX, model artifacts, or document adapter bundles.

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

### Install as a user

```bash
cargo install --git https://github.com/heyAyushh/redacted --locked
redacted --version
```

This installs the Rust CLI only. It must not download optional provider models.

### Redact a single string

```bash
redacted --text "email me at user@example.com"
# Output: email me at [REDACTED:EMAIL]
```

### Pipe from stdin

```bash
echo "password=correct-horse-battery-staple" | redacted
```

### Scan a directory, write redacted copies

```bash
redacted --input logs/ --output cleaned/ --summary
```

### Dry-run with fail-on-find (CI gate)

```bash
redacted --input . --fail-on-find --dry-run
# Exits 3 if any secrets/PII found; exits 0 if clean.
```

### Use a config file

```bash
redacted --input data/ --output clean/ --config redact.toml
```

### Add a one-off custom pattern

```bash
redacted --text "code PROJ-9999" --pattern "PROJECT=PROJ-\\d+"
```

### Enable the supported OpenAI privacy-filter provider

```bash
redacted provider enable openai
redacted --privacy-filter --input logs/
```

`openai` resolves to the pinned exact target `openai/privacy-filter-v1`. Setup may download and verify the external provider bundle. Later scans with `--privacy-filter` must not download anything.

### Enable the experimental MLX privacy-filter provider

```bash
redacted provider enable mlx
redacted --privacy-filter --text "Jane Doe emailed jane@example.com"
```

`mlx` resolves to `openai/privacy-filter-v1-mlx` and uses the pinned MLX-converted OpenAI Privacy Filter model. It is experimental and still follows the same span-only provider contract.

### Use the document adapter

```bash
redacted document enable pdf
redacted --input report.pdf --document-adapter
```

Firecrawl PDF Inspector is available as a separate adapter:

```bash
redacted document enable firecrawl-pdf
redacted --input report.pdf --document-adapter
```

Document adapters extract text first. The core detector, merge, policy, redaction, and reporting pipeline still belongs to `redacted`.
The `pdf` alias is the short user-facing selector for the PDF document type;
exact targets such as `poppler/pdftotext-v1` and
`firecrawl/pdf-inspector-v1` name the adapter implementation.

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
| Checksums (SHA-256) | Hand-rolled SHA-256 in `provider.rs`; keep boundary vectors covered by tests |

## 13. Optional Provider Architecture

Use `provider` as the public CLI noun and `adapter` as the internal implementation noun.

Supported targets:

| Alias | Exact target | Status |
|-------|--------------|--------|
| `openai` | `openai/privacy-filter-v1` | Supported |
| `mlx` | `openai/privacy-filter-v1-mlx` | Experimental |

Provider commands:

```bash
redacted provider enable <provider-or-target>
redacted provider install <provider-or-target>
redacted provider use <provider-or-target>
redacted provider current
redacted provider list
redacted provider verify [<provider-or-target> | --all]
redacted provider disable
```

Rules:

- `enable` is the human-friendly path: install if missing, verify, then activate.
- `install` downloads and verifies without activating.
- `use` switches only to an installed, verified target.
- Aliases must resolve to pinned exact targets and print the resolved target.
- `--privacy-filter` fails fast if no active provider is configured.
- Provider catalog entries must declare extension license metadata.
- Provider responses contain labels and byte spans only. They must not contain raw matched text or redacted text.
- Core maps provider labels into canonical detector names and applies existing policy/report/redaction logic once after merging findings.
- Generative runtimes are not privacy-filter providers unless they run a real detector with verified span output.

Provider runner request:

```json
{"schema_version":1,"request_id":"...","text":"..."}
```

Provider runner response:

```json
{"schema_version":1,"request_id":"...","target":"openai/privacy-filter-v1","spans":[{"label":"private_email","start":40,"end":61}]}
```

## 14. Optional Document Adapter Architecture

Document adapter commands mirror provider commands:

```bash
redacted document enable <adapter-or-target>
redacted document install <adapter-or-target>
redacted document use <adapter-or-target>
redacted document current
redacted document list
redacted document verify [<adapter-or-target> | --all]
redacted document disable
```

Rules:

- Scans with `--document-adapter` never install adapters.
- `--document-adapter` is valid only for file/directory input, not `--text` or stdin.
- In-place rewrite is blocked for document-adapter extracted files.
- Adapter runner paths must be validated as bundle-relative child paths.
- Adapter output is extracted text only; `redacted` still owns detection and redaction.
- Document adapter catalog entries must declare extension license metadata.
- Keep document-type aliases short. Use exact targets to distinguish swappable
  adapter implementations.

## 15. Optional External Detector Architecture

Use `detector` as the public CLI noun for external secret-scanner engines. Native
detectors still live in `src/detector/`; external detectors are adapters around
separate executables.

Supported targets:

| Alias | Exact target | Status |
|-------|--------------|--------|
| `trufflehog` | `trufflehog/secrets-v1` | Supported external engine |

Detector commands:

```bash
redacted detector install <detector-or-target>
redacted detector use <detector-or-target>
redacted detector current
redacted detector list
redacted detector verify [<detector-or-target> | --all]
redacted detector disable [<detector-or-target> | --all]
redacted detector default <on|off>
```

Rules:

- `install` must not download TruffleHog; it binds to a local executable in `PATH`.
- `use` adds an installed, verified target to the active set.
- `--detectors` runs native detectors plus all active external detectors for `--input` scans.
- `--no-detectors` disables external detectors for one scan.
- `redacted detector default on` makes active external detectors run by default for `--input` scans.
- TruffleHog must run with `--json --no-verification --no-update --no-color`.
- External detector errors must not include raw matched text.
- Core maps external detector results into normal `Finding` values and still owns policy/report/redaction logic.
- External detector catalog entries must declare extension license metadata.

## 16. Extension License Checklist

Core remains MIT. Optional extension entries must include:

- target
- kind: `provider`, `detector`, or `document`
- source URL
- license
- distribution: `external-binary`, `downloaded-artifact`, `vendored-source`, or `linked-library`
- bundled: `true` or `false`
- network default: `true` or `false`
- attribution/notice text

Rules:

- External binaries do not change the core license when they remain separate user-installed tools.
- Downloaded artifacts need pinned URLs, byte sizes, SHA-256 hashes, and a notice before install/use.
- Vendored source or linked libraries require explicit maintainer approval.
- Unknown-license extensions must stay disabled by default.
- Update `docs/extension-licenses.md`, README attribution, and tests whenever adding an extension.

---

## 17. Release Checklist

1. Update `version` in `Cargo.toml`.
2. Run the full test suite: `cargo test --locked`.
3. Run lints: `cargo clippy --all-targets --all-features -- -D warnings`.
4. Run format check: `cargo fmt --check`.
5. Build the release binary: `cargo build --release --locked`.
6. Verify `--help` and `--version` output the correct version.
7. Run a quick smoke test: `echo "user@example.com" | ./target/release/redacted`.
8. Confirm the binary has zero dynamic dependencies beyond libc: `ldd target/release/redacted`.
9. Tag the release: `git tag -a v<VERSION> -m "Release v<VERSION>"`.
10. Update the README if any CLI flags or detectors changed.
