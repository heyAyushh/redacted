# Testing

This document covers how to run the test suite, the test categories, and how to add new tests.

---

## Running Tests

### All Tests

```bash
cargo test
```

This runs both unit tests (inline in source files) and integration tests (in `tests/`).

### Unit Tests Only

```bash
cargo test --lib
```

### Integration Tests Only

```bash
cargo test --test integration
```

### A Specific Test

```bash
cargo test test_name
```

For example:

```bash
cargo test detect_email
cargo test file_in_place
cargo test luhn_valid
```

### With Output

To see `println!` / `eprintln!` output from passing tests:

```bash
cargo test -- --nocapture
```

### Release Mode

To test with optimizations (useful for performance-related checks):

```bash
cargo test --release
```

---

## Test Categories

### Unit Tests

Unit tests are defined in `#[cfg(test)] mod tests` blocks at the bottom of each source file. They test individual functions and types in isolation.

| File | What's Tested |
|------|---------------|
| `src/cli.rs` | Argument parsing: flags, values, defaults, error cases |
| `src/config.rs` | TOML parsing, config merging, defaults |
| `src/detector/mod.rs` | Masked sample generation, finding merging, registry allow/deny |
| `src/detector/secrets.rs` | Each secret detector individually: AWS keys, Bearer tokens, JWTs, private keys, API keys, database URLs, passwords, webhook secrets, Slack tokens, GitHub tokens, Stripe keys, generic secrets |
| `src/detector/pii.rs` | Each PII detector individually: emails, phones, IPv4, IPv6, credit cards, SSNs. Includes Luhn validation tests |
| `src/detector/custom.rs` | Custom pattern compilation, literal matching, character classes, quantifiers, negated classes, bounded repetition, invalid pattern handling |
| `src/redact.rs` | Redaction application: no findings, single, multiple, custom replacement, overlapping findings |
| `src/io_safe.rs` | Binary detection, atomic file writes, file size limits |
| `src/traverse.rs` | Directory traversal: hidden file skipping, hidden file inclusion, relative path preservation |
| `src/report.rs` | JSON escaping, line number calculation, summary aggregation, JSON report generation |
| `src/errors.rs` | Error display formatting, exit code assignment, I/O error conversion |

### Integration Tests

Integration tests are in `tests/integration.rs`. They invoke the compiled `redact` binary as a subprocess and verify end-to-end behavior.

| Test Group | Tests |
|------------|-------|
| **Help & version** | `help_flag`, `version_flag` |
| **Text mode** | `text_redacts_email`, `text_redacts_phone`, `text_redacts_ipv4`, `text_redacts_aws_key`, `text_redacts_jwt`, `text_redacts_stripe_key`, `text_redacts_github_token`, `text_redacts_database_url`, `text_redacts_credit_card`, `text_redacts_ssn`, `text_clean_no_findings`, `text_custom_replacement` |
| **Stdin mode** | `stdin_redacts_email`, `stdin_redacts_multiple` |
| **File mode** | `file_input_to_stdout`, `file_input_to_output`, `file_in_place` |
| **Directory mode** | `directory_to_output`, `directory_preserves_structure`, `directory_requires_output`, `directory_dry_run_no_output_required` |
| **Flags & modes** | `fail_on_find_exits_3`, `fail_on_find_exits_0_no_findings`, `dry_run_does_not_redact_text`, `summary_flag`, `report_json`, `format_json`, `custom_pattern`, `allow_pattern_filters`, `deny_pattern_filters` |
| **Error handling** | `missing_input_file`, `no_input_no_pipe`, `unknown_flag_error` |
| **Edge cases** | `empty_text`, `unicode_text`, `long_line_no_crash`, `multiple_secrets_same_line`, `binary_file_skipped`, `private_key_block`, `bearer_token`, `password_assignment`, `reports_never_leak_full_secrets` |
| **Config file** | `config_file_custom_pattern` |
| **Exit codes** | `exit_code_0_success`, `exit_code_3_findings_with_fail` |

---

## Adding New Tests

### Adding a Unit Test

Unit tests go in the `#[cfg(test)] mod tests` block at the bottom of the relevant source file.

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn my_new_test() {
        // Arrange
        let input = "test input";

        // Act
        let result = some_function(input);

        // Assert
        assert_eq!(result, "expected output");
    }
}
```

#### Conventions

- Test names should describe the behavior being verified: `detect_email`, `no_false_positive_secretary`, `luhn_valid`.
- Use `assert_eq!` for value comparisons and `assert!` for boolean conditions.
- Include a descriptive message in assertions when the failure reason might be unclear: `assert_eq!(findings.len(), 2, "Expected 2 findings, got: {:?}", findings)`.
- Clean up any temp files/directories created during tests.

### Adding an Integration Test

Integration tests go in `tests/integration.rs`. They use helper functions to run the binary:

```rust
#[test]
fn my_integration_test() {
    let (stdout, stderr, code) = run(&["redact", "--text", "test input"]);
    assert_eq!(code, 0);
    assert!(stdout.contains("expected output"));
}
```

#### Available Helpers

| Helper | Signature | Description |
|--------|-----------|-------------|
| `run` | `fn run(args: &[&str]) -> (String, String, i32)` | Run the binary with arguments; returns (stdout, stderr, exit code) |
| `run_with_stdin` | `fn run_with_stdin(args: &[&str], stdin: &str) -> (String, String, i32)` | Run with piped stdin |
| `temp_dir` | `fn temp_dir(name: &str) -> PathBuf` | Create a temporary directory for test files (auto-cleaned) |

#### Example: Testing a New Detector

```rust
#[test]
fn text_redacts_new_secret_type() {
    let (stdout, _, code) = run(&[
        "redact",
        "--text",
        "my_new_secret_value_here",
    ]);
    assert_eq!(code, 0);
    assert!(stdout.contains("[REDACTED:NEW_SECRET]"));
    assert!(!stdout.contains("my_new_secret_value_here"));
}
```

#### Example: Testing File Processing

```rust
#[test]
fn new_file_mode_test() {
    let dir = temp_dir("new_test");
    let input = dir.join("input.txt");
    let output = dir.join("output.txt");
    fs::write(&input, "content with secret").unwrap();

    let (_, _, code) = run(&[
        "redact",
        "--input", input.to_str().unwrap(),
        "--output", output.to_str().unwrap(),
    ]);
    assert_eq!(code, 0);

    let result = fs::read_to_string(&output).unwrap();
    assert!(result.contains("[REDACTED:"));
    let _ = fs::remove_dir_all(&dir);
}
```

### Adding a New Detector

When adding a new built-in detector:

1. **Implement the detector** in `src/detector/secrets.rs` (for secrets) or `src/detector/pii.rs` (for PII).
2. **Add unit tests** in the same file's `mod tests` block covering:
   - At least one positive detection case.
   - At least one negative case (no false positive for similar-looking input).
   - Edge cases (empty input, boundary conditions).
3. **Register the detector** in `DetectorRegistry::build_default()` in `src/detector/mod.rs`.
4. **Add integration tests** in `tests/integration.rs` covering:
   - Detection via `--text` mode.
   - Verification that the matched content is redacted (not present in output).
5. **Run the full suite:** `cargo test`

---

## Linting and Formatting

Run these before committing:

```bash
# Check formatting
cargo fmt --check

# Fix formatting
cargo fmt

# Run clippy lints
cargo clippy
```

---

## Test Design Principles

1. **No external test dependencies.** Tests use only `std` and the test framework. No test harness crates.
2. **Temp files are cleaned up.** Tests that create files use `temp_dir()` and remove their directories afterwards.
3. **Integration tests use the real binary.** They invoke the compiled binary as a subprocess, testing the full CLI path including argument parsing, config loading, detection, redaction, and output.
4. **Reports never leak secrets.** The `reports_never_leak_full_secrets` integration test verifies that JSON reports do not contain full secret values.
