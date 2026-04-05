use std::fs;
use std::path::PathBuf;
use std::process::Command;

fn binary_path() -> PathBuf {
    let mut path = std::env::current_exe().unwrap();
    path.pop(); // remove test binary name
    path.pop(); // remove 'deps'
    path.push("redact");
    path
}

fn run(args: &[&str]) -> (String, String, i32) {
    let output = Command::new(binary_path())
        .args(args)
        .output()
        .expect("Failed to execute binary");
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let code = output.status.code().unwrap_or(-1);
    (stdout, stderr, code)
}

fn run_with_stdin(args: &[&str], stdin: &str) -> (String, String, i32) {
    use std::io::Write;
    use std::process::Stdio;

    let mut child = Command::new(binary_path())
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to spawn");

    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(stdin.as_bytes())
        .unwrap();

    let output = child.wait_with_output().unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let code = output.status.code().unwrap_or(-1);
    (stdout, stderr, code)
}

fn temp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("redact_integ_{}", name));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

// === Help and Version ===

#[test]
fn help_flag() {
    let (_, stderr, code) = run(&["redact", "--help"]);
    assert_eq!(code, 0);
    assert!(stderr.contains("USAGE:"));
    assert!(stderr.contains("--input"));
    assert!(stderr.contains("EXAMPLES:"));
}

#[test]
fn version_flag() {
    let (_, stderr, code) = run(&["redact", "--version"]);
    assert_eq!(code, 0);
    assert!(stderr.contains("redact 0.1.0"));
}

// === Text Mode ===

#[test]
fn text_redacts_email() {
    let (stdout, _, code) = run(&["redact", "--text", "email me at user@example.com please"]);
    assert_eq!(code, 0);
    assert!(stdout.contains("[REDACTED:EMAIL]"));
    assert!(!stdout.contains("user@example.com"));
}

#[test]
fn text_redacts_phone() {
    let (stdout, _, code) = run(&["redact", "--text", "call +1-555-867-5309"]);
    assert_eq!(code, 0);
    assert!(stdout.contains("[REDACTED:PHONE]"));
}

#[test]
fn text_redacts_ipv4() {
    let (stdout, _, code) = run(&["redact", "--text", "server 192.168.1.100"]);
    assert_eq!(code, 0);
    assert!(stdout.contains("[REDACTED:IPV4]"));
    assert!(!stdout.contains("192.168.1.100"));
}

#[test]
fn text_redacts_aws_key() {
    let (stdout, _, code) = run(&["redact", "--text", "key=AKIAIOSFODNN7EXAMPLE"]);
    assert_eq!(code, 0);
    assert!(stdout.contains("[REDACTED:AWS_KEY]"));
}

#[test]
fn text_redacts_jwt() {
    let (stdout, _, code) = run(&[
        "redact",
        "--text",
        "token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
    ]);
    assert_eq!(code, 0);
    assert!(stdout.contains("[REDACTED:JWT]"));
}

#[test]
fn text_redacts_stripe_key() {
    let (stdout, _, code) = run(&["redact", "--text", "STRIPE_KEY=sk_live_abcdef1234567890"]);
    assert_eq!(code, 0);
    assert!(stdout.contains("[REDACTED:"));
    assert!(!stdout.contains("sk_live_abcdef1234567890"));
}

#[test]
fn text_redacts_github_token() {
    let (stdout, _, code) = run(&[
        "redact",
        "--text",
        "token: ghp_abcdefghijklmnop1234567890abcd",
    ]);
    assert_eq!(code, 0);
    assert!(stdout.contains("[REDACTED:GITHUB_TOKEN]"));
}

#[test]
fn text_redacts_database_url() {
    let (stdout, _, code) = run(&[
        "redact",
        "--text",
        "DATABASE_URL=postgres://admin:s3cret@db.host:5432/mydb",
    ]);
    assert_eq!(code, 0);
    assert!(stdout.contains("[REDACTED:"));
    assert!(!stdout.contains("s3cret"));
}

#[test]
fn text_redacts_credit_card() {
    let (stdout, _, code) = run(&["redact", "--text", "card: 4111 1111 1111 1111"]);
    assert_eq!(code, 0);
    assert!(stdout.contains("[REDACTED:CREDIT_CARD]"));
}

#[test]
fn text_redacts_ssn() {
    let (stdout, _, code) = run(&["redact", "--text", "ssn: 123-45-6789"]);
    assert_eq!(code, 0);
    assert!(stdout.contains("[REDACTED:SSN]"));
}

#[test]
fn text_clean_no_findings() {
    let (stdout, _, code) = run(&["redact", "--text", "this is clean text"]);
    assert_eq!(code, 0);
    assert_eq!(stdout, "this is clean text");
}

#[test]
fn text_custom_replacement() {
    let (stdout, _, code) = run(&[
        "redact",
        "--text",
        "email: user@example.com",
        "--replacement",
        "***",
    ]);
    assert_eq!(code, 0);
    assert!(stdout.contains("***"));
    assert!(!stdout.contains("[REDACTED"));
}

// === Stdin Mode ===

#[test]
fn stdin_redacts_email() {
    let (stdout, _, code) = run_with_stdin(&["redact"], "contact user@example.com");
    assert_eq!(code, 0);
    assert!(stdout.contains("[REDACTED:EMAIL]"));
}

#[test]
fn stdin_redacts_multiple() {
    let (stdout, _, code) = run_with_stdin(
        &["redact"],
        "email: user@example.com\nkey=AKIAIOSFODNN7EXAMPLE\n",
    );
    assert_eq!(code, 0);
    assert!(stdout.contains("[REDACTED:EMAIL]"));
    assert!(stdout.contains("[REDACTED:AWS_KEY]"));
}

// === File Mode ===

#[test]
fn file_input_to_stdout() {
    let dir = temp_dir("file_stdout");
    let input = dir.join("input.txt");
    fs::write(&input, "secret: user@example.com").unwrap();

    let (stdout, _, code) = run(&["redact", "--input", input.to_str().unwrap()]);
    assert_eq!(code, 0);
    assert!(stdout.contains("[REDACTED:EMAIL]"));
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn file_input_to_output() {
    let dir = temp_dir("file_output");
    let input = dir.join("input.txt");
    let output = dir.join("output.txt");
    fs::write(&input, "email: user@example.com").unwrap();

    let (_, _, code) = run(&[
        "redact",
        "--input",
        input.to_str().unwrap(),
        "--output",
        output.to_str().unwrap(),
    ]);
    assert_eq!(code, 0);
    let content = fs::read_to_string(&output).unwrap();
    assert!(content.contains("[REDACTED:EMAIL]"));
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn file_in_place() {
    let dir = temp_dir("file_inplace");
    let input = dir.join("input.txt");
    fs::write(&input, "email: user@example.com").unwrap();

    let (_, _, code) = run(&["redact", "--input", input.to_str().unwrap(), "--in-place"]);
    assert_eq!(code, 0);
    let content = fs::read_to_string(&input).unwrap();
    assert!(content.contains("[REDACTED:EMAIL]"));
    assert!(!content.contains("user@example.com"));
    let _ = fs::remove_dir_all(&dir);
}

// === Directory Mode ===

#[test]
fn directory_to_output() {
    let dir = temp_dir("dir_output");
    let input_dir = dir.join("input");
    let output_dir = dir.join("output");
    fs::create_dir_all(input_dir.join("sub")).unwrap();
    fs::write(input_dir.join("a.txt"), "email: user@example.com").unwrap();
    fs::write(
        input_dir.join("sub").join("b.txt"),
        "key=AKIAIOSFODNN7EXAMPLE",
    )
    .unwrap();

    let (_, stderr, code) = run(&[
        "redact",
        "--input",
        input_dir.to_str().unwrap(),
        "--output",
        output_dir.to_str().unwrap(),
    ]);
    assert_eq!(code, 0, "stderr: {}", stderr);

    let a_content = fs::read_to_string(output_dir.join("a.txt")).unwrap();
    assert!(a_content.contains("[REDACTED:EMAIL]"));

    let b_content = fs::read_to_string(output_dir.join("sub").join("b.txt")).unwrap();
    assert!(b_content.contains("[REDACTED:AWS_KEY]"));
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn directory_preserves_structure() {
    let dir = temp_dir("dir_structure");
    let input_dir = dir.join("input");
    let output_dir = dir.join("output");
    fs::create_dir_all(input_dir.join("a").join("b")).unwrap();
    fs::write(input_dir.join("a").join("b").join("deep.txt"), "clean text").unwrap();

    let (_, _, code) = run(&[
        "redact",
        "--input",
        input_dir.to_str().unwrap(),
        "--output",
        output_dir.to_str().unwrap(),
    ]);
    assert_eq!(code, 0);
    assert!(output_dir.join("a").join("b").join("deep.txt").exists());
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn directory_requires_output() {
    let dir = temp_dir("dir_no_output");
    let input_dir = dir.join("input");
    fs::create_dir_all(&input_dir).unwrap();
    fs::write(input_dir.join("a.txt"), "test").unwrap();

    let (_, _, code) = run(&["redact", "--input", input_dir.to_str().unwrap()]);
    assert_eq!(code, 2); // Usage error
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn directory_dry_run_no_output_required() {
    let dir = temp_dir("dir_dryrun");
    let input_dir = dir.join("input");
    fs::create_dir_all(&input_dir).unwrap();
    fs::write(input_dir.join("a.txt"), "email: user@example.com").unwrap();

    let (_, stderr, code) = run(&[
        "redact",
        "--input",
        input_dir.to_str().unwrap(),
        "--dry-run",
    ]);
    assert_eq!(code, 0);
    assert!(stderr.contains("Summary"));
    let _ = fs::remove_dir_all(&dir);
}

// === Flags and Modes ===

#[test]
fn fail_on_find_exits_3() {
    let (_, _, code) = run(&[
        "redact",
        "--text",
        "email: user@example.com",
        "--fail-on-find",
    ]);
    assert_eq!(code, 3);
}

#[test]
fn fail_on_find_exits_0_no_findings() {
    let (_, _, code) = run(&["redact", "--text", "clean text", "--fail-on-find"]);
    assert_eq!(code, 0);
}

#[test]
fn dry_run_does_not_redact_text() {
    let (stdout, stderr, code) = run(&["redact", "--text", "email: user@example.com", "--dry-run"]);
    assert_eq!(code, 0);
    assert!(stdout.contains("user@example.com")); // Not redacted
    assert!(stderr.contains("Summary"));
}

#[test]
fn summary_flag() {
    let (_, stderr, code) = run(&["redact", "--text", "user@example.com", "--summary"]);
    assert_eq!(code, 0);
    assert!(stderr.contains("Summary"));
    assert!(stderr.contains("Total findings"));
}

#[test]
fn report_json() {
    let (stdout, stderr, code) = run(&[
        "redact",
        "--text",
        "email: user@example.com",
        "--report-json",
    ]);
    assert_eq!(code, 0);
    assert!(stdout.contains("[REDACTED:EMAIL]"));
    assert!(stderr.contains("\"files_processed\""));
    assert!(stderr.contains("\"detector\""));
}

#[test]
fn format_json() {
    let (stdout, _, code) = run(&[
        "redact",
        "--text",
        "email: user@example.com",
        "--format",
        "json",
    ]);
    assert_eq!(code, 0);
    assert!(stdout.contains("\"summary\""));
    assert!(stdout.contains("\"files\""));
}

#[test]
fn custom_pattern() {
    let (stdout, _, code) = run(&[
        "redact",
        "--text",
        "code: PROJ-1234",
        "--pattern",
        "PROJECT=PROJ-\\d+",
    ]);
    assert_eq!(code, 0);
    assert!(stdout.contains("[REDACTED:PROJECT]"));
}

#[test]
fn allow_pattern_filters() {
    let (stdout, _, code) = run(&[
        "redact",
        "--text",
        "email: user@example.com and key=AKIAIOSFODNN7EXAMPLE",
        "--allow-pattern",
        "EMAIL",
    ]);
    assert_eq!(code, 0);
    assert!(stdout.contains("[REDACTED:EMAIL]"));
    assert!(stdout.contains("AKIAIOSFODNN7EXAMPLE")); // AWS key not redacted
}

#[test]
fn deny_pattern_filters() {
    let (stdout, _, code) = run(&[
        "redact",
        "--text",
        "email: user@example.com",
        "--deny-pattern",
        "EMAIL",
    ]);
    assert_eq!(code, 0);
    assert!(stdout.contains("user@example.com")); // Not redacted
}

// === Error Handling ===

#[test]
fn missing_input_file() {
    let (_, _, code) = run(&["redact", "--input", "/nonexistent/path"]);
    assert_eq!(code, 2);
}

#[test]
fn no_input_no_pipe() {
    let (_, stderr, code) = run(&["redact"]);
    assert!(
        code == 2 || code == 0,
        "code was {}, stderr: {}",
        code,
        stderr
    );
}

#[test]
fn unknown_flag_error() {
    let (_, _, code) = run(&["redact", "--banana"]);
    assert_eq!(code, 2);
}

// === Adversarial and Edge Cases ===

#[test]
fn empty_text() {
    let (stdout, _, code) = run(&["redact", "--text", ""]);
    assert_eq!(code, 0);
    assert_eq!(stdout, "");
}

#[test]
fn unicode_text() {
    let (stdout, _, code) = run(&["redact", "--text", "日本語テスト user@example.com résumé"]);
    assert_eq!(code, 0);
    assert!(stdout.contains("[REDACTED:EMAIL]"));
    assert!(stdout.contains("日本語テスト"));
    assert!(stdout.contains("résumé"));
}

#[test]
fn long_line_no_crash() {
    let long_line = "a".repeat(100_000);
    let (stdout, _, code) = run(&["redact", "--text", &long_line]);
    assert_eq!(code, 0);
    assert_eq!(stdout.len(), 100_000);
}

#[test]
fn multiple_secrets_same_line() {
    let (stdout, _, code) = run(&[
        "redact",
        "--text",
        "user@a.com and user@b.com and 192.168.1.1",
    ]);
    assert_eq!(code, 0);
    // Should have multiple redactions
    let redact_count = stdout.matches("[REDACTED:").count();
    assert!(
        redact_count >= 3,
        "Expected >= 3 redactions, got {}",
        redact_count
    );
}

#[test]
fn binary_file_skipped() {
    let dir = temp_dir("binary_skip");
    let binary_file = dir.join("binary.dat");
    let mut data = vec![0u8; 1000];
    data[0] = 0x00; // null byte
    data[1] = 0xFF;
    fs::write(&binary_file, &data).unwrap();

    let (_, stderr, code) = run(&["redact", "--input", binary_file.to_str().unwrap()]);
    // Should skip (or error gracefully) for binary
    assert!(code == 0 || code == 1, "code: {}, stderr: {}", code, stderr);
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn private_key_block() {
    let text = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAn\n-----END RSA PRIVATE KEY-----";
    let (stdout, _, code) = run(&["redact", "--text", text]);
    assert_eq!(code, 0);
    assert!(stdout.contains("[REDACTED:PRIVATE_KEY]"));
    assert!(!stdout.contains("MIIEowIBAAKCAQEAn"));
}

#[test]
fn bearer_token() {
    let (stdout, _, code) = run(&[
        "redact",
        "--text",
        "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9",
    ]);
    assert_eq!(code, 0);
    assert!(stdout.contains("[REDACTED:"));
}

#[test]
fn password_assignment() {
    let (stdout, _, code) = run(&["redact", "--text", "password=supersecret123"]);
    assert_eq!(code, 0);
    assert!(stdout.contains("[REDACTED:PASSWORD]"));
    assert!(!stdout.contains("supersecret123"));
}

#[test]
fn reports_never_leak_full_secrets() {
    let (_, stderr, _) = run(&[
        "redact",
        "--text",
        "password=my_super_secret_password_value",
        "--report-json",
    ]);
    assert!(!stderr.contains("my_super_secret_password_value"));
    // Should contain masked sample with ***
    if stderr.contains("masked_sample") {
        assert!(stderr.contains("***"));
    }
}

// === Config File ===

#[test]
fn config_file_custom_pattern() {
    let dir = temp_dir("config_test");
    let config_path = dir.join("config.toml");
    fs::write(
        &config_path,
        r#"
replacement = "[SCRUBBED]"

[pattern]
MY_ID = "ID-\d+"
"#,
    )
    .unwrap();

    let (stdout, _, code) = run(&[
        "redact",
        "--text",
        "user ID-12345 found",
        "--config",
        config_path.to_str().unwrap(),
    ]);
    assert_eq!(code, 0);
    assert!(stdout.contains("[SCRUBBED]"));
    assert!(!stdout.contains("ID-12345"));
    let _ = fs::remove_dir_all(&dir);
}

// === Exit Codes ===

#[test]
fn exit_code_0_success() {
    let (_, _, code) = run(&["redact", "--text", "clean"]);
    assert_eq!(code, 0);
}

#[test]
fn exit_code_3_findings_with_fail() {
    let (_, _, code) = run(&["redact", "--text", "user@example.com", "--fail-on-find"]);
    assert_eq!(code, 3);
}
