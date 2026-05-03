use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::Command;

fn binary_path() -> PathBuf {
    let mut path = std::env::current_exe().unwrap();
    path.pop(); // remove test binary name
    path.pop(); // remove 'deps'
    path.push("redacted");
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

fn run_with_env(args: &[&str], envs: &[(String, String)]) -> (String, String, i32) {
    let mut command = Command::new(binary_path());
    command.args(args);
    for (key, value) in envs {
        command.env(key, value);
    }
    let output = command.output().expect("Failed to execute binary");
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let code = output.status.code().unwrap_or(-1);
    (stdout, stderr, code)
}

fn run_with_stdin_env(
    args: &[&str],
    stdin: &str,
    envs: &[(String, String)],
) -> (String, String, i32) {
    use std::io::Write;
    use std::process::Stdio;

    let mut command = Command::new(binary_path());
    command.args(args);
    for (key, value) in envs {
        command.env(key, value);
    }

    let mut child = command
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

#[cfg(unix)]
fn sha256_hex_for_test(path: &std::path::Path) -> String {
    let output = Command::new("shasum")
        .args(["-a", "256"])
        .arg(path)
        .output()
        .or_else(|_| Command::new("sha256sum").arg(path).output())
        .expect("Failed to hash test fixture");
    assert!(
        output.status.success(),
        "hash command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout)
        .split_whitespace()
        .next()
        .expect("missing hash output")
        .to_string()
}

fn provider_env(name: &str) -> (PathBuf, PathBuf, Vec<(String, String)>) {
    let root = temp_dir(name);
    let config_root = root.join("provider-config");
    let data_root = root.join("provider-data");
    fs::create_dir_all(&config_root).unwrap();
    fs::create_dir_all(&data_root).unwrap();
    let envs = vec![
        (
            "REDACTED_CONFIG_HOME".to_string(),
            config_root.to_string_lossy().into_owned(),
        ),
        (
            "REDACTED_DATA_HOME".to_string(),
            data_root.to_string_lossy().into_owned(),
        ),
    ];
    (config_root, data_root, envs)
}

#[cfg(unix)]
fn add_fake_pdftotext_to_env(
    envs: &mut Vec<(String, String)>,
    root: &std::path::Path,
) -> std::io::Result<()> {
    let bin_dir = root.join("fake-bin");
    fs::create_dir_all(&bin_dir)?;
    let tool_path = bin_dir.join("pdftotext");
    fs::write(
        &tool_path,
        "#!/usr/bin/env python3\nimport sys\nsys.stdout.write('pdftotext 1.0\\n')\n",
    )?;
    fs::set_permissions(&tool_path, fs::Permissions::from_mode(0o755))?;
    let current_path = std::env::var("PATH").unwrap_or_default();
    envs.push((
        "PATH".to_string(),
        format!("{}:{}", bin_dir.to_string_lossy(), current_path),
    ));
    Ok(())
}

#[cfg(unix)]
fn install_fake_provider_bundle(
    config_root: &std::path::Path,
    data_root: &std::path::Path,
    runner_contents: &str,
    activate: bool,
) {
    let bundle_root = data_root
        .join("providers")
        .join("openai")
        .join("privacy-filter-v1");
    fs::create_dir_all(bundle_root.join("runner")).unwrap();
    fs::create_dir_all(bundle_root.join("venv").join("bin")).unwrap();
    fs::create_dir_all(bundle_root.join("model")).unwrap();
    let entry_path = bundle_root.join("runner").join("openai_privacy_runner.py");
    fs::write(
        &entry_path,
        "#!/usr/bin/env python3\nimport argparse\nimport json\nimport sys\nfrom opf._api import OPF\n",
    )
    .unwrap();
    fs::set_permissions(&entry_path, fs::Permissions::from_mode(0o755)).unwrap();
    let runner_path = bundle_root.join("venv").join("bin").join("python");
    fs::write(&runner_path, runner_contents).unwrap();
    fs::set_permissions(&runner_path, fs::Permissions::from_mode(0o755)).unwrap();
    let runner_sha256 = sha256_hex_for_test(&entry_path);
    let runner_executable_sha256 = sha256_hex_for_test(&runner_path);
    fs::write(
        bundle_root.join("bundle.state"),
        format!(
            "schema_version=1\n\
target=openai/privacy-filter-v1\n\
provider=openai\n\
model=privacy-filter-v1\n\
adapter=openai-opf-local\n\
runner_rel=venv/bin/python\n\
entry_rel=runner/openai_privacy_runner.py\n\
checkpoint_rel=model\n\
runner_sha256={}\n\
runner_executable_sha256={}\n",
            runner_sha256, runner_executable_sha256
        ),
    )
    .unwrap();
    fs::write(
        bundle_root.join("verified.state"),
        "schema_version=1\n\
target=openai/privacy-filter-v1\n\
verified_unix_seconds=1\n",
    )
    .unwrap();
    if activate {
        fs::write(
            config_root.join("active-provider.state"),
            "target=openai/privacy-filter-v1\n",
        )
        .unwrap();
    }
}

#[cfg(unix)]
fn install_fake_document_bundle(
    config_root: &std::path::Path,
    data_root: &std::path::Path,
    runner_contents: &str,
    activate: bool,
) {
    let bundle_root = data_root
        .join("document-adapters")
        .join("pdf-inspector")
        .join("local-v1");
    fs::create_dir_all(bundle_root.join("runner")).unwrap();
    let runner_path = bundle_root.join("runner").join("fake_document_runner.py");
    fs::write(&runner_path, runner_contents).unwrap();
    fs::set_permissions(&runner_path, fs::Permissions::from_mode(0o755)).unwrap();
    fs::write(
        bundle_root.join("bundle.state"),
        "schema_version=1\n\
target=pdf-inspector/local-v1\n\
adapter=pdftotext-local\n\
runner_rel=runner/fake_document_runner.py\n",
    )
    .unwrap();
    fs::write(
        bundle_root.join("verified.state"),
        "schema_version=1\n\
target=pdf-inspector/local-v1\n\
verified_unix_seconds=1\n",
    )
    .unwrap();
    if activate {
        fs::write(
            config_root.join("active-document-adapter.state"),
            "target=pdf-inspector/local-v1\n",
        )
        .unwrap();
    }
}

#[cfg(unix)]
fn fake_document_runner() -> String {
    r#"#!/usr/bin/env python3
import argparse
import pathlib
import sys

parser = argparse.ArgumentParser()
parser.add_argument("--target", required=True)
parser.add_argument("--input", required=True)
args = parser.parse_args()

text = pathlib.Path(args.input).read_text(encoding="utf-8", errors="ignore")
sys.stdout.write(text)
"#
    .to_string()
}

#[cfg(unix)]
fn fake_provider_runner() -> String {
    r#"#!/usr/bin/env python3
import argparse
import json
import os
import sys

parser = argparse.ArgumentParser()
parser.add_argument("entry", nargs="?")
parser.add_argument("--target", required=True)
parser.add_argument("--checkpoint", required=True)
args = parser.parse_args()

marker = os.environ.get("FAKE_PROVIDER_START_MARKER")
if marker:
    with open(marker, "a", encoding="utf-8") as handle:
        handle.write("start\n")

mode = os.environ.get("FAKE_PROVIDER_MODE", "normal")
if mode == "exit_with_stderr":
    sys.stderr.write("provider import failed: missing fake_package\n")
    sys.exit(7)
desync_marker = os.environ.get("FAKE_PROVIDER_DESYNC_MARKER")

for raw_line in sys.stdin:
    line = raw_line.strip()
    if not line:
        continue
    if mode == "malformed":
        sys.stdout.write("{bad json}\n")
        sys.stdout.flush()
        continue
    if mode == "desync_once" and desync_marker and not os.path.exists(desync_marker):
        with open(desync_marker, "w", encoding="utf-8") as handle:
            handle.write("used\n")
        sys.stdout.write("debug output on stdout\n")
        sys.stdout.flush()
        continue

    request = json.loads(line)
    text = request["text"]
    spans = []
    if mode == "bad_span":
        spans.append({"label": "private_person", "start": 1, "end": 2})
    elif mode == "zero_span":
        spans.append({"label": "private_person", "start": 0, "end": 0})
    else:
        if text.startswith("Alice"):
            spans.append({"label": "private_person", "start": 0, "end": 5})
        date_value = "1990-01-02"
        if date_value in text:
            start = text.index(date_value)
            spans.append({"label": "private_date", "start": start, "end": start + len(date_value)})

    response = {
        "schema_version": 1,
        "request_id": request["request_id"],
        "target": args.target,
        "spans": spans,
    }
    sys.stdout.write(json.dumps(response, separators=(",", ":")) + "\n")
    sys.stdout.flush()
"#
    .to_string()
}

// === Help and Version ===

#[test]
fn help_flag() {
    let (_, stderr, code) = run(&["--help"]);
    assert_eq!(code, 0);
    assert!(stderr.contains("USAGE:"));
    assert!(stderr.contains("--input"));
    assert!(stderr.contains("EXAMPLES:"));
}

#[test]
fn version_flag() {
    let (_, stderr, code) = run(&["--version"]);
    assert_eq!(code, 0);
    assert!(stderr.contains("redacted 0.1.0"));
}

#[test]
fn provider_help_flag() {
    let (_, stderr, code) = run(&["provider", "--help"]);
    assert_eq!(code, 0);
    assert!(stderr.contains("redacted provider"));
    assert!(stderr.contains("enable <provider-or-target>"));
}

#[test]
fn provider_enable_help_flag() {
    let (_, stderr, code) = run(&["provider", "enable", "--help"]);
    assert_eq!(code, 0);
    assert!(stderr.contains("redacted provider enable"));
    assert!(stderr.contains("openai/privacy-filter-v1"));
}

#[test]
fn document_help_flag() {
    let (_, stderr, code) = run(&["document", "--help"]);
    assert_eq!(code, 0);
    assert!(stderr.contains("redacted document"));
    assert!(stderr.contains("enable <adapter-or-target>"));
}

#[test]
fn document_enable_help_flag() {
    let (_, stderr, code) = run(&["document", "enable", "--help"]);
    assert_eq!(code, 0);
    assert!(stderr.contains("redacted document enable"));
    assert!(stderr.contains("pdf-inspector/local-v1"));
}

#[test]
fn benchmark_help_flag() {
    let (_, stderr, code) = run(&["benchmark", "--help"]);
    assert_eq!(code, 0);
    assert!(stderr.contains("redacted benchmark"));
    assert!(stderr.contains("--iterations"));
}

#[test]
fn benchmark_runs_text_report() {
    let dir = temp_dir("benchmark_text");
    let input_path = dir.join("sample.txt");
    fs::write(&input_path, "email user@example.com").unwrap();

    let (stdout, stderr, code) = run(&[
        "benchmark",
        "--input",
        input_path.to_str().unwrap(),
        "--iterations",
        "2",
    ]);
    assert_eq!(code, 0, "stderr: {}", stderr);
    assert!(stdout.contains("Benchmark report"));
    assert!(stdout.contains("iterations: 2"));
    assert!(stdout.contains("runs:"));
}

#[test]
fn benchmark_runs_json_report() {
    let dir = temp_dir("benchmark_json");
    let input_path = dir.join("sample.txt");
    fs::write(&input_path, "token=sk_live_abcdef123456").unwrap();

    let (stdout, stderr, code) = run(&[
        "benchmark",
        "--input",
        input_path.to_str().unwrap(),
        "--iterations",
        "1",
        "--format",
        "json",
    ]);
    assert_eq!(code, 0, "stderr: {}", stderr);
    assert!(stdout.contains("\"runs\""));
    assert!(stdout.contains("\"summary\""));
}

#[cfg(unix)]
#[test]
fn benchmark_accepts_directory_reports_with_file_errors() {
    let dir = temp_dir("benchmark_file_error");
    let input_dir = dir.join("input");
    fs::create_dir_all(&input_dir).unwrap();
    fs::write(input_dir.join("ok.txt"), "email user@example.com").unwrap();
    let unreadable = input_dir.join("blocked.txt");
    fs::write(&unreadable, "blocked").unwrap();
    fs::set_permissions(&unreadable, fs::Permissions::from_mode(0o000)).unwrap();

    let (stdout, stderr, code) = run(&[
        "benchmark",
        "--input",
        input_dir.to_str().unwrap(),
        "--iterations",
        "1",
    ]);

    let _ = fs::set_permissions(&unreadable, fs::Permissions::from_mode(0o600));
    assert_eq!(code, 0, "stderr: {}", stderr);
    assert!(stdout.contains("Benchmark report"));
    assert!(stdout.contains("files_errored=1"));
    let _ = fs::remove_dir_all(&dir);
}

#[cfg(unix)]
#[test]
fn provider_current_without_active_shows_onboarding() {
    let (_config_root, _data_root, envs) = provider_env("provider_current_none");
    let (stdout, _, code) = run_with_env(&["provider", "current"], &envs);
    assert_eq!(code, 0);
    assert!(stdout.contains("No active provider configured"));
    assert!(stdout.contains("redacted provider enable openai"));
}

#[cfg(unix)]
#[test]
fn document_current_without_active_shows_onboarding() {
    let (config_root, _data_root, mut envs) = provider_env("document_current_none");
    add_fake_pdftotext_to_env(&mut envs, config_root.parent().unwrap()).unwrap();
    let (stdout, _, code) = run_with_env(&["document", "current"], &envs);
    assert_eq!(code, 0);
    assert!(stdout.contains("No active document adapter configured"));
    assert!(stdout.contains("redacted document enable pdf-inspector"));
}

#[cfg(unix)]
#[test]
fn provider_use_alias_sets_exact_active_target() {
    let (config_root, data_root, envs) = provider_env("provider_use_alias");
    install_fake_provider_bundle(&config_root, &data_root, &fake_provider_runner(), false);

    let (stdout, stderr, code) = run_with_env(&["provider", "use", "openai"], &envs);
    assert_eq!(code, 0, "stderr: {}", stderr);
    assert!(stdout.contains("resolved target: openai/privacy-filter-v1"));

    let active_state = fs::read_to_string(config_root.join("active-provider.state")).unwrap();
    assert!(active_state.contains("openai/privacy-filter-v1"));
}

#[cfg(unix)]
#[test]
fn document_use_alias_sets_exact_active_target() {
    let (config_root, data_root, mut envs) = provider_env("document_use_alias");
    add_fake_pdftotext_to_env(&mut envs, config_root.parent().unwrap()).unwrap();
    install_fake_document_bundle(&config_root, &data_root, &fake_document_runner(), false);

    let (stdout, stderr, code) = run_with_env(&["document", "use", "pdf-inspector"], &envs);
    assert_eq!(code, 0, "stderr: {}", stderr);
    assert!(stdout.contains("resolved target: pdf-inspector/local-v1"));

    let active_state =
        fs::read_to_string(config_root.join("active-document-adapter.state")).unwrap();
    assert!(active_state.contains("pdf-inspector/local-v1"));
}

#[cfg(unix)]
#[test]
fn provider_enable_alias_reuses_verified_bundle() {
    let (config_root, data_root, envs) = provider_env("provider_enable_alias");
    install_fake_provider_bundle(&config_root, &data_root, &fake_provider_runner(), false);

    let (stdout, stderr, code) = run_with_env(&["provider", "enable", "openai"], &envs);
    assert_eq!(code, 0, "stderr: {}", stderr);
    assert!(stdout.contains("resolved target: openai/privacy-filter-v1"));
    assert!(stdout.contains("verified: yes"));
}

#[cfg(unix)]
#[test]
fn provider_list_shows_aliases_and_install_state() {
    let (config_root, data_root, envs) = provider_env("provider_list");
    install_fake_provider_bundle(&config_root, &data_root, &fake_provider_runner(), true);

    let (stdout, _, code) = run_with_env(&["provider", "list"], &envs);
    assert_eq!(code, 0);
    assert!(stdout.contains("Aliases:"));
    assert!(stdout.contains("openai -> openai/privacy-filter-v1"));
    assert!(stdout.contains("mlx -> openai/privacy-filter-v1-mlx"));
    assert!(stdout.contains("support=supported"));
    assert!(stdout.contains("support=experimental"));
    assert!(stdout.contains("mode=token-span"));
    assert!(stdout.contains("mode=token-span-mlx"));
    assert!(stdout.contains("installed=yes"));
    assert!(stdout.contains("active=yes"));
    assert!(stdout.contains("installed=no"));
}

#[cfg(unix)]
#[test]
fn provider_disable_is_idempotent() {
    let (_config_root, _data_root, envs) = provider_env("provider_disable");
    let (stdout, _, code) = run_with_env(&["provider", "disable"], &envs);
    assert_eq!(code, 0);
    assert!(stdout.contains("already disabled"));
}

// === Text Mode ===

#[test]
fn text_redacts_email() {
    let (stdout, _, code) = run(&["--text", "email me at user@example.com please"]);
    assert_eq!(code, 0);
    assert!(stdout.contains("[REDACTED:EMAIL]"));
    assert!(!stdout.contains("user@example.com"));
}

#[test]
fn text_redacts_phone() {
    let (stdout, _, code) = run(&["--text", "call +1-555-867-5309"]);
    assert_eq!(code, 0);
    assert!(stdout.contains("[REDACTED:PHONE]"));
}

#[cfg(unix)]
#[test]
fn privacy_filter_requires_active_provider() {
    let (_config_root, _data_root, envs) = provider_env("privacy_requires_active");
    let (_stdout, stderr, code) = run_with_env(
        &["--text", "Alice user@example.com", "--privacy-filter"],
        &envs,
    );
    assert_eq!(code, 2);
    assert!(stderr.contains("No active privacy-filter provider is configured"));
    assert!(stderr.contains("redacted provider enable openai"));
}

#[cfg(unix)]
#[test]
fn document_adapter_requires_active_adapter() {
    let (config_root, _data_root, mut envs) = provider_env("document_requires_active");
    add_fake_pdftotext_to_env(&mut envs, config_root.parent().unwrap()).unwrap();
    let pdf_path = config_root.join("sample.pdf");
    fs::write(&pdf_path, "Alice user@example.com").unwrap();

    let (_stdout, stderr, code) = run_with_env(
        &["--input", pdf_path.to_str().unwrap(), "--document-adapter"],
        &envs,
    );
    assert_eq!(code, 2);
    assert!(stderr.contains("No active document adapter is configured"));
    assert!(stderr.contains("redacted document enable pdf-inspector"));
}

#[cfg(unix)]
#[test]
fn document_adapter_rejects_single_file_in_place_before_extraction() {
    let (config_root, data_root, mut envs) = provider_env("document_single_in_place");
    add_fake_pdftotext_to_env(&mut envs, config_root.parent().unwrap()).unwrap();
    install_fake_document_bundle(&config_root, &data_root, &fake_document_runner(), true);

    let pdf_path = data_root.join("report.pdf");
    fs::write(&pdf_path, "email: user@example.com").unwrap();

    let (_stdout, stderr, code) = run_with_env(
        &[
            "--input",
            pdf_path.to_str().unwrap(),
            "--document-adapter",
            "--in-place",
        ],
        &envs,
    );
    assert_eq!(code, 2);
    assert!(stderr.contains("Cannot use --in-place with --document-adapter"));
}

#[cfg(unix)]
#[test]
fn document_adapter_redacts_pdf_with_fake_runner() {
    let (config_root, data_root, mut envs) = provider_env("document_scan_pdf");
    add_fake_pdftotext_to_env(&mut envs, config_root.parent().unwrap()).unwrap();
    install_fake_document_bundle(&config_root, &data_root, &fake_document_runner(), true);

    let pdf_path = data_root.join("report.pdf");
    fs::write(
        &pdf_path,
        "Alice can be reached at user@example.com and +1-555-867-5309",
    )
    .unwrap();

    let (stdout, stderr, code) = run_with_env(
        &["--input", pdf_path.to_str().unwrap(), "--document-adapter"],
        &envs,
    );
    assert_eq!(code, 0, "stderr: {}", stderr);
    assert!(stdout.contains("[REDACTED:EMAIL]"));
    assert!(stdout.contains("[REDACTED:PHONE]"));
}

#[cfg(unix)]
#[test]
fn privacy_filter_redacts_provider_findings_in_addition_to_built_ins() {
    let (config_root, data_root, envs) = provider_env("privacy_text_merge");
    install_fake_provider_bundle(&config_root, &data_root, &fake_provider_runner(), true);

    let (stdout, stderr, code) = run_with_env(
        &[
            "--text",
            "Alice emailed user@example.com on 1990-01-02",
            "--privacy-filter",
        ],
        &envs,
    );
    assert_eq!(code, 0, "stderr: {}", stderr);
    assert!(stdout.contains("[REDACTED:PRIVATE_PERSON]"));
    assert!(stdout.contains("[REDACTED:EMAIL]"));
}

#[cfg(unix)]
#[test]
fn privacy_filter_respects_allow_pattern_for_provider_labels() {
    let (config_root, data_root, envs) = provider_env("privacy_allow_pattern");
    install_fake_provider_bundle(&config_root, &data_root, &fake_provider_runner(), true);

    let (stdout, stderr, code) = run_with_env(
        &[
            "--text",
            "Alice emailed user@example.com on 1990-01-02",
            "--privacy-filter",
            "--allow-pattern",
            "PRIVATE_PERSON",
        ],
        &envs,
    );
    assert_eq!(code, 0, "stderr: {}", stderr);
    assert!(stdout.contains("[REDACTED:PRIVATE_PERSON]"));
    assert!(stdout.contains("user@example.com"));
    assert!(stdout.contains("1990-01-02"));
}

#[cfg(unix)]
#[test]
fn privacy_filter_reports_invalid_runner_json() {
    let (config_root, data_root, mut envs) = provider_env("privacy_bad_json");
    install_fake_provider_bundle(&config_root, &data_root, &fake_provider_runner(), true);
    envs.push(("FAKE_PROVIDER_MODE".into(), "malformed".into()));

    let (_stdout, stderr, code) = run_with_env(
        &["--text", "Alice user@example.com", "--privacy-filter"],
        &envs,
    );
    assert_eq!(code, 1);
    assert!(stderr.contains("Invalid provider response JSON"));
}

#[cfg(unix)]
#[test]
fn privacy_filter_hides_provider_stderr_by_default() {
    let (config_root, data_root, mut envs) = provider_env("privacy_stderr_hidden");
    install_fake_provider_bundle(&config_root, &data_root, &fake_provider_runner(), true);
    envs.push(("FAKE_PROVIDER_MODE".into(), "exit_with_stderr".into()));

    let (_stdout, stderr, code) = run_with_env(
        &["--text", "Alice user@example.com", "--privacy-filter"],
        &envs,
    );
    assert_eq!(code, 1);
    assert!(stderr.contains("exited without returning a response"));
    assert!(stderr.contains("Provider stderr was captured but hidden"));
    assert!(!stderr.contains("missing fake_package"));
}

#[cfg(unix)]
#[test]
fn privacy_filter_can_show_provider_stderr_when_debug_enabled() {
    let (config_root, data_root, mut envs) = provider_env("privacy_stderr_debug");
    install_fake_provider_bundle(&config_root, &data_root, &fake_provider_runner(), true);
    envs.push(("FAKE_PROVIDER_MODE".into(), "exit_with_stderr".into()));
    envs.push(("REDACTED_PROVIDER_DEBUG".into(), "1".into()));

    let (_stdout, stderr, code) = run_with_env(
        &["--text", "Alice user@example.com", "--privacy-filter"],
        &envs,
    );
    assert_eq!(code, 1);
    assert!(stderr.contains("Provider stderr (truncated):"));
    assert!(stderr.contains("missing fake_package"));
}

#[cfg(unix)]
#[test]
fn privacy_filter_directory_provider_error_marks_files_and_continues() {
    let (config_root, data_root, mut envs) = provider_env("privacy_dir_provider_error");
    install_fake_provider_bundle(&config_root, &data_root, &fake_provider_runner(), true);
    envs.push(("FAKE_PROVIDER_MODE".into(), "malformed".into()));

    let input_dir = data_root.join("input");
    fs::create_dir_all(&input_dir).unwrap();
    fs::write(input_dir.join("a.txt"), "Alice emailed user@example.com").unwrap();
    fs::write(input_dir.join("b.txt"), "Alice was born on 1990-01-02").unwrap();

    let (_stdout, stderr, code) = run_with_env(
        &[
            "--input",
            input_dir.to_str().unwrap(),
            "--privacy-filter",
            "--dry-run",
            "--report-json",
        ],
        &envs,
    );
    assert_eq!(code, 1);
    assert!(stderr.contains("\"path\": \"a.txt\""));
    assert!(stderr.contains("\"path\": \"b.txt\""));
    assert!(stderr.contains("\"files_errored\": 2"));
    assert!(stderr.contains("Invalid provider response JSON"));
}

#[cfg(unix)]
#[test]
fn privacy_filter_rejects_non_boundary_provider_spans() {
    let (config_root, data_root, mut envs) = provider_env("privacy_bad_span");
    install_fake_provider_bundle(&config_root, &data_root, &fake_provider_runner(), true);
    envs.push(("FAKE_PROVIDER_MODE".into(), "bad_span".into()));

    let (_stdout, stderr, code) = run_with_env(&["--text", "éAlice", "--privacy-filter"], &envs);
    assert_eq!(code, 1);
    assert!(stderr.contains("returned invalid span"));
}

#[cfg(unix)]
#[test]
fn privacy_filter_rejects_zero_length_provider_spans() {
    let (config_root, data_root, mut envs) = provider_env("privacy_zero_span");
    install_fake_provider_bundle(&config_root, &data_root, &fake_provider_runner(), true);
    envs.push(("FAKE_PROVIDER_MODE".into(), "zero_span".into()));

    let (_stdout, stderr, code) = run_with_env(&["--text", "Alice", "--privacy-filter"], &envs);
    assert_eq!(code, 1);
    assert!(stderr.contains("returned invalid span 0..0"));
}

#[cfg(unix)]
#[test]
fn privacy_filter_directory_restarts_provider_after_desync() {
    let (config_root, data_root, mut envs) = provider_env("privacy_dir_desync_restart");
    install_fake_provider_bundle(&config_root, &data_root, &fake_provider_runner(), true);
    let marker_path = data_root.join("desync-marker");
    let starts_path = data_root.join("runner-starts.log");
    envs.push(("FAKE_PROVIDER_MODE".into(), "desync_once".into()));
    envs.push((
        "FAKE_PROVIDER_DESYNC_MARKER".into(),
        marker_path.to_string_lossy().into_owned(),
    ));
    envs.push((
        "FAKE_PROVIDER_START_MARKER".into(),
        starts_path.to_string_lossy().into_owned(),
    ));

    let input_dir = data_root.join("input");
    fs::create_dir_all(&input_dir).unwrap();
    fs::write(input_dir.join("a.txt"), "Alice emailed user@example.com").unwrap();
    fs::write(input_dir.join("b.txt"), "Alice was born on 1990-01-02").unwrap();

    let (stdout, stderr, code) = run_with_env(
        &[
            "--input",
            input_dir.to_str().unwrap(),
            "--privacy-filter",
            "--dry-run",
            "--format",
            "json",
        ],
        &envs,
    );
    assert_eq!(code, 1, "stderr: {}", stderr);
    assert!(stdout.contains("\"path\": \"a.txt\""));
    assert!(stdout.contains("\"path\": \"b.txt\""));
    assert!(stdout.contains("\"files_errored\": 1"));
    assert!(stdout.contains("\"files_processed\": 1"));
    let starts = fs::read_to_string(&starts_path).unwrap();
    assert_eq!(starts.lines().count(), 2);
}

#[test]
fn text_redacts_ipv4() {
    let (stdout, _, code) = run(&["--text", "server 192.168.1.100"]);
    assert_eq!(code, 0);
    assert!(stdout.contains("[REDACTED:IP]"));
    assert!(!stdout.contains("192.168.1.100"));
}

#[test]
fn text_redacts_ipv6() {
    let (stdout, _, code) = run(&["--text", "addr: 2001:0db8:85a3:0000:0000:8a2e:0370:7334"]);
    assert_eq!(code, 0);
    assert!(stdout.contains("[REDACTED:IP]"));
    assert!(!stdout.contains("2001:0db8"));
}

#[test]
fn text_redacts_aws_key() {
    let (stdout, _, code) = run(&["--text", "key=AKIAIOSFODNN7EXAMPLE"]);
    assert_eq!(code, 0);
    assert!(stdout.contains("[REDACTED:AWS_KEY]"));
}

#[test]
fn text_redacts_jwt() {
    let (stdout, _, code) = run(&[
        "--text",
        "token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
    ]);
    assert_eq!(code, 0);
    assert!(stdout.contains("[REDACTED:JWT]"));
}

#[test]
fn text_redacts_stripe_key() {
    let (stdout, _, code) = run(&["--text", "STRIPE_KEY=sk_live_abcdef1234567890"]);
    assert_eq!(code, 0);
    assert!(stdout.contains("[REDACTED:"));
    assert!(!stdout.contains("sk_live_abcdef1234567890"));
}

#[test]
fn text_redacts_github_token() {
    let (stdout, _, code) = run(&["--text", "token: ghp_abcdefghijklmnop1234567890abcd"]);
    assert_eq!(code, 0);
    assert!(stdout.contains("[REDACTED:GITHUB_TOKEN]"));
}

#[test]
fn text_redacts_database_url() {
    let (stdout, _, code) = run(&[
        "--text",
        "DATABASE_URL=postgres://admin:s3cret@db.host:5432/mydb",
    ]);
    assert_eq!(code, 0);
    assert!(stdout.contains("[REDACTED:"));
    assert!(!stdout.contains("s3cret"));
}

#[test]
fn text_redacts_credit_card() {
    let (stdout, _, code) = run(&["--text", "card: 4111 1111 1111 1111"]);
    assert_eq!(code, 0);
    assert!(stdout.contains("[REDACTED:CREDIT_CARD]"));
}

#[test]
fn text_redacts_ssn() {
    let (stdout, _, code) = run(&["--text", "ssn: 123-45-6789"]);
    assert_eq!(code, 0);
    assert!(stdout.contains("[REDACTED:SSN]"));
}

#[test]
fn text_clean_no_findings() {
    let (stdout, _, code) = run(&["--text", "this is clean text"]);
    assert_eq!(code, 0);
    assert_eq!(stdout, "this is clean text");
}

#[test]
fn text_custom_replacement() {
    let (stdout, _, code) = run(&["--text", "email: user@example.com", "--replacement", "***"]);
    assert_eq!(code, 0);
    assert!(stdout.contains("***"));
    assert!(!stdout.contains("[REDACTED"));
}

// === Path Detection ===

#[test]
fn text_redacts_unix_path() {
    let (stdout, _, code) = run(&["--text", "config at /etc/nginx/nginx.conf"]);
    assert_eq!(code, 0);
    assert!(stdout.contains("[REDACTED:PATH]"));
    assert!(!stdout.contains("/etc/nginx"));
}

#[test]
fn text_redacts_home_path() {
    let (stdout, _, code) = run(&["--text", "file: /home/user/.ssh/id_rsa"]);
    assert_eq!(code, 0);
    assert!(stdout.contains("[REDACTED:PATH]"));
    assert!(!stdout.contains("/home/user"));
}

#[test]
fn text_redacts_relative_path() {
    let (stdout, _, code) = run(&["--text", "log at ./logs/app/server.log ok"]);
    assert_eq!(code, 0);
    assert!(stdout.contains("[REDACTED:PATH]"));
    assert!(!stdout.contains("./logs/app"));
}

#[test]
fn text_no_false_positive_single_slash() {
    let (stdout, _, code) = run(&["--text", "use a/b for the option"]);
    assert_eq!(code, 0);
    // "a/b" is too short to be a meaningful path — should not be redacted
    assert!(!stdout.contains("[REDACTED:PATH]"));
}

// === Stdin Mode ===

#[test]
fn stdin_redacts_email() {
    let (stdout, _, code) = run_with_stdin(&[], "contact user@example.com");
    assert_eq!(code, 0);
    assert!(stdout.contains("[REDACTED:EMAIL]"));
}

#[test]
fn stdin_redacts_multiple() {
    let (stdout, _, code) =
        run_with_stdin(&[], "email: user@example.com\nkey=AKIAIOSFODNN7EXAMPLE\n");
    assert_eq!(code, 0);
    assert!(stdout.contains("[REDACTED:EMAIL]"));
    assert!(stdout.contains("[REDACTED:AWS_KEY]"));
}

#[cfg(unix)]
#[test]
fn privacy_filter_works_with_stdin() {
    let (config_root, data_root, envs) = provider_env("privacy_stdin");
    install_fake_provider_bundle(&config_root, &data_root, &fake_provider_runner(), true);

    let (stdout, stderr, code) =
        run_with_stdin_env(&["--privacy-filter"], "Alice user@example.com", &envs);
    assert_eq!(code, 0, "stderr: {}", stderr);
    assert!(stdout.contains("[REDACTED:PRIVATE_PERSON]"));
    assert!(stdout.contains("[REDACTED:EMAIL]"));
}

// === File Mode ===

#[test]
fn file_input_to_stdout() {
    let dir = temp_dir("file_stdout");
    let input = dir.join("input.txt");
    fs::write(&input, "secret: user@example.com").unwrap();

    let (stdout, _, code) = run(&["--input", input.to_str().unwrap()]);
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

    let (_, _, code) = run(&["--input", input.to_str().unwrap(), "--in-place"]);
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

    let (_, _, code) = run(&["--input", input_dir.to_str().unwrap()]);
    assert_eq!(code, 2);
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn directory_in_place_without_output_is_allowed() {
    let dir = temp_dir("dir_in_place_only");
    let input_dir = dir.join("input");
    fs::create_dir_all(&input_dir).unwrap();
    let file = input_dir.join("a.txt");
    fs::write(&file, "email: user@example.com").unwrap();

    let (_, stderr, code) = run(&["--input", input_dir.to_str().unwrap(), "--in-place"]);
    assert_eq!(code, 0, "stderr: {}", stderr);
    let content = fs::read_to_string(&file).unwrap();
    assert!(content.contains("[REDACTED:EMAIL]"));
    let _ = fs::remove_dir_all(&dir);
}

#[cfg(unix)]
#[test]
fn directory_rejects_document_adapter_in_place() {
    let (config_root, data_root, mut envs) = provider_env("document_dir_in_place");
    install_fake_document_bundle(&config_root, &data_root, &fake_document_runner(), true);
    add_fake_pdftotext_to_env(&mut envs, &data_root).unwrap();
    let input_dir = data_root.join("input");
    fs::create_dir_all(&input_dir).unwrap();
    fs::write(input_dir.join("report.pdf"), "email: user@example.com").unwrap();

    let (_stdout, stderr, code) = run_with_env(
        &[
            "--input",
            input_dir.to_str().unwrap(),
            "--document-adapter",
            "--in-place",
        ],
        &envs,
    );
    assert_eq!(code, 2);
    assert!(stderr.contains("Cannot use --in-place with --document-adapter"));
}

#[test]
fn directory_dry_run_no_output_required() {
    let dir = temp_dir("dir_dryrun");
    let input_dir = dir.join("input");
    fs::create_dir_all(&input_dir).unwrap();
    fs::write(input_dir.join("a.txt"), "email: user@example.com").unwrap();

    let (_, stderr, code) = run(&["--input", input_dir.to_str().unwrap(), "--dry-run"]);
    assert_eq!(code, 0);
    assert!(stderr.contains("Summary"));
    let _ = fs::remove_dir_all(&dir);
}

#[cfg(unix)]
#[test]
fn privacy_filter_directory_reuses_runner_once_per_invocation() {
    let (config_root, data_root, mut envs) = provider_env("privacy_directory_runner_once");
    install_fake_provider_bundle(&config_root, &data_root, &fake_provider_runner(), true);
    let marker_path = data_root.join("runner-starts.log");
    envs.push((
        "FAKE_PROVIDER_START_MARKER".into(),
        marker_path.to_string_lossy().into_owned(),
    ));

    let input_dir = data_root.join("input");
    let output_dir = data_root.join("output");
    fs::create_dir_all(&input_dir).unwrap();
    fs::write(input_dir.join("a.txt"), "Alice emailed user@example.com").unwrap();
    fs::write(input_dir.join("b.txt"), "Alice was born on 1990-01-02").unwrap();

    let (_stdout, stderr, code) = run_with_env(
        &[
            "--input",
            input_dir.to_str().unwrap(),
            "--output",
            output_dir.to_str().unwrap(),
            "--privacy-filter",
        ],
        &envs,
    );
    assert_eq!(code, 0, "stderr: {}", stderr);

    let marker = fs::read_to_string(&marker_path).unwrap();
    assert_eq!(marker.lines().count(), 1);
}

// === Flags and Modes ===

#[test]
fn fail_on_find_exits_3() {
    let (_, _, code) = run(&["--text", "email: user@example.com", "--fail-on-find"]);
    assert_eq!(code, 3);
}

#[test]
fn fail_on_find_exits_0_no_findings() {
    let (_, _, code) = run(&["--text", "clean text", "--fail-on-find"]);
    assert_eq!(code, 0);
}

#[test]
fn fail_on_find_takes_precedence_over_directory_errors() {
    let dir = temp_dir("fail_on_find_with_errors");
    let input_dir = dir.join("input");
    fs::create_dir_all(&input_dir).unwrap();
    fs::write(input_dir.join("secret.txt"), "email: user@example.com").unwrap();
    let binary_path = input_dir.join("binary.dat");
    fs::write(&binary_path, b"\x00\xff\x00").unwrap();

    let (_stdout, stderr, code) = run(&[
        "--input",
        input_dir.to_str().unwrap(),
        "--dry-run",
        "--binary",
        "fail",
        "--fail-on-find",
        "--report-json",
    ]);
    assert_eq!(code, 3, "stderr: {}", stderr);
    assert!(stderr.contains("\"path\": \"binary.dat\""));
    assert!(!stderr.contains(&binary_path.display().to_string()));
    assert!(stderr.contains("\"total_findings\": 1"));
    assert!(stderr.contains("\"files_errored\": 1"));
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn directory_binary_skip_reports_relative_path() {
    let dir = temp_dir("binary_skip_relative");
    let input_dir = dir.join("input");
    fs::create_dir_all(&input_dir).unwrap();
    let binary_path = input_dir.join("binary.dat");
    fs::write(&binary_path, b"\x00\xff\x00").unwrap();

    let (_stdout, stderr, code) = run(&[
        "--input",
        input_dir.to_str().unwrap(),
        "--dry-run",
        "--binary",
        "skip",
        "--report-json",
    ]);
    assert_eq!(code, 0, "stderr: {}", stderr);
    assert!(stderr.contains("\"path\": \"binary.dat\""));
    assert!(!stderr.contains(&binary_path.display().to_string()));
    assert!(stderr.contains("\"files_skipped\": 1"));
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn dry_run_does_not_redact_text() {
    let (stdout, stderr, code) = run(&["--text", "email: user@example.com", "--dry-run"]);
    assert_eq!(code, 0);
    assert!(stdout.contains("user@example.com"));
    assert!(stderr.contains("Summary"));
}

#[test]
fn summary_flag() {
    let (_, stderr, code) = run(&["--text", "user@example.com", "--summary"]);
    assert_eq!(code, 0);
    assert!(stderr.contains("Summary"));
    assert!(stderr.contains("Total findings"));
}

#[test]
fn report_json() {
    let (stdout, stderr, code) = run(&["--text", "email: user@example.com", "--report-json"]);
    assert_eq!(code, 0);
    assert!(stdout.contains("[REDACTED:EMAIL]"));
    assert!(stderr.contains("\"files_processed\""));
    assert!(stderr.contains("\"detector\""));
}

#[test]
fn format_json() {
    let (stdout, _, code) = run(&["--text", "email: user@example.com", "--format", "json"]);
    assert_eq!(code, 0);
    assert!(stdout.contains("\"summary\""));
    assert!(stdout.contains("\"files\""));
}

#[test]
fn custom_pattern() {
    let (stdout, _, code) = run(&[
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
        "--text",
        "email: user@example.com and key=AKIAIOSFODNN7EXAMPLE",
        "--allow-pattern",
        "EMAIL",
    ]);
    assert_eq!(code, 0);
    assert!(stdout.contains("[REDACTED:EMAIL]"));
    assert!(stdout.contains("AKIAIOSFODNN7EXAMPLE"));
}

#[test]
fn deny_pattern_filters() {
    let (stdout, _, code) = run(&[
        "--text",
        "email: user@example.com",
        "--deny-pattern",
        "EMAIL",
    ]);
    assert_eq!(code, 0);
    assert!(stdout.contains("user@example.com"));
}

#[test]
fn retain_detector_keeps_visible_value_but_reports_it() {
    let (stdout, stderr, code) = run(&[
        "--text",
        "email: user@example.com",
        "--retain-detector",
        "EMAIL",
        "--report-json",
    ]);
    assert_eq!(code, 0);
    assert!(stdout.contains("user@example.com"));
    assert!(!stdout.contains("[REDACTED:EMAIL]"));
    assert!(stderr.contains("\"detector\""));
    assert!(stderr.contains("\"action\": \"retained\""));
}

#[test]
fn except_file_retain_detector_keeps_visible_value() {
    let dir = temp_dir("except_retain_detector");
    let except_file = dir.join("rules.txt");
    fs::write(&except_file, "retain\tdetector\tEMAIL\n").unwrap();

    let (stdout, stderr, code) = run(&[
        "--text",
        "email: user@example.com",
        "--except-file",
        except_file.to_str().unwrap(),
        "--report-json",
    ]);
    assert_eq!(code, 0, "stderr: {}", stderr);
    assert!(stdout.contains("user@example.com"));
    assert!(stderr.contains("\"action\": \"retained\""));
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn except_subcommand_add_list_remove_round_trip() {
    let dir = temp_dir("except_subcommand");
    let except_file = dir.join("rules.txt");

    let (stdout, _, code) = run(&[
        "except",
        "--file",
        except_file.to_str().unwrap(),
        "add",
        "--detector",
        "EMAIL",
    ]);
    assert_eq!(code, 0);
    assert!(stdout.contains("Added retain detector EMAIL"));

    let (stdout, _, code) = run(&["except", "--file", except_file.to_str().unwrap(), "list"]);
    assert_eq!(code, 0);
    assert!(stdout.contains("retain detector EMAIL"));

    let (stdout, _, code) = run(&[
        "except",
        "--file",
        except_file.to_str().unwrap(),
        "remove",
        "--detector",
        "EMAIL",
    ]);
    assert_eq!(code, 0);
    assert!(stdout.contains("Removed retain detector EMAIL"));
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn entropy_detector_redacts_unassigned_high_entropy_token() {
    let (stdout, _, code) = run(&["--text", "token 9fJ4skQ2LmN8pR7vX5cT1wHbZ6dK3qY"]);
    assert_eq!(code, 0);
    assert!(stdout.contains("[REDACTED:HIGH_ENTROPY_SECRET]"));
}

#[test]
fn retain_custom_project_id_keeps_visible_value() {
    let (stdout, stderr, code) = run(&[
        "--text",
        "project PROJ-1234 ready",
        "--pattern",
        "PROJECT_ID=PROJ-\\d+",
        "--retain-detector",
        "PROJECT_ID",
        "--report-json",
    ]);
    assert_eq!(code, 0, "stderr: {}", stderr);
    assert!(stdout.contains("PROJ-1234"));
    assert!(!stdout.contains("[REDACTED:PROJECT_ID]"));
    assert!(stderr.contains("\"action\": \"retained\""));
}

// === Error Handling ===

#[test]
fn missing_input_file() {
    let (_, _, code) = run(&["--input", "/nonexistent/path"]);
    assert_eq!(code, 2);
}

#[test]
fn no_input_no_pipe() {
    let (_, stderr, code) = run(&[]);
    assert!(
        code == 2 || code == 0,
        "code was {}, stderr: {}",
        code,
        stderr
    );
}

#[test]
fn unknown_flag_error() {
    let (_, _, code) = run(&["--banana"]);
    assert_eq!(code, 2);
}

// === Adversarial and Edge Cases ===

#[test]
fn empty_text() {
    let (stdout, _, code) = run(&["--text", ""]);
    assert_eq!(code, 0);
    assert_eq!(stdout, "");
}

#[test]
fn unicode_text() {
    let (stdout, _, code) = run(&["--text", "日本語テスト user@example.com résumé"]);
    assert_eq!(code, 0);
    assert!(stdout.contains("[REDACTED:EMAIL]"));
    assert!(stdout.contains("日本語テスト"));
    assert!(stdout.contains("résumé"));
}

#[test]
fn long_line_no_crash() {
    let long_line = "a".repeat(100_000);
    let (stdout, _, code) = run(&["--text", &long_line]);
    assert_eq!(code, 0);
    assert_eq!(stdout.len(), 100_000);
}

#[test]
fn multiple_secrets_same_line() {
    let (stdout, _, code) = run(&["--text", "user@a.com and user@b.com and 192.168.1.1"]);
    assert_eq!(code, 0);
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
    data[0] = 0x00;
    data[1] = 0xFF;
    fs::write(&binary_file, &data).unwrap();

    let (_, stderr, code) = run(&["--input", binary_file.to_str().unwrap()]);
    assert!(code == 0 || code == 1, "code: {}, stderr: {}", code, stderr);
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn binary_file_best_effort_single_file_processes_lossy_text() {
    let dir = temp_dir("binary_best_effort_file");
    let binary_file = dir.join("binary.dat");
    fs::write(&binary_file, b"token=sk_live_secret123\x00\xff").unwrap();

    let (stdout, stderr, code) = run(&[
        "--input",
        binary_file.to_str().unwrap(),
        "--binary",
        "best-effort",
    ]);
    assert_eq!(code, 0, "stderr: {}", stderr);
    assert!(stdout.contains("[REDACTED:STRIPE_KEY]"));
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn binary_file_best_effort_directory_not_error() {
    let dir = temp_dir("binary_best_effort_dir");
    let input_dir = dir.join("input");
    fs::create_dir_all(&input_dir).unwrap();
    fs::write(input_dir.join("a.bin"), b"token=sk_live_secret123\x00\xff").unwrap();

    let (_, stderr, code) = run(&[
        "--input",
        input_dir.to_str().unwrap(),
        "--binary",
        "best-effort",
        "--summary",
    ]);
    assert_eq!(code, 0, "stderr: {}", stderr);
    assert!(!stderr.contains("Error"));
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn private_key_block() {
    let text = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAn\n-----END RSA PRIVATE KEY-----";
    let (stdout, _, code) = run(&["--text", text]);
    assert_eq!(code, 0);
    assert!(stdout.contains("[REDACTED:PRIVATE_KEY]"));
    assert!(!stdout.contains("MIIEowIBAAKCAQEAn"));
}

#[test]
fn bearer_token() {
    let (stdout, _, code) = run(&[
        "--text",
        "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9",
    ]);
    assert_eq!(code, 0);
    assert!(stdout.contains("[REDACTED:"));
}

#[test]
fn password_assignment() {
    let (stdout, _, code) = run(&["--text", "password=supersecret123"]);
    assert_eq!(code, 0);
    assert!(stdout.contains("[REDACTED:PASSWORD]"));
    assert!(!stdout.contains("supersecret123"));
}

#[test]
fn reports_never_leak_full_secrets() {
    let (_, stderr, _) = run(&[
        "--text",
        "password=my_super_secret_password_value",
        "--report-json",
    ]);
    assert!(!stderr.contains("my_super_secret_password_value"));
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
    let (_, _, code) = run(&["--text", "clean"]);
    assert_eq!(code, 0);
}

#[test]
fn exit_code_3_findings_with_fail() {
    let (_, _, code) = run(&["--text", "user@example.com", "--fail-on-find"]);
    assert_eq!(code, 3);
}
