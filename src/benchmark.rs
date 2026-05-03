use crate::cli::{print_benchmark_help, BenchmarkArgs, OutputFormat};
use crate::errors::{RedactError, Result, EXIT_SUCCESS};
use crate::text_utils::previous_char_boundary;
use crate::{app_paths::yes_or_no, io_safe, json::json_escape};
use std::path::Path;
use std::process::Command;
use std::time::Instant;

#[derive(Debug, Clone)]
struct IterationMetrics {
    iteration: usize,
    elapsed_ms: u128,
    files_processed: u64,
    files_skipped: u64,
    files_errored: u64,
    total_findings: u64,
}

pub fn run_benchmark_command(args: &BenchmarkArgs) -> Result<i32> {
    if args.help {
        print_benchmark_help();
        return Ok(EXIT_SUCCESS);
    }

    let input = args.input.as_ref().ok_or_else(|| {
        RedactError::Usage(
            "Benchmark requires --input <PATH>.\n  redacted benchmark --input logs/".into(),
        )
    })?;
    let input_path = Path::new(input);
    if !input_path.exists() {
        return Err(RedactError::Usage(format!(
            "Benchmark input '{}' does not exist.\n  redacted benchmark --input <PATH>",
            input
        )));
    }

    let mut iterations = Vec::new();
    for iteration in 1..=args.iterations {
        iterations.push(run_single_iteration(args, iteration)?);
    }

    match args.format {
        OutputFormat::Text => io_safe::write_stdout(&render_text_report(input, args, &iterations))?,
        OutputFormat::Json => io_safe::write_stdout(&render_json_report(input, args, &iterations))?,
    }

    Ok(EXIT_SUCCESS)
}

fn run_single_iteration(args: &BenchmarkArgs, iteration: usize) -> Result<IterationMetrics> {
    let current_exe = std::env::current_exe().map_err(|error| {
        RedactError::Config(format!("Cannot determine executable path: {}", error))
    })?;
    let input = args.input.as_ref().ok_or_else(|| {
        RedactError::Usage(
            "Benchmark requires --input <PATH>.\n  redacted benchmark --input logs/".into(),
        )
    })?;

    let mut command = Command::new(current_exe);
    command
        .arg("--input")
        .arg(input)
        .arg("--dry-run")
        .arg("--format")
        .arg("json");
    if args.privacy_filter {
        command.arg("--privacy-filter");
    }
    if args.document_adapter {
        command.arg("--document-adapter");
    }

    let started = Instant::now();
    let output = command.output().map_err(|error| {
        RedactError::Detection(format!(
            "Failed to execute benchmark iteration {}: {}",
            iteration, error
        ))
    })?;
    let elapsed_ms = started.elapsed().as_millis();

    let stdout = String::from_utf8(output.stdout).map_err(|_| {
        RedactError::Detection(format!(
            "Benchmark iteration {} returned invalid UTF-8 JSON output.",
            iteration
        ))
    })?;

    let metrics = IterationMetrics {
        iteration,
        elapsed_ms,
        files_processed: parse_summary_field(&stdout, "files_processed")?,
        files_skipped: parse_summary_field(&stdout, "files_skipped")?,
        files_errored: parse_summary_field(&stdout, "files_errored")?,
        total_findings: parse_summary_field(&stdout, "total_findings")?,
    };

    if !output.status.success() && metrics.files_processed == 0 && metrics.files_errored == 0 {
        let code = output.status.code().unwrap_or(-1);
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(RedactError::Detection(format!(
            "Benchmark iteration {} failed with exit code {}.\n{}",
            iteration,
            code,
            truncate_message(&stderr, 400)
        )));
    }

    Ok(metrics)
}

fn parse_summary_field(json: &str, field: &str) -> Result<u64> {
    let summary = summary_object(json)?;
    let needle = format!("\"{}\":", field);
    let position = summary.find(&needle).ok_or_else(|| {
        RedactError::Detection(format!(
            "Benchmark output is missing summary field '{}'.",
            field
        ))
    })?;
    let mut number = String::new();
    for character in summary[position + needle.len()..].chars() {
        if character.is_ascii_digit() {
            number.push(character);
        } else if number.is_empty() && character.is_ascii_whitespace() {
            continue;
        } else {
            break;
        }
    }
    if number.is_empty() {
        return Err(RedactError::Detection(format!(
            "Benchmark summary field '{}' is not numeric.",
            field
        )));
    }
    number.parse::<u64>().map_err(|_| {
        RedactError::Detection(format!(
            "Benchmark summary field '{}' has invalid value '{}'.",
            field, number
        ))
    })
}

fn summary_object(json: &str) -> Result<&str> {
    let object_start = find_top_level_object_field(json, "summary")?;
    let object_end = matching_object_end(json, object_start)?;
    Ok(&json[object_start..=object_end])
}

fn find_top_level_object_field(json: &str, field: &str) -> Result<usize> {
    let bytes = json.as_bytes();
    let mut position = skip_json_whitespace(bytes, 0);
    if bytes.get(position) != Some(&b'{') {
        return Err(RedactError::Detection(
            "Benchmark output is not a JSON object.".into(),
        ));
    }
    position += 1;
    loop {
        position = skip_json_whitespace(bytes, position);
        if bytes.get(position) == Some(&b'}') {
            break;
        }
        if bytes.get(position) != Some(&b'"') {
            return Err(RedactError::Detection(
                "Benchmark output has invalid object key.".into(),
            ));
        }
        let key_start = position + 1;
        let key_end = string_literal_end(json, position)?;
        let key = &json[key_start..key_end];
        position = skip_json_whitespace(bytes, key_end + 1);
        if bytes.get(position) != Some(&b':') {
            return Err(RedactError::Detection(
                "Benchmark output object key is missing ':'.".into(),
            ));
        }
        position = skip_json_whitespace(bytes, position + 1);
        if key == field {
            if bytes.get(position) != Some(&b'{') {
                return Err(RedactError::Detection(
                    "Benchmark output summary is not an object.".into(),
                ));
            }
            return Ok(position);
        }
        position = skip_json_value(bytes, position)?;
        position = skip_json_whitespace(bytes, position);
        match bytes.get(position) {
            Some(b',') => position += 1,
            Some(b'}') => break,
            _ => {
                return Err(RedactError::Detection(
                    "Benchmark output object is malformed.".into(),
                ));
            }
        }
    }
    Err(RedactError::Detection(
        "Benchmark output is missing summary object.".into(),
    ))
}

fn matching_object_end(json: &str, object_start: usize) -> Result<usize> {
    let bytes = json.as_bytes();
    let mut depth = 0usize;
    let mut in_string = false;
    let mut escaped = false;
    for (offset, byte) in bytes[object_start..].iter().enumerate() {
        if in_string {
            if escaped {
                escaped = false;
                continue;
            }
            match byte {
                b'\\' => escaped = true,
                b'"' => in_string = false,
                _ => {}
            }
            continue;
        }

        match byte {
            b'"' => in_string = true,
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return Ok(object_start + offset);
                }
            }
            _ => {}
        }
    }
    Err(RedactError::Detection(
        "Benchmark output summary object is incomplete.".into(),
    ))
}

fn skip_json_value(bytes: &[u8], start: usize) -> Result<usize> {
    let mut position = start;
    let mut depth = 0usize;
    let mut in_string = false;
    let mut escaped = false;
    while position < bytes.len() {
        let byte = bytes[position];
        if in_string {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                in_string = false;
            }
            position += 1;
            continue;
        }
        match byte {
            b'"' => {
                in_string = true;
                position += 1;
            }
            b'{' | b'[' => {
                depth += 1;
                position += 1;
            }
            b'}' | b']' => {
                if depth == 0 {
                    return Ok(position);
                }
                depth -= 1;
                position += 1;
            }
            b',' if depth == 0 => return Ok(position),
            _ => position += 1,
        }
    }
    Ok(position)
}

fn string_literal_end(json: &str, start_quote: usize) -> Result<usize> {
    let bytes = json.as_bytes();
    let mut position = start_quote + 1;
    let mut escaped = false;
    while position < bytes.len() {
        let byte = bytes[position];
        if escaped {
            escaped = false;
        } else if byte == b'\\' {
            escaped = true;
        } else if byte == b'"' {
            return Ok(position);
        }
        position += 1;
    }
    Err(RedactError::Detection(
        "Benchmark output has unterminated string.".into(),
    ))
}

fn skip_json_whitespace(bytes: &[u8], mut position: usize) -> usize {
    while matches!(bytes.get(position), Some(b' ' | b'\n' | b'\r' | b'\t')) {
        position += 1;
    }
    position
}

fn render_text_report(
    input: &str,
    args: &BenchmarkArgs,
    iterations: &[IterationMetrics],
) -> String {
    let (min_ms, max_ms, avg_ms) = elapsed_statistics(iterations);
    let mut output = String::new();
    output.push_str("Benchmark report\n");
    output.push_str(&format!("input: {}\n", input));
    output.push_str(&format!("iterations: {}\n", iterations.len()));
    output.push_str(&format!(
        "privacy_filter: {}\ndocument_adapter: {}\n",
        yes_or_no(args.privacy_filter),
        yes_or_no(args.document_adapter)
    ));
    output.push_str("runs:\n");
    for metrics in iterations {
        output.push_str(&format!(
            "- #{:02}: {} ms, files_processed={}, files_skipped={}, files_errored={}, total_findings={}\n",
            metrics.iteration,
            metrics.elapsed_ms,
            metrics.files_processed,
            metrics.files_skipped,
            metrics.files_errored,
            metrics.total_findings
        ));
    }
    output.push_str("summary:\n");
    output.push_str(&format!("min_ms: {}\n", min_ms));
    output.push_str(&format!("max_ms: {}\n", max_ms));
    output.push_str(&format!("avg_ms: {:.2}\n", avg_ms));
    output
}

fn render_json_report(
    input: &str,
    args: &BenchmarkArgs,
    iterations: &[IterationMetrics],
) -> String {
    let (min_ms, max_ms, avg_ms) = elapsed_statistics(iterations);
    let mut output = String::new();
    output.push_str("{\n");
    output.push_str(&format!("  \"input\": \"{}\",\n", json_escape(input)));
    output.push_str(&format!("  \"iterations\": {},\n", iterations.len()));
    output.push_str(&format!(
        "  \"privacy_filter\": {},\n",
        if args.privacy_filter { "true" } else { "false" }
    ));
    output.push_str(&format!(
        "  \"document_adapter\": {},\n",
        if args.document_adapter {
            "true"
        } else {
            "false"
        }
    ));
    output.push_str("  \"runs\": [");
    for (index, metrics) in iterations.iter().enumerate() {
        if index > 0 {
            output.push(',');
        }
        output.push_str(&format!(
            "\n    {{\"iteration\":{},\"elapsed_ms\":{},\"files_processed\":{},\"files_skipped\":{},\"files_errored\":{},\"total_findings\":{}}}",
            metrics.iteration,
            metrics.elapsed_ms,
            metrics.files_processed,
            metrics.files_skipped,
            metrics.files_errored,
            metrics.total_findings
        ));
    }
    if !iterations.is_empty() {
        output.push('\n');
    }
    output.push_str("  ],\n");
    output.push_str(&format!(
        "  \"summary\": {{\"min_ms\":{},\"max_ms\":{},\"avg_ms\":{:.2}}}\n",
        min_ms, max_ms, avg_ms
    ));
    output.push_str("}\n");
    output
}

fn elapsed_statistics(iterations: &[IterationMetrics]) -> (u128, u128, f64) {
    let min_ms = iterations.iter().map(|m| m.elapsed_ms).min().unwrap_or(0);
    let max_ms = iterations.iter().map(|m| m.elapsed_ms).max().unwrap_or(0);
    let total_ms: u128 = iterations.iter().map(|m| m.elapsed_ms).sum();
    let avg_ms = if iterations.is_empty() {
        0.0
    } else {
        total_ms as f64 / iterations.len() as f64
    };
    (min_ms, max_ms, avg_ms)
}

fn truncate_message(message: &str, max_bytes: usize) -> String {
    if message.len() <= max_bytes {
        return message.trim().to_string();
    }
    let truncation_point = previous_char_boundary(message, max_bytes);
    let mut output = message[..truncation_point].trim().to_string();
    output.push_str("...");
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_summary_field_reads_number() {
        let json = r#"{"summary":{"files_processed":12,"files_skipped":1}}"#;
        assert_eq!(parse_summary_field(json, "files_processed").unwrap(), 12);
        assert_eq!(parse_summary_field(json, "files_skipped").unwrap(), 1);
    }

    #[test]
    fn parse_summary_field_ignores_matching_text_outside_summary() {
        let json =
            r#"{"files":[{"path":"\"files_processed\":999"}],"summary":{"files_processed":12}}"#;
        assert_eq!(parse_summary_field(json, "files_processed").unwrap(), 12);
    }

    #[test]
    fn summary_object_ignores_summary_text_inside_strings() {
        let json = r#"{"files":[{"path":"\"summary\":{\"files_processed\":999}"}],"summary":{"files_processed":12}}"#;
        assert_eq!(parse_summary_field(json, "files_processed").unwrap(), 12);
    }

    #[test]
    fn elapsed_statistics_handles_values() {
        let runs = vec![
            IterationMetrics {
                iteration: 1,
                elapsed_ms: 10,
                files_processed: 1,
                files_skipped: 0,
                files_errored: 0,
                total_findings: 1,
            },
            IterationMetrics {
                iteration: 2,
                elapsed_ms: 20,
                files_processed: 1,
                files_skipped: 0,
                files_errored: 0,
                total_findings: 1,
            },
        ];
        let (min_ms, max_ms, avg_ms) = elapsed_statistics(&runs);
        assert_eq!(min_ms, 10);
        assert_eq!(max_ms, 20);
        assert_eq!(avg_ms, 15.0);
    }

    #[test]
    fn truncate_message_keeps_utf8_boundaries() {
        let message = format!("{}é", "a".repeat(399));
        let truncated = truncate_message(&message, 400);
        assert_eq!(truncated, format!("{}...", "a".repeat(399)));
    }
}
