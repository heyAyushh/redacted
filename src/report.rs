use crate::detector::{Confidence, Finding};
use std::io::{self, Write};

/// A processed file result for reporting.
#[derive(Debug)]
pub struct FileResult {
    pub path: String,
    pub findings_count: usize,
    pub findings: Vec<FindingReport>,
    pub status: FileStatus,
}

#[derive(Debug)]
pub enum FileStatus {
    Processed,
    Skipped(String),
    Error(String),
}

#[derive(Debug)]
pub struct FindingReport {
    pub detector: String,
    pub category: String,
    pub action: String,
    pub confidence: Confidence,
    pub masked_sample: String,
    pub line_number: Option<usize>,
}

/// Summary statistics.
#[derive(Debug, Default)]
pub struct Summary {
    pub files_processed: usize,
    pub files_skipped: usize,
    pub files_errored: usize,
    pub total_findings: usize,
    pub findings_by_type: Vec<(String, usize)>,
}

impl Summary {
    pub fn from_results(results: &[FileResult]) -> Self {
        let mut summary = Summary::default();
        let mut type_counts: Vec<(String, usize)> = Vec::new();

        for r in results {
            match &r.status {
                FileStatus::Processed => summary.files_processed += 1,
                FileStatus::Skipped(_) => summary.files_skipped += 1,
                FileStatus::Error(_) => summary.files_errored += 1,
            }
            summary.total_findings += r.findings_count;
            for f in &r.findings {
                if let Some(entry) = type_counts.iter_mut().find(|(name, _)| name == &f.detector) {
                    entry.1 += 1;
                } else {
                    type_counts.push((f.detector.clone(), 1));
                }
            }
        }
        type_counts.sort_by(|a, b| b.1.cmp(&a.1));
        summary.findings_by_type = type_counts;
        summary
    }
}

/// Print a human-readable summary to stderr.
pub fn print_summary(summary: &Summary) {
    let stderr = io::stderr();
    let mut h = stderr.lock();
    let _ = writeln!(h, "\n--- Redaction Summary ---");
    let _ = writeln!(h, "Files processed: {}", summary.files_processed);
    let _ = writeln!(h, "Files skipped:   {}", summary.files_skipped);
    let _ = writeln!(h, "Files errored:   {}", summary.files_errored);
    let _ = writeln!(h, "Total findings:  {}", summary.total_findings);
    if !summary.findings_by_type.is_empty() {
        let _ = writeln!(h, "Findings by type:");
        for (name, count) in &summary.findings_by_type {
            let _ = writeln!(h, "  {}: {}", name, count);
        }
    }
    let _ = writeln!(h, "-------------------------");
}

/// Write a JSON report to a writer. Hand-rolled JSON to avoid dependencies.
pub fn write_json_report<W: Write>(
    results: &[FileResult],
    summary: &Summary,
    mut w: W,
) -> io::Result<()> {
    w.write_all(b"{\n")?;

    // Summary
    w.write_all(b"  \"summary\": {\n")?;
    writeln!(w, "    \"files_processed\": {},", summary.files_processed)?;
    writeln!(w, "    \"files_skipped\": {},", summary.files_skipped)?;
    writeln!(w, "    \"files_errored\": {},", summary.files_errored)?;
    writeln!(w, "    \"total_findings\": {},", summary.total_findings)?;
    w.write_all(b"    \"findings_by_type\": {")?;
    for (i, (name, count)) in summary.findings_by_type.iter().enumerate() {
        if i > 0 {
            w.write_all(b",")?;
        }
        write!(w, "\n      \"{}\": {}", json_escape(name), count)?;
    }
    if !summary.findings_by_type.is_empty() {
        w.write_all(b"\n    ")?;
    }
    w.write_all(b"}\n  },\n")?;

    // Files
    w.write_all(b"  \"files\": [")?;
    for (i, r) in results.iter().enumerate() {
        if i > 0 {
            w.write_all(b",")?;
        }
        w.write_all(b"\n    {\n")?;
        writeln!(w, "      \"path\": \"{}\",", json_escape(&r.path))?;
        writeln!(
            w,
            "      \"status\": \"{}\",",
            match &r.status {
                FileStatus::Processed => "processed",
                FileStatus::Skipped(_) => "skipped",
                FileStatus::Error(_) => "error",
            }
        )?;

        if let FileStatus::Skipped(reason) | FileStatus::Error(reason) = &r.status {
            writeln!(w, "      \"reason\": \"{}\",", json_escape(reason))?;
        }

        writeln!(w, "      \"findings_count\": {},", r.findings_count)?;
        w.write_all(b"      \"findings\": [")?;

        for (j, f) in r.findings.iter().enumerate() {
            if j > 0 {
                w.write_all(b",")?;
            }
            w.write_all(b"\n        {\n")?;
            writeln!(
                w,
                "          \"detector\": \"{}\",",
                json_escape(&f.detector)
            )?;
            writeln!(
                w,
                "          \"category\": \"{}\",",
                json_escape(&f.category)
            )?;
            writeln!(w, "          \"action\": \"{}\",", json_escape(&f.action))?;
            writeln!(
                w,
                "          \"confidence\": \"{}\",",
                f.confidence.as_str()
            )?;
            write!(
                w,
                "          \"masked_sample\": \"{}\"",
                json_escape(&f.masked_sample)
            )?;
            if let Some(ln) = f.line_number {
                write!(w, ",\n          \"line\": {}", ln)?;
            }
            w.write_all(b"\n        }")?;
        }

        if !r.findings.is_empty() {
            w.write_all(b"\n      ")?;
        }
        w.write_all(b"]\n    }")?;
    }

    if !results.is_empty() {
        w.write_all(b"\n  ")?;
    }
    w.write_all(b"]\n}\n")?;

    Ok(())
}

fn json_escape(s: &str) -> String {
    let mut escaped = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => escaped.push_str("\\\""),
            '\\' => escaped.push_str("\\\\"),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                escaped.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => escaped.push(c),
        }
    }
    escaped
}

/// Compute line number for a byte offset within text.
pub fn line_number_for_offset(text: &str, offset: usize) -> usize {
    text[..offset].bytes().filter(|&b| b == b'\n').count() + 1
}

/// Build a FindingReport from a Finding and the source text.
pub fn finding_to_report(finding: &Finding, text: &str, action: &str) -> FindingReport {
    FindingReport {
        detector: finding.detector_name.to_string(),
        category: finding.category.to_string(),
        action: action.to_string(),
        confidence: finding.confidence,
        masked_sample: finding.masked_sample(text),
        line_number: Some(line_number_for_offset(text, finding.start)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_escape_special_chars() {
        assert_eq!(json_escape("a\"b"), "a\\\"b");
        assert_eq!(json_escape("a\\b"), "a\\\\b");
        assert_eq!(json_escape("a\nb"), "a\\nb");
    }

    #[test]
    fn line_number_calculation() {
        let text = "line1\nline2\nline3";
        assert_eq!(line_number_for_offset(text, 0), 1);
        assert_eq!(line_number_for_offset(text, 6), 2);
        assert_eq!(line_number_for_offset(text, 12), 3);
    }

    #[test]
    fn summary_from_results() {
        let results = vec![FileResult {
            path: "a.txt".into(),
            findings_count: 2,
            findings: vec![
                FindingReport {
                    detector: "EMAIL".into(),
                    category: "pii".into(),
                    action: "redact".into(),
                    confidence: Confidence::High,
                    masked_sample: "u***".into(),
                    line_number: Some(1),
                },
                FindingReport {
                    detector: "EMAIL".into(),
                    category: "pii".into(),
                    action: "redact".into(),
                    confidence: Confidence::High,
                    masked_sample: "x***".into(),
                    line_number: Some(2),
                },
            ],
            status: FileStatus::Processed,
        }];
        let summary = Summary::from_results(&results);
        assert_eq!(summary.files_processed, 1);
        assert_eq!(summary.total_findings, 2);
    }

    #[test]
    fn json_report_valid() {
        let results = vec![FileResult {
            path: "test.txt".into(),
            findings_count: 0,
            findings: vec![],
            status: FileStatus::Processed,
        }];
        let summary = Summary::from_results(&results);
        let mut buf = Vec::new();
        write_json_report(&results, &summary, &mut buf).unwrap();
        let json = String::from_utf8(buf).unwrap();
        assert!(json.contains("\"files_processed\": 1"));
    }
}
