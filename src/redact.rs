use crate::detector::Finding;

/// Apply redactions to text based on findings.
/// Replaces each finding span with a redaction marker.
/// Findings must be sorted by start position and non-overlapping.
pub fn apply_redactions(
    text: &str,
    findings: &[Finding],
    custom_replacement: Option<&str>,
) -> String {
    if findings.is_empty() {
        return text.to_string();
    }

    let mut result = String::with_capacity(text.len());
    let mut last_end = 0;

    for finding in findings {
        if finding.start < last_end {
            continue; // Skip overlapping (should be pre-merged, but defensive)
        }
        if finding.start > last_end {
            result.push_str(&text[last_end..finding.start]);
        }
        match custom_replacement {
            Some(r) => result.push_str(r),
            None => {
                result.push_str("[REDACTED:");
                result.push_str(finding.detector_name);
                result.push(']');
            }
        }
        last_end = finding.end;
    }

    if last_end < text.len() {
        result.push_str(&text[last_end..]);
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detector::{Confidence, Finding};

    #[test]
    fn no_findings_returns_original() {
        assert_eq!(apply_redactions("hello world", &[], None), "hello world");
    }

    #[test]
    fn single_redaction() {
        let findings = vec![Finding {
            detector_name: "EMAIL",
            category: "pii",
            start: 6,
            end: 22,
            confidence: Confidence::High,
            matched_len: 16,
        }];
        let result = apply_redactions("email user@example.com here", &findings, None);
        assert_eq!(result, "email [REDACTED:EMAIL] here");
    }

    #[test]
    fn multiple_redactions() {
        let text = "user@a.com and user@b.com";
        let findings = vec![
            Finding {
                detector_name: "EMAIL",
                category: "pii",
                start: 0,
                end: 10,
                confidence: Confidence::High,
                matched_len: 10,
            },
            Finding {
                detector_name: "EMAIL",
                category: "pii",
                start: 15,
                end: 25,
                confidence: Confidence::High,
                matched_len: 10,
            },
        ];
        let result = apply_redactions(text, &findings, None);
        assert_eq!(result, "[REDACTED:EMAIL] and [REDACTED:EMAIL]");
    }

    #[test]
    fn custom_replacement() {
        let findings = vec![Finding {
            detector_name: "EMAIL",
            category: "pii",
            start: 0,
            end: 10,
            confidence: Confidence::High,
            matched_len: 10,
        }];
        let result = apply_redactions("user@a.com rest", &findings, Some("***"));
        assert_eq!(result, "*** rest");
    }

    #[test]
    fn overlapping_findings_handled() {
        let findings = vec![
            Finding {
                detector_name: "A",
                category: "test",
                start: 0,
                end: 10,
                confidence: Confidence::High,
                matched_len: 10,
            },
            Finding {
                detector_name: "B",
                category: "test",
                start: 5,
                end: 15,
                confidence: Confidence::High,
                matched_len: 10,
            },
        ];
        let text = "0123456789ABCDE";
        let result = apply_redactions(text, &findings, None);
        assert_eq!(result, "[REDACTED:A]ABCDE");
    }
}
