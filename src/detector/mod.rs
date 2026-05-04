pub mod custom;
pub mod pii;
pub mod secrets;

/// Confidence level for a detection match.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[allow(dead_code)]
pub enum Confidence {
    Low,
    Medium,
    High,
}

impl Confidence {
    pub fn as_str(&self) -> &'static str {
        match self {
            Confidence::Low => "low",
            Confidence::Medium => "medium",
            Confidence::High => "high",
        }
    }
}

impl std::fmt::Display for Confidence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A single finding within text.
#[derive(Debug, Clone)]
pub struct Finding {
    pub detector_name: &'static str,
    pub category: &'static str,
    pub start: usize,
    pub end: usize,
    pub confidence: Confidence,
    #[allow(dead_code)]
    pub matched_len: usize,
}

impl Finding {
    pub fn masked_sample(&self, text: &str) -> String {
        let matched = &text[self.start..self.end];
        let len = matched.len();
        if len <= 4 {
            "*".repeat(len)
        } else {
            let visible = std::cmp::min(4, len / 4);
            let prefix: String = matched.chars().take(visible).collect();
            format!("{}***", prefix)
        }
    }
}

/// Trait for all detector implementations.
pub trait Detector: Send + Sync {
    fn name(&self) -> &'static str;
    fn category(&self) -> &'static str;
    fn detect(&self, text: &str) -> Vec<Finding>;
}

/// The registry holds all active detectors and runs them.
pub struct DetectorRegistry {
    detectors: Vec<Box<dyn Detector>>,
}

impl Default for DetectorRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl DetectorRegistry {
    pub fn new() -> Self {
        Self {
            detectors: Vec::new(),
        }
    }

    pub fn register(&mut self, detector: Box<dyn Detector>) {
        self.detectors.push(detector);
    }

    /// Build the default set of detectors, respecting allow/deny lists.
    pub fn build_default(
        allow: &[String],
        deny: &[String],
        custom_patterns: &[(String, String)],
    ) -> Self {
        let mut registry = Self::new();

        let all_builtins: Vec<Box<dyn Detector>> = vec![
            // Secrets
            Box::new(secrets::AwsKeyDetector),
            Box::new(secrets::BearerTokenDetector),
            Box::new(secrets::JwtDetector),
            Box::new(secrets::PrivateKeyDetector),
            Box::new(secrets::GenericApiKeyDetector),
            Box::new(secrets::DatabaseUrlDetector),
            Box::new(secrets::PasswordAssignDetector),
            Box::new(secrets::WebhookSecretDetector),
            Box::new(secrets::SlackTokenDetector),
            Box::new(secrets::GithubTokenDetector),
            Box::new(secrets::StripeKeyDetector),
            Box::new(secrets::GenericSecretAssignDetector),
            Box::new(secrets::HighEntropyKeywordDetector),
            // PII
            Box::new(pii::EmailDetector),
            Box::new(pii::PhoneDetector),
            Box::new(pii::Ipv4Detector),
            Box::new(pii::Ipv6Detector),
            Box::new(pii::CreditCardDetector),
            Box::new(pii::SsnDetector),
            Box::new(pii::PathDetector),
        ];

        for det in all_builtins {
            let name = det.name();
            if !allow.is_empty() && !allow.iter().any(|a| a == name) {
                continue;
            }
            if deny.iter().any(|d| d == name) {
                continue;
            }
            registry.register(det);
        }

        for (name, pattern) in custom_patterns {
            if let Some(det) = custom::CustomDetector::new(name.clone(), pattern.clone()) {
                registry.register(Box::new(det));
            }
        }

        registry
    }

    /// Run all detectors against text. Returns unmerged findings sorted by start position.
    pub fn detect_all_unmerged(&self, text: &str) -> Vec<Finding> {
        let mut findings: Vec<Finding> = Vec::new();
        for detector in &self.detectors {
            findings.extend(detector.detect(text));
        }
        findings.sort_by(|a, b| a.start.cmp(&b.start).then(b.end.cmp(&a.end)));
        findings
    }

    /// Run all detectors against text. Returns findings sorted by start position.
    /// Merges overlapping findings, keeping the higher-confidence one.
    pub fn detect_all(&self, text: &str) -> Vec<Finding> {
        merge_findings(self.detect_all_unmerged(text))
    }

    #[allow(dead_code)]
    pub fn detector_names(&self) -> Vec<&'static str> {
        self.detectors.iter().map(|d| d.name()).collect()
    }
}

/// Merge findings after sorting them by `start ASC, end DESC`.
/// Overlapping spans are unioned to avoid leaving partially exposed matches.
pub fn merge_findings(mut findings: Vec<Finding>) -> Vec<Finding> {
    if findings.is_empty() {
        return findings;
    }
    findings.sort_by(|a, b| a.start.cmp(&b.start).then(b.end.cmp(&a.end)));
    let mut merged: Vec<Finding> = Vec::with_capacity(findings.len());
    for f in findings {
        if let Some(last) = merged.last_mut() {
            if f.start < last.end {
                // Overlapping: expand the span to cover both findings (union),
                // and keep the strongest detector metadata for equal-confidence
                // overlaps. Redaction uses the union span, but metadata tie-breaks
                // use the original selected match length to avoid giving chained
                // unions an unfair size advantage.
                let union_start = std::cmp::min(last.start, f.start);
                let union_end = std::cmp::max(last.end, f.end);
                let last_specificity = detector_specificity_rank(last.detector_name);
                let new_specificity = detector_specificity_rank(f.detector_name);
                let prefer_new_metadata = f.confidence > last.confidence
                    || (f.confidence == last.confidence
                        && if new_specificity != last_specificity {
                            new_specificity > last_specificity
                        } else {
                            f.matched_len > last.matched_len
                        });
                if prefer_new_metadata {
                    last.detector_name = f.detector_name;
                    last.category = f.category;
                    last.confidence = f.confidence;
                    last.matched_len = f.matched_len;
                }
                last.start = union_start;
                last.end = union_end;
                continue;
            }
        }
        merged.push(f);
    }
    merged
}

fn detector_specificity_rank(detector_name: &str) -> u8 {
    match detector_name {
        "GENERIC_SECRET" => 0,
        "HIGH_ENTROPY_SECRET" => 1,
        "API_KEY" | "PASSWORD" | "SECRET" => 2,
        _ => 3,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FixedDetector {
        name: &'static str,
        category: &'static str,
        findings: Vec<Finding>,
    }

    impl Detector for FixedDetector {
        fn name(&self) -> &'static str {
            self.name
        }

        fn category(&self) -> &'static str {
            self.category
        }

        fn detect(&self, _text: &str) -> Vec<Finding> {
            self.findings.clone()
        }
    }

    #[test]
    fn masked_sample_short() {
        let finding = Finding {
            detector_name: "test",
            category: "test",
            start: 0,
            end: 3,
            confidence: Confidence::High,
            matched_len: 3,
        };
        assert_eq!(finding.masked_sample("abc"), "***");
    }

    #[test]
    fn masked_sample_long() {
        let finding = Finding {
            detector_name: "test",
            category: "test",
            start: 0,
            end: 20,
            confidence: Confidence::High,
            matched_len: 20,
        };
        let sample = finding.masked_sample("abcdefghijklmnopqrst");
        assert!(sample.starts_with("abcd"));
        assert!(sample.ends_with("***"));
    }

    #[test]
    fn merge_overlapping_uses_union_span_and_higher_confidence() {
        let findings = vec![
            Finding {
                detector_name: "a",
                category: "test",
                start: 0,
                end: 10,
                confidence: Confidence::Medium,
                matched_len: 10,
            },
            Finding {
                detector_name: "b",
                category: "test",
                start: 5,
                end: 15,
                confidence: Confidence::High,
                matched_len: 10,
            },
        ];
        let merged = merge_findings(findings);
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].detector_name, "b");
        // Span must be the union: 0..15, not 5..15
        assert_eq!(merged[0].start, 0);
        assert_eq!(merged[0].end, 15);
    }

    #[test]
    fn merge_findings_sorts_unsorted_input() {
        let findings = vec![
            Finding {
                detector_name: "SECOND",
                category: "test",
                start: 5,
                end: 15,
                confidence: Confidence::High,
                matched_len: 10,
            },
            Finding {
                detector_name: "FIRST",
                category: "test",
                start: 0,
                end: 10,
                confidence: Confidence::Medium,
                matched_len: 10,
            },
        ];

        let merged = merge_findings(findings);
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].detector_name, "SECOND");
        assert_eq!(merged[0].start, 0);
        assert_eq!(merged[0].end, 15);
    }

    #[test]
    fn merge_overlapping_never_shrinks_span() {
        // Higher-confidence finding is strictly inside the lower one
        let findings = vec![
            Finding {
                detector_name: "wide",
                category: "test",
                start: 0,
                end: 20,
                confidence: Confidence::Medium,
                matched_len: 20,
            },
            Finding {
                detector_name: "narrow",
                category: "test",
                start: 5,
                end: 10,
                confidence: Confidence::High,
                matched_len: 5,
            },
        ];
        let merged = merge_findings(findings);
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].detector_name, "narrow");
        // Must keep the wider span to avoid leaking the uncovered prefix/suffix
        assert_eq!(merged[0].start, 0);
        assert_eq!(merged[0].end, 20);
    }

    #[test]
    fn merge_overlapping_equal_confidence_prefers_specific_detector_name() {
        let findings = vec![
            Finding {
                detector_name: "HIGH_ENTROPY_SECRET",
                category: "secret",
                start: 0,
                end: 40,
                confidence: Confidence::Medium,
                matched_len: 40,
            },
            Finding {
                detector_name: "GENERIC_SECRET",
                category: "secret",
                start: 7,
                end: 40,
                confidence: Confidence::Medium,
                matched_len: 33,
            },
        ];
        let merged = merge_findings(findings);
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].detector_name, "HIGH_ENTROPY_SECRET");
        assert_eq!(merged[0].start, 0);
        assert_eq!(merged[0].end, 40);
    }

    #[test]
    fn merge_overlapping_equal_confidence_keeps_specific_secret_over_generic_submatch() {
        let findings = vec![
            Finding {
                detector_name: "AWS_KEY",
                category: "secret",
                start: 0,
                end: 20,
                confidence: Confidence::High,
                matched_len: 20,
            },
            Finding {
                detector_name: "GENERIC_SECRET",
                category: "secret",
                start: 5,
                end: 18,
                confidence: Confidence::High,
                matched_len: 13,
            },
        ];
        let merged = merge_findings(findings);
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].detector_name, "AWS_KEY");
        assert_eq!(merged[0].start, 0);
        assert_eq!(merged[0].end, 20);
    }

    #[test]
    fn merge_overlapping_cross_category_still_prefers_longer_span() {
        let findings = vec![
            Finding {
                detector_name: "GENERIC_SECRET",
                category: "secret",
                start: 0,
                end: 8,
                confidence: Confidence::Medium,
                matched_len: 8,
            },
            Finding {
                detector_name: "EMAIL",
                category: "pii",
                start: 2,
                end: 20,
                confidence: Confidence::Medium,
                matched_len: 18,
            },
        ];
        let merged = merge_findings(findings);
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].detector_name, "EMAIL");
        assert_eq!(merged[0].start, 0);
        assert_eq!(merged[0].end, 20);
    }

    #[test]
    fn merge_overlapping_cross_category_prefers_specific_detector_metadata() {
        let findings = vec![
            Finding {
                detector_name: "SECRET",
                category: "secret",
                start: 0,
                end: 24,
                confidence: Confidence::Medium,
                matched_len: 24,
            },
            Finding {
                detector_name: "EMAIL",
                category: "pii",
                start: 5,
                end: 21,
                confidence: Confidence::Medium,
                matched_len: 16,
            },
        ];
        let merged = merge_findings(findings);
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].detector_name, "EMAIL");
        assert_eq!(merged[0].start, 0);
        assert_eq!(merged[0].end, 24);
    }

    #[test]
    fn merge_overlapping_equal_confidence_partial_overlap_keeps_longer_detector_name() {
        let findings = vec![
            Finding {
                detector_name: "FIRST",
                category: "secret",
                start: 0,
                end: 12,
                confidence: Confidence::Medium,
                matched_len: 12,
            },
            Finding {
                detector_name: "SECOND",
                category: "secret",
                start: 8,
                end: 24,
                confidence: Confidence::Medium,
                matched_len: 16,
            },
        ];
        let merged = merge_findings(findings);
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].detector_name, "SECOND");
        assert_eq!(merged[0].start, 0);
        assert_eq!(merged[0].end, 24);
    }

    #[test]
    fn merge_overlapping_chained_metadata_uses_original_match_lengths() {
        let findings = vec![
            Finding {
                detector_name: "FIRST",
                category: "pii",
                start: 0,
                end: 10,
                confidence: Confidence::Medium,
                matched_len: 10,
            },
            Finding {
                detector_name: "SECOND",
                category: "pii",
                start: 8,
                end: 20,
                confidence: Confidence::Medium,
                matched_len: 12,
            },
            Finding {
                detector_name: "THIRD",
                category: "pii",
                start: 19,
                end: 35,
                confidence: Confidence::Medium,
                matched_len: 16,
            },
        ];

        let merged = merge_findings(findings);
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].detector_name, "THIRD");
        assert_eq!(merged[0].start, 0);
        assert_eq!(merged[0].end, 35);
    }

    #[test]
    fn detector_registry_allow_deny() {
        let registry = DetectorRegistry::build_default(&["EMAIL".to_string()], &[], &[]);
        let names = registry.detector_names();
        assert_eq!(names, vec!["EMAIL"]);
    }

    #[test]
    fn detector_registry_can_return_unmerged_findings() {
        let mut registry = DetectorRegistry::new();
        registry.register(Box::new(FixedDetector {
            name: "fixed",
            category: "test",
            findings: vec![
                Finding {
                    detector_name: "FIRST",
                    category: "test",
                    start: 0,
                    end: 10,
                    confidence: Confidence::Medium,
                    matched_len: 10,
                },
                Finding {
                    detector_name: "SECOND",
                    category: "test",
                    start: 5,
                    end: 15,
                    confidence: Confidence::Medium,
                    matched_len: 10,
                },
            ],
        }));

        let unmerged = registry.detect_all_unmerged("0123456789012345");
        assert_eq!(unmerged.len(), 2);

        let merged = registry.detect_all("0123456789012345");
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].start, 0);
        assert_eq!(merged[0].end, 15);
    }
}
