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
            // PII
            Box::new(pii::EmailDetector),
            Box::new(pii::PhoneDetector),
            Box::new(pii::Ipv4Detector),
            Box::new(pii::Ipv6Detector),
            Box::new(pii::CreditCardDetector),
            Box::new(pii::SsnDetector),
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

    /// Run all detectors against text. Returns findings sorted by start position.
    /// Merges overlapping findings, keeping the higher-confidence one.
    pub fn detect_all(&self, text: &str) -> Vec<Finding> {
        let mut findings: Vec<Finding> = Vec::new();
        for detector in &self.detectors {
            findings.extend(detector.detect(text));
        }
        findings.sort_by(|a, b| a.start.cmp(&b.start).then(b.end.cmp(&a.end)));
        merge_overlapping(findings)
    }

    #[allow(dead_code)]
    pub fn detector_names(&self) -> Vec<&'static str> {
        self.detectors.iter().map(|d| d.name()).collect()
    }
}

fn merge_overlapping(findings: Vec<Finding>) -> Vec<Finding> {
    if findings.is_empty() {
        return findings;
    }
    let mut merged: Vec<Finding> = Vec::with_capacity(findings.len());
    for f in findings {
        if let Some(last) = merged.last() {
            if f.start < last.end {
                // Overlapping: keep the one with higher confidence or longer match
                if f.confidence > last.confidence
                    || (f.confidence == last.confidence
                        && (f.end - f.start) > (last.end - last.start))
                {
                    let len = merged.len();
                    merged[len - 1] = f;
                }
                continue;
            }
        }
        merged.push(f);
    }
    merged
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn merge_overlapping_keeps_higher_confidence() {
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
        let merged = merge_overlapping(findings);
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].detector_name, "b");
    }

    #[test]
    fn detector_registry_allow_deny() {
        let registry = DetectorRegistry::build_default(&["EMAIL".to_string()], &[], &[]);
        let names = registry.detector_names();
        assert_eq!(names, vec!["EMAIL"]);
    }
}
