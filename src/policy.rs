use crate::detector::Finding;
use crate::except::ExceptRule;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FindingAction {
    Redact,
    Retain,
    Ignore,
}

#[derive(Debug, Clone)]
pub struct FindingDecision {
    pub finding: Finding,
    pub action: FindingAction,
}

pub fn decide_findings(
    text: &str,
    findings: Vec<Finding>,
    retain_detectors: &[String],
    retain_literals: &[String],
    except_detectors: &[String],
    except_literals: &[String],
    except_rules: &[ExceptRule],
) -> Vec<FindingDecision> {
    findings
        .into_iter()
        .map(|finding| {
            let action = decide_finding(
                text,
                &finding,
                retain_detectors,
                retain_literals,
                except_detectors,
                except_literals,
                except_rules,
            );
            FindingDecision { finding, action }
        })
        .collect()
}

fn decide_finding(
    text: &str,
    finding: &Finding,
    retain_detectors: &[String],
    retain_literals: &[String],
    except_detectors: &[String],
    except_literals: &[String],
    except_rules: &[ExceptRule],
) -> FindingAction {
    if except_detectors
        .iter()
        .any(|name| name == finding.detector_name)
    {
        return FindingAction::Ignore;
    }

    if retain_detectors
        .iter()
        .any(|name| name == finding.detector_name)
    {
        return FindingAction::Retain;
    }

    let matched = &text[finding.start..finding.end];

    if except_literals.iter().any(|literal| literal == matched) {
        return FindingAction::Ignore;
    }

    if retain_literals.iter().any(|literal| literal == matched) {
        return FindingAction::Retain;
    }

    for rule in except_rules {
        if rule_matches(rule, finding, matched) {
            return FindingAction::Retain;
        }
    }

    FindingAction::Redact
}

fn rule_matches(rule: &ExceptRule, finding: &Finding, matched: &str) -> bool {
    match rule {
        ExceptRule::RetainDetector(name) => name == finding.detector_name,
        ExceptRule::RetainLiteral(value) => value == matched,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detector::Confidence;

    fn finding(name: &'static str, start: usize, end: usize) -> Finding {
        Finding {
            detector_name: name,
            category: "secret",
            start,
            end,
            confidence: Confidence::High,
            matched_len: end - start,
        }
    }

    #[test]
    fn detector_retain_beats_default_redaction() {
        let decisions = decide_findings(
            "email: user@example.com",
            vec![finding("EMAIL", 7, 23)],
            &["EMAIL".into()],
            &[],
            &[],
            &[],
            &[],
        );
        assert_eq!(decisions[0].action, FindingAction::Retain);
    }

    #[test]
    fn literal_retain_beats_default_redaction() {
        let decisions = decide_findings(
            "email: user@example.com",
            vec![finding("EMAIL", 7, 23)],
            &[],
            &["user@example.com".into()],
            &[],
            &[],
            &[],
        );
        assert_eq!(decisions[0].action, FindingAction::Retain);
    }

    #[test]
    fn detector_ignore_excludes_finding() {
        let decisions = decide_findings(
            "email: user@example.com",
            vec![finding("EMAIL", 7, 23)],
            &[],
            &[],
            &["EMAIL".into()],
            &[],
            &[],
        );
        assert_eq!(decisions[0].action, FindingAction::Ignore);
    }
}
