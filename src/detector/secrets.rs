use super::{Confidence, Detector, Finding};

// Purpose-built scanners for common secret patterns.
// Each scanner uses character-by-character matching to avoid regex DoS.
// No backtracking, bounded scan windows, O(n) per detector.

fn is_base64url(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'-' || c == b'_' || c == b'='
}

fn is_word_boundary(text: &[u8], pos: usize) -> bool {
    if pos == 0 || pos >= text.len() {
        return true;
    }
    let prev = text[pos - 1];
    !prev.is_ascii_alphanumeric() && prev != b'_'
}

fn find_prefix_case_insensitive(text: &[u8], start: usize, prefix: &[u8]) -> bool {
    if start + prefix.len() > text.len() {
        return false;
    }
    for (i, &expected) in prefix.iter().enumerate() {
        if text[start + i].to_ascii_lowercase() != expected.to_ascii_lowercase() {
            return false;
        }
    }
    true
}

fn scan_while(text: &[u8], start: usize, pred: fn(u8) -> bool, max_len: usize) -> usize {
    let mut end = start;
    let limit = std::cmp::min(text.len(), start + max_len);
    while end < limit && pred(text[end]) {
        end += 1;
    }
    end
}

// --- AWS Key Detector ---

pub struct AwsKeyDetector;

impl Detector for AwsKeyDetector {
    fn name(&self) -> &'static str {
        "AWS_KEY"
    }
    fn category(&self) -> &'static str {
        "secret"
    }

    fn detect(&self, text: &str) -> Vec<Finding> {
        let bytes = text.as_bytes();
        let mut findings = Vec::new();
        let prefixes: &[&[u8]] = &[b"AKIA", b"ABIA", b"ACCA", b"ASIA"];

        for i in 0..bytes.len().saturating_sub(19) {
            for prefix in prefixes {
                if bytes[i..].starts_with(prefix) && is_word_boundary(bytes, i) {
                    let end = i + 20;
                    if end <= bytes.len()
                        && bytes[i..end].iter().all(|c| c.is_ascii_alphanumeric())
                        && (end >= bytes.len() || !bytes[end].is_ascii_alphanumeric())
                    {
                        findings.push(Finding {
                            detector_name: self.name(),
                            category: self.category(),
                            start: i,
                            end,
                            confidence: Confidence::High,
                            matched_len: 20,
                        });
                    }
                }
            }
        }
        findings
    }
}

// --- Bearer Token Detector ---

pub struct BearerTokenDetector;

impl Detector for BearerTokenDetector {
    fn name(&self) -> &'static str {
        "BEARER_TOKEN"
    }
    fn category(&self) -> &'static str {
        "secret"
    }

    fn detect(&self, text: &str) -> Vec<Finding> {
        let bytes = text.as_bytes();
        let mut findings = Vec::new();
        let prefix = b"bearer ";
        let prefix_len = prefix.len();

        let mut i = 0;
        while i + prefix_len < bytes.len() {
            if find_prefix_case_insensitive(bytes, i, prefix) {
                let token_start = i + prefix_len;
                let token_end =
                    scan_while(bytes, token_start, |c| is_base64url(c) || c == b'.', 2048);
                let token_len = token_end - token_start;
                if token_len >= 20 {
                    findings.push(Finding {
                        detector_name: self.name(),
                        category: self.category(),
                        start: i,
                        end: token_end,
                        confidence: Confidence::High,
                        matched_len: token_end - i,
                    });
                    i = token_end;
                    continue;
                }
            }
            i += 1;
        }
        findings
    }
}

// --- JWT Detector ---

pub struct JwtDetector;

impl Detector for JwtDetector {
    fn name(&self) -> &'static str {
        "JWT"
    }
    fn category(&self) -> &'static str {
        "secret"
    }

    fn detect(&self, text: &str) -> Vec<Finding> {
        let bytes = text.as_bytes();
        let mut findings = Vec::new();
        let prefix = b"eyJ";

        let mut i = 0;
        while i + 3 < bytes.len() {
            if bytes[i..].starts_with(prefix) && is_word_boundary(bytes, i) {
                let mut dot_count = 0;
                let mut j = i;
                let limit = std::cmp::min(bytes.len(), i + 4096);
                while j < limit {
                    let c = bytes[j];
                    if is_base64url(c) {
                        j += 1;
                    } else if c == b'.' && dot_count < 2 {
                        dot_count += 1;
                        j += 1;
                    } else {
                        break;
                    }
                }
                if dot_count == 2 && (j - i) >= 36 {
                    findings.push(Finding {
                        detector_name: self.name(),
                        category: self.category(),
                        start: i,
                        end: j,
                        confidence: Confidence::High,
                        matched_len: j - i,
                    });
                    i = j;
                    continue;
                }
            }
            i += 1;
        }
        findings
    }
}

// --- Private Key Detector ---

pub struct PrivateKeyDetector;

impl Detector for PrivateKeyDetector {
    fn name(&self) -> &'static str {
        "PRIVATE_KEY"
    }
    fn category(&self) -> &'static str {
        "secret"
    }

    fn detect(&self, text: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        let begin_markers = [
            "-----BEGIN RSA PRIVATE KEY-----",
            "-----BEGIN PRIVATE KEY-----",
            "-----BEGIN EC PRIVATE KEY-----",
            "-----BEGIN OPENSSH PRIVATE KEY-----",
            "-----BEGIN DSA PRIVATE KEY-----",
            "-----BEGIN PGP PRIVATE KEY BLOCK-----",
        ];

        for marker in &begin_markers {
            let end_marker = marker.replace("BEGIN", "END");
            let mut search_start = 0;
            while let Some(start) = text[search_start..].find(marker) {
                let abs_start = search_start + start;
                if let Some(end_pos) = text[abs_start..].find(&end_marker) {
                    let abs_end = abs_start + end_pos + end_marker.len();
                    findings.push(Finding {
                        detector_name: self.name(),
                        category: self.category(),
                        start: abs_start,
                        end: abs_end,
                        confidence: Confidence::High,
                        matched_len: abs_end - abs_start,
                    });
                    search_start = abs_end;
                } else {
                    // Partial key block — still flag it
                    let abs_end = std::cmp::min(text.len(), abs_start + marker.len() + 200);
                    findings.push(Finding {
                        detector_name: self.name(),
                        category: self.category(),
                        start: abs_start,
                        end: abs_end,
                        confidence: Confidence::Medium,
                        matched_len: abs_end - abs_start,
                    });
                    search_start = abs_end;
                }
            }
        }
        findings
    }
}

// --- Generic API Key Detector ---
// Looks for key=value or key: value patterns where key contains api, key, secret, token

pub struct GenericApiKeyDetector;

impl Detector for GenericApiKeyDetector {
    fn name(&self) -> &'static str {
        "API_KEY"
    }
    fn category(&self) -> &'static str {
        "secret"
    }

    fn detect(&self, text: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        let keywords = ["api_key", "apikey", "api-key", "access_key", "secret_key"];

        for line in text.lines() {
            let lower = line.to_ascii_lowercase();
            for kw in &keywords {
                if let Some(kw_pos) = lower.find(kw) {
                    if let Some(finding) =
                        scan_key_value_pair(text, line, kw_pos, self.name(), self.category())
                    {
                        findings.push(finding);
                    }
                }
            }
        }
        findings
    }
}

// --- Database URL Detector ---

pub struct DatabaseUrlDetector;

impl Detector for DatabaseUrlDetector {
    fn name(&self) -> &'static str {
        "DATABASE_URL"
    }
    fn category(&self) -> &'static str {
        "secret"
    }

    fn detect(&self, text: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        let schemes = [
            "postgres://",
            "postgresql://",
            "mysql://",
            "mongodb://",
            "mongodb+srv://",
            "redis://",
            "rediss://",
            "amqp://",
            "amqps://",
        ];

        let mut search_start = 0;
        let lower = text.to_ascii_lowercase();
        loop {
            let mut earliest: Option<(usize, usize)> = None;
            for scheme in &schemes {
                if let Some(pos) = lower[search_start..].find(scheme) {
                    let abs = search_start + pos;
                    if earliest.is_none() || abs < earliest.unwrap().0 {
                        earliest = Some((abs, scheme.len()));
                    }
                }
            }
            match earliest {
                Some((start, _scheme_len)) => {
                    let end = scan_while(
                        text.as_bytes(),
                        start,
                        |c| !c.is_ascii_whitespace() && c != b'\'' && c != b'"' && c != b'`',
                        2048,
                    );
                    if end - start >= 15 {
                        // Check if URL contains credentials (user:pass@)
                        let url_text = &text[start..end];
                        let confidence = if url_text.contains('@') {
                            Confidence::High
                        } else {
                            Confidence::Medium
                        };
                        findings.push(Finding {
                            detector_name: self.name(),
                            category: self.category(),
                            start,
                            end,
                            confidence,
                            matched_len: end - start,
                        });
                    }
                    search_start = end;
                }
                None => break,
            }
        }
        findings
    }
}

// --- Password Assignment Detector ---

pub struct PasswordAssignDetector;

impl Detector for PasswordAssignDetector {
    fn name(&self) -> &'static str {
        "PASSWORD"
    }
    fn category(&self) -> &'static str {
        "secret"
    }

    fn detect(&self, text: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        let keywords = ["password", "passwd", "pass"];

        for line in text.lines() {
            let lower = line.to_ascii_lowercase();
            let mut matched = false;
            // Try longest keywords first to avoid substring double-match
            for kw in &keywords {
                if matched {
                    break;
                }
                if let Some(kw_pos) = lower.find(kw) {
                    if let Some(finding) =
                        scan_key_value_pair(text, line, kw_pos, self.name(), self.category())
                    {
                        findings.push(finding);
                        matched = true;
                    }
                }
            }
        }
        findings
    }
}

// --- Webhook Secret Detector ---

pub struct WebhookSecretDetector;

impl Detector for WebhookSecretDetector {
    fn name(&self) -> &'static str {
        "WEBHOOK_SECRET"
    }
    fn category(&self) -> &'static str {
        "secret"
    }

    fn detect(&self, text: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        let prefixes = ["whsec_", "whsk_"];

        for prefix in &prefixes {
            let mut start = 0;
            while let Some(pos) = text[start..].find(prefix) {
                let abs_start = start + pos;
                let bytes = text.as_bytes();
                let end = scan_while(bytes, abs_start + prefix.len(), is_base64url, 256);
                let total = end - abs_start;
                if total >= 20 {
                    findings.push(Finding {
                        detector_name: self.name(),
                        category: self.category(),
                        start: abs_start,
                        end,
                        confidence: Confidence::High,
                        matched_len: total,
                    });
                }
                start = end;
            }
        }
        findings
    }
}

// --- Slack Token Detector ---

pub struct SlackTokenDetector;

impl Detector for SlackTokenDetector {
    fn name(&self) -> &'static str {
        "SLACK_TOKEN"
    }
    fn category(&self) -> &'static str {
        "secret"
    }

    fn detect(&self, text: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        let prefixes = ["xoxb-", "xoxp-", "xoxs-", "xoxa-", "xoxo-", "xoxr-"];

        for prefix in &prefixes {
            let mut start = 0;
            while let Some(pos) = text[start..].find(prefix) {
                let abs_start = start + pos;
                let bytes = text.as_bytes();
                let end = scan_while(
                    bytes,
                    abs_start + prefix.len(),
                    |c| c.is_ascii_alphanumeric() || c == b'-',
                    256,
                );
                let total = end - abs_start;
                if total >= 15 {
                    findings.push(Finding {
                        detector_name: self.name(),
                        category: self.category(),
                        start: abs_start,
                        end,
                        confidence: Confidence::High,
                        matched_len: total,
                    });
                }
                start = end;
            }
        }
        findings
    }
}

// --- GitHub Token Detector ---

pub struct GithubTokenDetector;

impl Detector for GithubTokenDetector {
    fn name(&self) -> &'static str {
        "GITHUB_TOKEN"
    }
    fn category(&self) -> &'static str {
        "secret"
    }

    fn detect(&self, text: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        let prefixes = ["ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_"];

        for prefix in &prefixes {
            let mut start = 0;
            while let Some(pos) = text[start..].find(prefix) {
                let abs_start = start + pos;
                let bytes = text.as_bytes();
                let end = scan_while(
                    bytes,
                    abs_start + prefix.len(),
                    |c| c.is_ascii_alphanumeric() || c == b'_',
                    256,
                );
                let total = end - abs_start;
                if total >= 15 {
                    findings.push(Finding {
                        detector_name: self.name(),
                        category: self.category(),
                        start: abs_start,
                        end,
                        confidence: Confidence::High,
                        matched_len: total,
                    });
                }
                start = end;
            }
        }
        findings
    }
}

// --- Stripe Key Detector ---

pub struct StripeKeyDetector;

impl Detector for StripeKeyDetector {
    fn name(&self) -> &'static str {
        "STRIPE_KEY"
    }
    fn category(&self) -> &'static str {
        "secret"
    }

    fn detect(&self, text: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        let prefixes = [
            "sk_live_", "sk_test_", "pk_live_", "pk_test_", "rk_live_", "rk_test_",
        ];

        for prefix in &prefixes {
            let mut start = 0;
            while let Some(pos) = text[start..].find(prefix) {
                let abs_start = start + pos;
                let bytes = text.as_bytes();
                let end = scan_while(
                    bytes,
                    abs_start + prefix.len(),
                    |c| c.is_ascii_alphanumeric() || c == b'_',
                    256,
                );
                let total = end - abs_start;
                if total >= 15 {
                    findings.push(Finding {
                        detector_name: self.name(),
                        category: self.category(),
                        start: abs_start,
                        end,
                        confidence: Confidence::High,
                        matched_len: total,
                    });
                }
                start = end;
            }
        }
        findings
    }
}

// --- Generic Secret Assignment Detector ---
// Catches: SECRET=..., TOKEN=..., etc.

pub struct GenericSecretAssignDetector;

impl Detector for GenericSecretAssignDetector {
    fn name(&self) -> &'static str {
        "GENERIC_SECRET"
    }
    fn category(&self) -> &'static str {
        "secret"
    }

    fn detect(&self, text: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        let keywords = ["secret", "token", "credential", "auth_key"];

        for line in text.lines() {
            let lower = line.to_ascii_lowercase();
            for kw in &keywords {
                if let Some(kw_pos) = lower.find(kw) {
                    // Avoid matching "secret" inside words like "secretary"
                    let after = kw_pos + kw.len();
                    if after < lower.len() {
                        let next_char = lower.as_bytes()[after];
                        if next_char.is_ascii_alphabetic()
                            && next_char != b'_'
                            && next_char != b'-'
                            && next_char != b'='
                            && next_char != b':'
                            && next_char != b' '
                        {
                            continue;
                        }
                    }
                    if let Some(finding) =
                        scan_key_value_pair(text, line, kw_pos, self.name(), self.category())
                    {
                        findings.push(finding);
                    }
                }
            }
        }
        findings
    }
}

// --- Shared helper: scan key=value or key: value patterns ---

fn scan_key_value_pair(
    full_text: &str,
    line: &str,
    kw_pos: usize,
    detector_name: &'static str,
    category: &'static str,
) -> Option<Finding> {
    let after_kw = &line[kw_pos..];
    // Find the separator: =, :, or whitespace-separated
    let sep_idx = after_kw.find(['=', ':']);
    let sep_idx = match sep_idx {
        Some(idx) => idx,
        None => return None,
    };

    let value_start_in_line = kw_pos + sep_idx + 1;
    if value_start_in_line >= line.len() {
        return None;
    }

    let value_part = line[value_start_in_line..].trim_start();
    if value_part.is_empty() {
        return None;
    }

    // Strip optional quotes
    let (value, _quoted) = if value_part.starts_with('"') || value_part.starts_with('\'') {
        let quote = value_part.as_bytes()[0];
        if let Some(end) = value_part[1..].find(|c: char| c as u8 == quote) {
            (&value_part[1..1 + end], true)
        } else {
            (value_part.trim(), false)
        }
    } else {
        // Take until whitespace, comma, semicolon
        let end = value_part
            .find(|c: char| c.is_ascii_whitespace() || c == ',' || c == ';' || c == '#')
            .unwrap_or(value_part.len());
        (&value_part[..end], false)
    };

    if value.len() < 4 {
        return None;
    }

    // Find absolute position in full_text
    let line_offset = line.as_ptr() as usize - full_text.as_ptr() as usize;
    let value_offset = value.as_ptr() as usize - full_text.as_ptr() as usize;
    let abs_start = line_offset + kw_pos;
    let abs_end = value_offset + value.len();

    Some(Finding {
        detector_name,
        category,
        start: abs_start,
        end: abs_end,
        confidence: Confidence::Medium,
        matched_len: abs_end - abs_start,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_aws_key() {
        let d = AwsKeyDetector;
        let text = "key=AKIAIOSFODNN7EXAMPLE rest";
        let findings = d.detect(text);
        assert_eq!(findings.len(), 1);
        assert_eq!(
            &text[findings[0].start..findings[0].end],
            "AKIAIOSFODNN7EXAMPLE"
        );
    }

    #[test]
    fn detect_bearer_token() {
        let d = BearerTokenDetector;
        let text = "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.test_payload.sig";
        let findings = d.detect(text);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].confidence, Confidence::High);
    }

    #[test]
    fn detect_jwt() {
        let d = JwtDetector;
        let text = "token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";
        let findings = d.detect(text);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].confidence, Confidence::High);
    }

    #[test]
    fn detect_private_key() {
        let d = PrivateKeyDetector;
        let text = "-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n-----END RSA PRIVATE KEY-----";
        let findings = d.detect(text);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn detect_database_url() {
        let d = DatabaseUrlDetector;
        let text = "DATABASE_URL=postgres://user:pass@host:5432/db";
        let findings = d.detect(text);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].confidence, Confidence::High);
    }

    #[test]
    fn detect_stripe_key() {
        let d = StripeKeyDetector;
        let text = "STRIPE_KEY=sk_live_abcdef1234567890";
        let findings = d.detect(text);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn detect_github_token() {
        let d = GithubTokenDetector;
        let text = "token: ghp_abcdefghijklmnop1234567890abcd";
        let findings = d.detect(text);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn detect_slack_token() {
        let d = SlackTokenDetector;
        let text = "SLACK_TOKEN=xoxb-1234-5678-abcdefghijkl";
        let findings = d.detect(text);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn detect_password_assignment() {
        let d = PasswordAssignDetector;
        let text = "password=hunter2";
        let findings = d.detect(text);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn detect_generic_secret() {
        let d = GenericSecretAssignDetector;
        let text = "MY_SECRET=abcdef123456";
        let findings = d.detect(text);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn no_false_positive_secretary() {
        let d = GenericSecretAssignDetector;
        let text = "The secretary went home.";
        let findings = d.detect(text);
        assert_eq!(findings.len(), 0);
    }

    #[test]
    fn detect_webhook_secret() {
        let d = WebhookSecretDetector;
        let text = "webhook=whsec_abcdefghijklmnopqrstuvwxyz";
        let findings = d.detect(text);
        assert_eq!(findings.len(), 1);
    }
}
