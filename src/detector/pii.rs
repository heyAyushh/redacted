use super::{Confidence, Detector, Finding};

// Purpose-built scanners for PII patterns.
// Each scanner uses linear-time character matching. No regex.

pub struct EmailDetector;

impl Detector for EmailDetector {
    fn name(&self) -> &'static str {
        "EMAIL"
    }
    fn category(&self) -> &'static str {
        "pii"
    }

    fn detect(&self, text: &str) -> Vec<Finding> {
        let bytes = text.as_bytes();
        let mut findings = Vec::new();

        for i in 0..bytes.len() {
            if bytes[i] == b'@' && i > 0 && i + 1 < bytes.len() {
                // Scan backwards for local part
                let local_start = scan_email_local_back(bytes, i);
                if local_start == i {
                    continue;
                }
                // Scan forward for domain
                let domain_end = scan_email_domain_forward(bytes, i + 1);
                if domain_end == i + 1 {
                    continue;
                }

                // Validate: domain must have at least one dot
                let domain = &bytes[i + 1..domain_end];
                if !domain.contains(&b'.') {
                    continue;
                }
                // TLD must be at least 2 chars
                if let Some(last_dot) = domain.iter().rposition(|&c| c == b'.') {
                    if domain.len() - last_dot - 1 < 2 {
                        continue;
                    }
                }

                let email_len = domain_end - local_start;
                if (5..=320).contains(&email_len) {
                    findings.push(Finding {
                        detector_name: self.name(),
                        category: self.category(),
                        start: local_start,
                        end: domain_end,
                        confidence: Confidence::High,
                        matched_len: email_len,
                    });
                }
            }
        }
        findings
    }
}

fn scan_email_local_back(bytes: &[u8], at_pos: usize) -> usize {
    let mut pos = at_pos;
    while pos > 0 {
        let c = bytes[pos - 1];
        if c.is_ascii_alphanumeric() || c == b'.' || c == b'+' || c == b'-' || c == b'_' {
            pos -= 1;
        } else {
            break;
        }
    }
    pos
}

fn scan_email_domain_forward(bytes: &[u8], start: usize) -> usize {
    let mut pos = start;
    while pos < bytes.len() {
        let c = bytes[pos];
        if c.is_ascii_alphanumeric() || c == b'.' || c == b'-' {
            pos += 1;
        } else {
            break;
        }
    }
    // Trim trailing dots/hyphens
    while pos > start && (bytes[pos - 1] == b'.' || bytes[pos - 1] == b'-') {
        pos -= 1;
    }
    pos
}

// --- Phone Detector ---

pub struct PhoneDetector;

impl Detector for PhoneDetector {
    fn name(&self) -> &'static str {
        "PHONE"
    }
    fn category(&self) -> &'static str {
        "pii"
    }

    fn detect(&self, text: &str) -> Vec<Finding> {
        let bytes = text.as_bytes();
        let mut findings = Vec::new();

        let mut i = 0;
        while i < bytes.len() {
            if (bytes[i] == b'+' || bytes[i] == b'(' || bytes[i].is_ascii_digit())
                && (i == 0 || !bytes[i - 1].is_ascii_alphanumeric())
            {
                let (end, digit_count) = scan_phone(bytes, i);
                if (7..=15).contains(&digit_count) && (end - i) >= 7 {
                    let matched = &bytes[i..end];
                    // Reject if it looks like an IP address (digits separated only by dots)
                    if !looks_like_ip(matched) {
                        findings.push(Finding {
                            detector_name: self.name(),
                            category: self.category(),
                            start: i,
                            end,
                            confidence: if digit_count >= 10 {
                                Confidence::High
                            } else {
                                Confidence::Medium
                            },
                            matched_len: end - i,
                        });
                        i = end;
                        continue;
                    }
                }
            }
            i += 1;
        }
        findings
    }
}

fn looks_like_ip(bytes: &[u8]) -> bool {
    let dot_count = bytes.iter().filter(|&&b| b == b'.').count();
    if dot_count < 2 {
        return false;
    }
    // If separators are only dots (no spaces, dashes, parens), it's likely an IP
    let non_digit_non_dot = bytes
        .iter()
        .any(|&b| !b.is_ascii_digit() && b != b'.' && b != b'+');
    dot_count >= 2 && !non_digit_non_dot
}

fn scan_phone(bytes: &[u8], start: usize) -> (usize, usize) {
    let mut pos = start;
    let mut digit_count = 0;
    let limit = std::cmp::min(bytes.len(), start + 30);

    while pos < limit {
        let c = bytes[pos];
        if c.is_ascii_digit() {
            digit_count += 1;
            pos += 1;
        } else if (c == b'+' && pos == start)
            || c == b' '
            || c == b'-'
            || c == b'.'
            || c == b'('
            || c == b')'
        {
            pos += 1;
        } else {
            break;
        }
    }

    // Trim trailing separators
    while pos > start && !bytes[pos - 1].is_ascii_digit() {
        pos -= 1;
    }
    (pos, digit_count)
}

// --- IPv4 Detector ---

pub struct Ipv4Detector;

impl Detector for Ipv4Detector {
    fn name(&self) -> &'static str {
        "IPV4"
    }
    fn category(&self) -> &'static str {
        "pii"
    }

    fn detect(&self, text: &str) -> Vec<Finding> {
        let bytes = text.as_bytes();
        let mut findings = Vec::new();

        let mut i = 0;
        while i < bytes.len() {
            if bytes[i].is_ascii_digit() && (i == 0 || !bytes[i - 1].is_ascii_alphanumeric()) {
                if let Some((end, valid)) = try_parse_ipv4(bytes, i) {
                    if valid && (end >= bytes.len() || !bytes[end].is_ascii_alphanumeric()) {
                        findings.push(Finding {
                            detector_name: self.name(),
                            category: self.category(),
                            start: i,
                            end,
                            confidence: Confidence::High,
                            matched_len: end - i,
                        });
                        i = end;
                        continue;
                    }
                }
            }
            i += 1;
        }
        findings
    }
}

fn try_parse_ipv4(bytes: &[u8], start: usize) -> Option<(usize, bool)> {
    let mut pos = start;
    let mut octets = 0;

    for octet_idx in 0..4 {
        if pos >= bytes.len() || !bytes[pos].is_ascii_digit() {
            return None;
        }
        let num_start = pos;
        while pos < bytes.len() && bytes[pos].is_ascii_digit() {
            pos += 1;
        }
        let num_len = pos - num_start;
        if num_len == 0 || num_len > 3 {
            return None;
        }
        // Parse the number
        let mut val: u32 = 0;
        for &b in &bytes[num_start..pos] {
            val = val * 10 + (b - b'0') as u32;
        }
        if val > 255 {
            return None;
        }
        // Leading zeros check (0 is ok, 01 is not)
        if num_len > 1 && bytes[num_start] == b'0' {
            return None;
        }
        octets += 1;
        if octet_idx < 3 {
            if pos >= bytes.len() || bytes[pos] != b'.' {
                return None;
            }
            pos += 1; // skip dot
        }
    }

    if octets == 4 {
        Some((pos, true))
    } else {
        None
    }
}

// --- IPv6 Detector ---

pub struct Ipv6Detector;

impl Detector for Ipv6Detector {
    fn name(&self) -> &'static str {
        "IPV6"
    }
    fn category(&self) -> &'static str {
        "pii"
    }

    fn detect(&self, text: &str) -> Vec<Finding> {
        let bytes = text.as_bytes();
        let mut findings = Vec::new();

        let mut i = 0;
        while i + 2 < bytes.len() {
            // Look for hex digit followed by colon, or "::" pattern
            let is_ipv6_start = (bytes[i].is_ascii_hexdigit()
                && i + 1 < bytes.len()
                && (bytes[i + 1] == b':' || bytes[i + 1].is_ascii_hexdigit()))
                || (bytes[i] == b':' && i + 1 < bytes.len() && bytes[i + 1] == b':');

            if is_ipv6_start && (i == 0 || !bytes[i - 1].is_ascii_alphanumeric()) {
                if let Some(end) = try_scan_ipv6(bytes, i) {
                    if end - i >= 6 {
                        findings.push(Finding {
                            detector_name: self.name(),
                            category: self.category(),
                            start: i,
                            end,
                            confidence: Confidence::Medium,
                            matched_len: end - i,
                        });
                        i = end;
                        continue;
                    }
                }
            }
            i += 1;
        }
        findings
    }
}

fn try_scan_ipv6(bytes: &[u8], start: usize) -> Option<usize> {
    let mut pos = start;
    let mut groups = 0;
    let mut has_double_colon = false;
    let limit = std::cmp::min(bytes.len(), start + 45);

    while pos < limit && groups <= 8 {
        if pos + 1 < limit && bytes[pos] == b':' && bytes[pos + 1] == b':' {
            if has_double_colon {
                break;
            }
            has_double_colon = true;
            pos += 2;
            continue;
        }

        let hex_start = pos;
        while pos < limit && bytes[pos].is_ascii_hexdigit() && pos - hex_start < 4 {
            pos += 1;
        }
        if pos == hex_start {
            break;
        }
        groups += 1;

        if pos < limit && bytes[pos] == b':' && pos + 1 < limit && bytes[pos + 1] != b':' {
            pos += 1;
        } else {
            break;
        }
    }

    if groups >= 3 || (has_double_colon && groups >= 1) {
        // Ensure we don't end on a colon
        while pos > start && bytes[pos - 1] == b':' {
            pos -= 1;
        }
        Some(pos)
    } else {
        None
    }
}

// --- Credit Card Detector ---

pub struct CreditCardDetector;

impl Detector for CreditCardDetector {
    fn name(&self) -> &'static str {
        "CREDIT_CARD"
    }
    fn category(&self) -> &'static str {
        "pii"
    }

    fn detect(&self, text: &str) -> Vec<Finding> {
        let bytes = text.as_bytes();
        let mut findings = Vec::new();

        let mut i = 0;
        while i < bytes.len() {
            if bytes[i].is_ascii_digit() && (i == 0 || !bytes[i - 1].is_ascii_alphanumeric()) {
                let (end, digits) = scan_cc_number(bytes, i);
                if (13..=19).contains(&digits)
                    && (end >= bytes.len() || !bytes[end].is_ascii_alphanumeric())
                {
                    // Extract just the digits for Luhn check
                    let digit_vec: Vec<u8> = bytes[i..end]
                        .iter()
                        .filter(|c| c.is_ascii_digit())
                        .copied()
                        .collect();
                    if luhn_check(&digit_vec) {
                        findings.push(Finding {
                            detector_name: self.name(),
                            category: self.category(),
                            start: i,
                            end,
                            confidence: Confidence::High,
                            matched_len: end - i,
                        });
                        i = end;
                        continue;
                    }
                }
            }
            i += 1;
        }
        findings
    }
}

fn scan_cc_number(bytes: &[u8], start: usize) -> (usize, usize) {
    let mut pos = start;
    let mut digit_count = 0;
    let limit = std::cmp::min(bytes.len(), start + 25);

    while pos < limit {
        let c = bytes[pos];
        if c.is_ascii_digit() {
            digit_count += 1;
            pos += 1;
        } else if (c == b' ' || c == b'-') && digit_count > 0 {
            // Allow separators between groups
            pos += 1;
        } else {
            break;
        }
    }
    // Trim trailing non-digits
    while pos > start && !bytes[pos - 1].is_ascii_digit() {
        pos -= 1;
    }
    (pos, digit_count)
}

fn luhn_check(digits: &[u8]) -> bool {
    if digits.len() < 13 {
        return false;
    }
    let mut sum: u32 = 0;
    let mut double = false;

    for &d in digits.iter().rev() {
        let mut n = (d - b'0') as u32;
        if double {
            n *= 2;
            if n > 9 {
                n -= 9;
            }
        }
        sum += n;
        double = !double;
    }
    sum % 10 == 0
}

// --- SSN Detector ---

pub struct SsnDetector;

impl Detector for SsnDetector {
    fn name(&self) -> &'static str {
        "SSN"
    }
    fn category(&self) -> &'static str {
        "pii"
    }

    fn detect(&self, text: &str) -> Vec<Finding> {
        let bytes = text.as_bytes();
        let mut findings = Vec::new();

        // Pattern: NNN-NN-NNNN
        let mut i = 0;
        while i + 10 < bytes.len() {
            if bytes[i].is_ascii_digit()
                && (i == 0 || !bytes[i - 1].is_ascii_alphanumeric())
                && matches_ssn_pattern(bytes, i)
            {
                let end = i + 11;
                if end >= bytes.len() || !bytes[end].is_ascii_digit() {
                    findings.push(Finding {
                        detector_name: self.name(),
                        category: self.category(),
                        start: i,
                        end,
                        confidence: Confidence::High,
                        matched_len: 11,
                    });
                    i = end;
                    continue;
                }
            }
            i += 1;
        }
        findings
    }
}

fn matches_ssn_pattern(bytes: &[u8], start: usize) -> bool {
    if start + 11 > bytes.len() {
        return false;
    }
    let b = &bytes[start..start + 11];
    b[0].is_ascii_digit()
        && b[1].is_ascii_digit()
        && b[2].is_ascii_digit()
        && b[3] == b'-'
        && b[4].is_ascii_digit()
        && b[5].is_ascii_digit()
        && b[6] == b'-'
        && b[7].is_ascii_digit()
        && b[8].is_ascii_digit()
        && b[9].is_ascii_digit()
        && b[10].is_ascii_digit()
        // SSN validation: area cannot be 000, 666, or 900-999
        && !(b[0] == b'0' && b[1] == b'0' && b[2] == b'0')
        && !(b[0] == b'6' && b[1] == b'6' && b[2] == b'6')
        && b[0] != b'9'
        // Group cannot be 00
        && !(b[4] == b'0' && b[5] == b'0')
        // Serial cannot be 0000
        && !(b[7] == b'0' && b[8] == b'0' && b[9] == b'0' && b[10] == b'0')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_email() {
        let d = EmailDetector;
        let findings = d.detect("contact user@example.com for help");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].start, 8);
    }

    #[test]
    fn no_false_email_no_tld() {
        let d = EmailDetector;
        let findings = d.detect("user@localhost");
        assert_eq!(findings.len(), 0);
    }

    #[test]
    fn detect_phone_us() {
        let d = PhoneDetector;
        let findings = d.detect("call +1-555-867-5309 now");
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn detect_phone_intl() {
        let d = PhoneDetector;
        let findings = d.detect("phone: +44 20 7946 0958");
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn detect_ipv4() {
        let d = Ipv4Detector;
        let findings = d.detect("server at 192.168.1.100 ready");
        assert_eq!(findings.len(), 1);
        assert_eq!(
            &"server at 192.168.1.100 ready"[findings[0].start..findings[0].end],
            "192.168.1.100"
        );
    }

    #[test]
    fn no_false_ipv4_overflow() {
        let d = Ipv4Detector;
        let findings = d.detect("version 300.1.2.3");
        assert_eq!(findings.len(), 0);
    }

    #[test]
    fn detect_ipv6() {
        let d = Ipv6Detector;
        let findings = d.detect("addr: 2001:0db8:85a3:0000:0000:8a2e:0370:7334");
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn detect_credit_card_visa() {
        let d = CreditCardDetector;
        let findings = d.detect("card: 4111 1111 1111 1111");
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn detect_credit_card_with_dashes() {
        let d = CreditCardDetector;
        let findings = d.detect("cc: 4111-1111-1111-1111");
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn no_false_cc_bad_luhn() {
        let d = CreditCardDetector;
        let findings = d.detect("num: 1234567890123456");
        assert_eq!(findings.len(), 0);
    }

    #[test]
    fn detect_ssn() {
        let d = SsnDetector;
        let findings = d.detect("ssn: 123-45-6789");
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn no_false_ssn_invalid() {
        let d = SsnDetector;
        // Area 000 is invalid
        let findings = d.detect("num: 000-45-6789");
        assert_eq!(findings.len(), 0);
    }

    #[test]
    fn luhn_valid() {
        assert!(luhn_check(b"4111111111111111"));
        assert!(luhn_check(b"5500000000000004"));
    }

    #[test]
    fn luhn_invalid() {
        assert!(!luhn_check(b"1234567890123456"));
    }
}
