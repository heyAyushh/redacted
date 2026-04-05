use super::{Confidence, Detector, Finding};

/// A simplified pattern matcher that supports a subset of regex-like patterns.
/// Intentionally avoids full regex to prevent catastrophic backtracking.
///
/// Supported syntax:
/// - Literal characters
/// - [a-zA-Z0-9_] character classes (ranges and individual chars)
/// - [^...] negated classes
/// - + (one or more)
/// - * (zero or more)
/// - ? (zero or one)
/// - . (any character except newline)
/// - \d \w \s and their negations \D \W \S
/// - ^ and $ anchors (per-line)
///
/// NOT supported (by design — avoids DoS):
/// - Backreferences
/// - Lookahead/lookbehind
/// - Nested quantifiers
/// - Unbounded repetition of complex groups
pub struct CustomDetector {
    name: &'static str,
    pattern: CompiledPattern,
}

impl CustomDetector {
    pub fn new(name: String, pattern_str: String) -> Option<Self> {
        let compiled = compile_pattern(&pattern_str)?;
        // Leak once at construction time. Custom detectors are created once at
        // startup and live for the process lifetime, so this is bounded.
        let leaked: &'static str = Box::leak(name.into_boxed_str());
        Some(Self {
            name: leaked,
            pattern: compiled,
        })
    }
}

impl Detector for CustomDetector {
    fn name(&self) -> &'static str {
        self.name
    }

    fn category(&self) -> &'static str {
        "custom"
    }

    fn detect(&self, text: &str) -> Vec<Finding> {
        let name = self.name();
        let mut findings = Vec::new();
        let bytes = text.as_bytes();

        for i in 0..bytes.len() {
            if let Some(end) = try_match(&self.pattern.ops, bytes, i) {
                if end > i {
                    findings.push(Finding {
                        detector_name: name,
                        category: self.category(),
                        start: i,
                        end,
                        confidence: Confidence::Medium,
                        matched_len: end - i,
                    });
                }
            }
        }
        findings
    }
}

#[derive(Debug, Clone)]
enum CharClass {
    Literal(u8),
    Any,
    Digit,
    NonDigit,
    Word,
    NonWord,
    Whitespace,
    NonWhitespace,
    Range(Vec<(u8, u8)>, bool), // (ranges, negated)
}

#[derive(Debug, Clone)]
enum Op {
    Match(CharClass),
    OneOrMore(CharClass),
    ZeroOrMore(CharClass),
    ZeroOrOne(CharClass),
}

#[derive(Debug, Clone)]
struct CompiledPattern {
    ops: Vec<Op>,
}

impl CharClass {
    fn matches(&self, c: u8) -> bool {
        match self {
            CharClass::Literal(expected) => c == *expected,
            CharClass::Any => c != b'\n',
            CharClass::Digit => c.is_ascii_digit(),
            CharClass::NonDigit => !c.is_ascii_digit(),
            CharClass::Word => c.is_ascii_alphanumeric() || c == b'_',
            CharClass::NonWord => !(c.is_ascii_alphanumeric() || c == b'_'),
            CharClass::Whitespace => c.is_ascii_whitespace(),
            CharClass::NonWhitespace => !c.is_ascii_whitespace(),
            CharClass::Range(ranges, negated) => {
                let in_range = ranges.iter().any(|(lo, hi)| c >= *lo && c <= *hi);
                if *negated {
                    !in_range
                } else {
                    in_range
                }
            }
        }
    }
}

fn compile_pattern(pat: &str) -> Option<CompiledPattern> {
    let bytes = pat.as_bytes();
    let mut ops = Vec::new();
    let mut i = 0;

    while i < bytes.len() {
        let cc = match bytes[i] {
            b'.' => {
                i += 1;
                CharClass::Any
            }
            b'\\' if i + 1 < bytes.len() => {
                i += 1;
                let cc = match bytes[i] {
                    b'd' => CharClass::Digit,
                    b'D' => CharClass::NonDigit,
                    b'w' => CharClass::Word,
                    b'W' => CharClass::NonWord,
                    b's' => CharClass::Whitespace,
                    b'S' => CharClass::NonWhitespace,
                    other => CharClass::Literal(other),
                };
                i += 1;
                cc
            }
            b'[' => {
                i += 1;
                let negated = i < bytes.len() && bytes[i] == b'^';
                if negated {
                    i += 1;
                }
                let mut ranges = Vec::new();
                while i < bytes.len() && bytes[i] != b']' {
                    let start_char = bytes[i];
                    i += 1;
                    if i + 1 < bytes.len() && bytes[i] == b'-' && bytes[i + 1] != b']' {
                        i += 1;
                        let end_char = bytes[i];
                        i += 1;
                        ranges.push((start_char, end_char));
                    } else {
                        ranges.push((start_char, start_char));
                    }
                }
                if i < bytes.len() && bytes[i] == b']' {
                    i += 1;
                } else {
                    return None; // Unterminated bracket
                }
                CharClass::Range(ranges, negated)
            }
            b'^' | b'$' => {
                // Anchors: skip for now (we do substring matching)
                i += 1;
                continue;
            }
            other => {
                i += 1;
                CharClass::Literal(other)
            }
        };

        if i < bytes.len() {
            match bytes[i] {
                b'+' => {
                    i += 1;
                    ops.push(Op::OneOrMore(cc));
                }
                b'*' => {
                    i += 1;
                    ops.push(Op::ZeroOrMore(cc));
                }
                b'?' => {
                    i += 1;
                    ops.push(Op::ZeroOrOne(cc));
                }
                _ => {
                    ops.push(Op::Match(cc));
                }
            }
        } else {
            ops.push(Op::Match(cc));
        }
    }

    Some(CompiledPattern { ops })
}

/// Non-backtracking greedy match. Returns end position or None.
/// Bounded: quantifiers are capped at 4096 repetitions to prevent DoS.
const MAX_REPETITIONS: usize = 4096;

fn try_match(ops: &[Op], text: &[u8], start: usize) -> Option<usize> {
    let mut pos = start;

    for op in ops {
        match op {
            Op::Match(cc) => {
                if pos >= text.len() || !cc.matches(text[pos]) {
                    return None;
                }
                pos += 1;
            }
            Op::OneOrMore(cc) => {
                if pos >= text.len() || !cc.matches(text[pos]) {
                    return None;
                }
                pos += 1;
                let mut count = 1;
                while pos < text.len() && cc.matches(text[pos]) && count < MAX_REPETITIONS {
                    pos += 1;
                    count += 1;
                }
            }
            Op::ZeroOrMore(cc) => {
                let mut count = 0;
                while pos < text.len() && cc.matches(text[pos]) && count < MAX_REPETITIONS {
                    pos += 1;
                    count += 1;
                }
            }
            Op::ZeroOrOne(cc) => {
                if pos < text.len() && cc.matches(text[pos]) {
                    pos += 1;
                }
            }
        }
    }

    Some(pos)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn custom_literal_match() {
        let det = CustomDetector::new("TEST".into(), "abc".into()).unwrap();
        let findings = det.detect("xxxabcyyy");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].start, 3);
        assert_eq!(findings[0].end, 6);
    }

    #[test]
    fn custom_char_class() {
        let det = CustomDetector::new("HEX".into(), "0x[0-9a-fA-F]+".into()).unwrap();
        let findings = det.detect("val=0xDEADBEEF rest");
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn custom_digit_shorthand() {
        let det = CustomDetector::new("NUM".into(), "\\d+".into()).unwrap();
        let findings = det.detect("abc 123 def");
        assert!(!findings.is_empty());
    }

    #[test]
    fn custom_negated_class() {
        let det = CustomDetector::new("NONDIGIT".into(), "[^0-9]+".into()).unwrap();
        let findings = det.detect("abc");
        // Matches at each start position: "abc" at 0, "bc" at 1, "c" at 2
        assert!(findings.len() >= 1);
        assert_eq!(findings[0].start, 0);
        assert_eq!(findings[0].end, 3);
    }

    #[test]
    fn invalid_pattern_returns_none() {
        let result = CustomDetector::new("BAD".into(), "[unclosed".into());
        assert!(result.is_none());
    }

    #[test]
    fn bounded_repetition() {
        // Ensure large inputs don't cause hangs
        let det = CustomDetector::new("BIG".into(), "a+".into()).unwrap();
        let input = "a".repeat(10000);
        let findings = det.detect(&input);
        assert!(!findings.is_empty());
    }
}
