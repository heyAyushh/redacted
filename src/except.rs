use crate::cli::{ExceptArgs, ExceptRuleSelector, ExceptSubcommand};
use crate::errors::{RedactError, Result, EXIT_SUCCESS};
use crate::io_safe;
use std::fs;
use std::path::{Path, PathBuf};

pub const DEFAULT_EXCEPT_FILE: &str = ".redacted-except";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExceptRule {
    RetainDetector(String),
    RetainLiteral(String),
}

impl ExceptRule {
    pub fn from_selector(selector: &ExceptRuleSelector) -> Self {
        match selector {
            ExceptRuleSelector::Detector(name) => Self::RetainDetector(name.clone()),
            ExceptRuleSelector::Literal(value) => Self::RetainLiteral(value.clone()),
        }
    }

    pub fn encode(&self) -> String {
        match self {
            Self::RetainDetector(name) => format!("retain\tdetector\t{}", name),
            Self::RetainLiteral(value) => format!("retain\tliteral\t{}", value),
        }
    }

    fn decode(line: &str) -> Result<Self> {
        let mut parts = line.splitn(3, '\t');
        let action = parts.next().unwrap_or_default();
        let kind = parts.next().unwrap_or_default();
        let value = parts.next().unwrap_or_default().trim();

        if action != "retain" || value.is_empty() {
            return Err(RedactError::Config(format!(
                "Invalid except rule '{}'. Expected: retain<TAB>detector|literal<TAB>VALUE",
                line
            )));
        }

        match kind {
            "detector" => Ok(Self::RetainDetector(value.to_string())),
            "literal" => Ok(Self::RetainLiteral(value.to_string())),
            _ => Err(RedactError::Config(format!(
                "Invalid except rule kind '{}' in '{}'",
                kind, line
            ))),
        }
    }

    pub fn display(&self) -> String {
        match self {
            Self::RetainDetector(name) => format!("retain detector {}", name),
            Self::RetainLiteral(value) => format!("retain literal {}", value),
        }
    }
}

pub fn default_except_path() -> PathBuf {
    PathBuf::from(DEFAULT_EXCEPT_FILE)
}

pub fn load_rules(path: &Path) -> Result<Vec<ExceptRule>> {
    if !path.exists() {
        return Ok(Vec::new());
    }

    let content = fs::read_to_string(path).map_err(|e| {
        RedactError::Config(format!(
            "Cannot read except file '{}': {}",
            path.display(),
            e
        ))
    })?;

    let mut rules = Vec::new();
    for raw_line in content.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        rules.push(ExceptRule::decode(line)?);
    }
    Ok(rules)
}

pub fn save_rules(path: &Path, rules: &[ExceptRule]) -> Result<()> {
    let mut encoded = String::new();
    for rule in rules {
        encoded.push_str(&rule.encode());
        encoded.push('\n');
    }
    io_safe::atomic_write(path, &encoded)
}

pub fn resolve_scan_except_path(explicit: Option<&str>) -> Result<Option<PathBuf>> {
    if let Some(path) = explicit {
        let path = PathBuf::from(path);
        if !path.exists() {
            return Err(RedactError::Usage(format!(
                "Except file '{}' does not exist.\n  redacted --except-file <PATH>",
                path.display()
            )));
        }
        return Ok(Some(path));
    }

    let default = default_except_path();
    if default.exists() {
        Ok(Some(default))
    } else {
        Ok(None)
    }
}

pub fn run_except_command(args: &ExceptArgs) -> Result<i32> {
    let path = args
        .file
        .as_deref()
        .map(PathBuf::from)
        .unwrap_or_else(default_except_path);

    match args.command.as_ref() {
        None => {}
        Some(ExceptSubcommand::List) => {
            let rules = load_rules(&path)?;
            let output = if rules.is_empty() {
                format!("No exception rules configured in {}\n", path.display())
            } else {
                let mut buf = format!("Exception rules in {}:\n", path.display());
                for rule in rules {
                    buf.push_str("- ");
                    buf.push_str(&rule.display());
                    buf.push('\n');
                }
                buf
            };
            io_safe::write_stdout(&output)?;
        }
        Some(ExceptSubcommand::Add(selector)) => {
            let mut rules = load_rules(&path)?;
            let rule = ExceptRule::from_selector(selector);
            let message = if rules.contains(&rule) {
                format!("Rule already present: {}\n", rule.display())
            } else {
                rules.push(rule.clone());
                save_rules(&path, &rules)?;
                format!("Added {}\n", rule.display())
            };
            io_safe::write_stdout(&message)?;
        }
        Some(ExceptSubcommand::Remove(selector)) => {
            let mut rules = load_rules(&path)?;
            let rule = ExceptRule::from_selector(selector);
            let before = rules.len();
            rules.retain(|existing| existing != &rule);
            let message = if rules.len() == before {
                format!("Rule not found: {}\n", rule.display())
            } else {
                save_rules(&path, &rules)?;
                format!("Removed {}\n", rule.display())
            };
            io_safe::write_stdout(&message)?;
        }
    }

    Ok(EXIT_SUCCESS)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_detector_rule() {
        let rule = ExceptRule::decode("retain\tdetector\tEMAIL").unwrap();
        assert_eq!(rule, ExceptRule::RetainDetector("EMAIL".into()));
    }

    #[test]
    fn decode_literal_rule() {
        let rule = ExceptRule::decode("retain\tliteral\tuser@example.com").unwrap();
        assert_eq!(rule, ExceptRule::RetainLiteral("user@example.com".into()));
    }
}
