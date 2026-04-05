use crate::cli::{BinaryMode, CliArgs, OutputFormat};
use crate::errors::{RedactError, Result};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

/// Merged configuration from CLI args and optional TOML config file.
/// CLI args always take precedence over config file values.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct Config {
    pub text: Option<String>,
    pub input: Option<String>,
    pub output: Option<String>,
    pub in_place: bool,
    pub recursive: bool,
    pub report_json: bool,
    pub patterns: Vec<(String, String)>,
    pub allow_patterns: Vec<String>,
    pub deny_patterns: Vec<String>,
    pub dry_run: bool,
    pub fail_on_find: bool,
    pub summary: bool,
    pub format: OutputFormat,
    pub replacement: Option<String>,
    pub binary: BinaryMode,
    pub max_file_size: u64,
    pub include_hidden: bool,
    pub follow_symlinks: bool,
    pub threads: Option<usize>,
}

impl Config {
    /// Build config from CLI args, optionally loading a TOML config file.
    pub fn from_cli(cli: &CliArgs) -> Result<Self> {
        let mut config = Self {
            text: cli.text.clone(),
            input: cli.input.clone(),
            output: cli.output.clone(),
            in_place: cli.in_place,
            recursive: cli.recursive,
            report_json: cli.report_json,
            patterns: cli.patterns.clone(),
            allow_patterns: cli.allow_patterns.clone(),
            deny_patterns: cli.deny_patterns.clone(),
            dry_run: cli.dry_run,
            fail_on_find: cli.fail_on_find,
            summary: cli.summary,
            format: cli.format.clone(),
            replacement: cli.replacement.clone(),
            binary: cli.binary.clone(),
            max_file_size: cli.max_file_size,
            include_hidden: cli.include_hidden,
            follow_symlinks: cli.follow_symlinks,
            threads: cli.threads,
        };

        if let Some(ref config_path) = cli.config {
            config.merge_toml(Path::new(config_path))?;
        }

        Ok(config)
    }

    fn merge_toml(&mut self, path: &Path) -> Result<()> {
        let content = fs::read_to_string(path).map_err(|e| {
            RedactError::Config(format!("Cannot read config '{}': {}", path.display(), e))
        })?;

        let values = parse_simple_toml(&content)?;

        // Only apply config values if they weren't explicitly set on CLI
        if self.replacement.is_none() {
            if let Some(v) = values.get("replacement") {
                self.replacement = Some(v.clone());
            }
        }
        if let Some(v) = values.get("max_file_size") {
            if self.max_file_size == 25 * 1024 * 1024 {
                if let Ok(n) = v.parse::<u64>() {
                    self.max_file_size = n;
                }
            }
        }
        if let Some(v) = values.get("include_hidden") {
            if !self.include_hidden && v == "true" {
                self.include_hidden = true;
            }
        }
        if let Some(v) = values.get("follow_symlinks") {
            if !self.follow_symlinks && v == "true" {
                self.follow_symlinks = true;
            }
        }
        if let Some(v) = values.get("binary") {
            if self.binary == BinaryMode::Skip {
                self.binary = match v.as_str() {
                    "fail" => BinaryMode::Fail,
                    "best-effort" => BinaryMode::BestEffort,
                    _ => BinaryMode::Skip,
                };
            }
        }

        // Load custom patterns from config
        for (key, val) in &values {
            if let Some(name) = key.strip_prefix("pattern.") {
                self.patterns.push((name.to_string(), val.clone()));
            }
        }

        // Load allow/deny from config
        if let Some(v) = values.get("allow_patterns") {
            for name in v.split(',') {
                let trimmed = name.trim().to_string();
                if !trimmed.is_empty() && !self.allow_patterns.contains(&trimmed) {
                    self.allow_patterns.push(trimmed);
                }
            }
        }
        if let Some(v) = values.get("deny_patterns") {
            for name in v.split(',') {
                let trimmed = name.trim().to_string();
                if !trimmed.is_empty() && !self.deny_patterns.contains(&trimmed) {
                    self.deny_patterns.push(trimmed);
                }
            }
        }

        Ok(())
    }
}

/// Minimal TOML parser supporting flat key=value pairs and [section] headers.
/// Does not support arrays, inline tables, or multi-line strings.
/// This is intentionally limited to avoid complexity in a security tool.
fn parse_simple_toml(content: &str) -> Result<HashMap<String, String>> {
    let mut map = HashMap::new();
    let mut section = String::new();

    for (line_num, line) in content.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        if line.starts_with('[') && line.ends_with(']') {
            section = line[1..line.len() - 1].trim().to_string();
            continue;
        }

        if let Some(eq_pos) = line.find('=') {
            let key = line[..eq_pos].trim();
            let val = line[eq_pos + 1..].trim();

            // Strip quotes
            let val = if (val.starts_with('"') && val.ends_with('"'))
                || (val.starts_with('\'') && val.ends_with('\''))
            {
                &val[1..val.len() - 1]
            } else {
                val
            };

            let full_key = if section.is_empty() {
                key.to_string()
            } else {
                format!("{}.{}", section, key)
            };
            map.insert(full_key, val.to_string());
        } else {
            return Err(RedactError::Config(format!(
                "Invalid TOML at line {}: {}",
                line_num + 1,
                line
            )));
        }
    }

    Ok(map)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_simple_toml_basic() {
        let content = r#"
replacement = "[SCRUBBED]"
max_file_size = 1048576

[pattern]
my_key = "sk_[a-z]+"
"#;
        let map = parse_simple_toml(content).unwrap();
        assert_eq!(map.get("replacement").unwrap(), "[SCRUBBED]");
        assert_eq!(map.get("max_file_size").unwrap(), "1048576");
        assert_eq!(map.get("pattern.my_key").unwrap(), "sk_[a-z]+");
    }

    #[test]
    fn parse_toml_comments_and_empty() {
        let content = "# comment\n\nkey = value\n";
        let map = parse_simple_toml(content).unwrap();
        assert_eq!(map.get("key").unwrap(), "value");
    }

    #[test]
    fn config_from_cli_defaults() {
        let cli = CliArgs::default();
        let config = Config::from_cli(&cli).unwrap();
        assert!(config.recursive);
        assert!(!config.follow_symlinks);
    }
}
