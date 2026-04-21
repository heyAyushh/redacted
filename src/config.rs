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
    pub retain_detectors: Vec<String>,
    pub retain_literals: Vec<String>,
    pub except_detectors: Vec<String>,
    pub except_literals: Vec<String>,
    pub except_file: Option<String>,
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
            retain_detectors: cli.retain_detectors.clone(),
            retain_literals: cli.retain_literals.clone(),
            except_detectors: cli.except_detectors.clone(),
            except_literals: cli.except_literals.clone(),
            except_file: cli.except_file.clone(),
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
            config.merge_toml(Path::new(config_path), &cli.explicit_flags)?;
        }

        Ok(config)
    }

    /// Merge TOML config values, but only for flags NOT explicitly set on the CLI.
    fn merge_toml(
        &mut self,
        path: &Path,
        explicit: &std::collections::HashSet<String>,
    ) -> Result<()> {
        let content = fs::read_to_string(path).map_err(|e| {
            RedactError::Config(format!("Cannot read config '{}': {}", path.display(), e))
        })?;

        let values = parse_simple_toml(&content)?;

        if self.replacement.is_none() {
            if let Some(v) = values.get("replacement") {
                self.replacement = Some(v.clone());
            }
        }
        if !explicit.contains("max_file_size") {
            if let Some(v) = values.get("max_file_size") {
                if let Ok(n) = v.parse::<u64>() {
                    self.max_file_size = n;
                }
            }
        }
        if !explicit.contains("include_hidden") {
            if let Some(v) = values.get("include_hidden") {
                if v == "true" {
                    self.include_hidden = true;
                } else if v == "false" {
                    self.include_hidden = false;
                }
            }
        }
        if !explicit.contains("follow_symlinks") {
            if let Some(v) = values.get("follow_symlinks") {
                if v == "true" {
                    self.follow_symlinks = true;
                } else if v == "false" {
                    self.follow_symlinks = false;
                }
            }
        }
        if !explicit.contains("binary") {
            if let Some(v) = values.get("binary") {
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
        if let Some(v) = values.get("retain_detectors") {
            for name in v.split(',') {
                let trimmed = name.trim().to_string();
                if !trimmed.is_empty() && !self.retain_detectors.contains(&trimmed) {
                    self.retain_detectors.push(trimmed);
                }
            }
        }
        if let Some(v) = values.get("retain_literals") {
            for value in v.split(',') {
                let trimmed = value.trim().to_string();
                if !trimmed.is_empty() && !self.retain_literals.contains(&trimmed) {
                    self.retain_literals.push(trimmed);
                }
            }
        }
        if let Some(v) = values.get("except_detectors") {
            for name in v.split(',') {
                let trimmed = name.trim().to_string();
                if !trimmed.is_empty() && !self.except_detectors.contains(&trimmed) {
                    self.except_detectors.push(trimmed);
                }
            }
        }
        if let Some(v) = values.get("except_literals") {
            for value in v.split(',') {
                let trimmed = value.trim().to_string();
                if !trimmed.is_empty() && !self.except_literals.contains(&trimmed) {
                    self.except_literals.push(trimmed);
                }
            }
        }
        if self.except_file.is_none() {
            if let Some(v) = values.get("except_file") {
                self.except_file = Some(v.clone());
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
            let val = if val.len() >= 2
                && ((val.starts_with('"') && val.ends_with('"'))
                    || (val.starts_with('\'') && val.ends_with('\'')))
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
    fn parse_toml_single_quote_char_value_does_not_panic() {
        let content = "key = \"\"\nkey2 = '\''\n";
        let map = parse_simple_toml(content).unwrap();
        assert_eq!(map.get("key").unwrap(), "");
        assert_eq!(map.get("key2").unwrap(), "'");
    }

    #[test]
    fn config_from_cli_defaults() {
        let cli = CliArgs::default();
        let config = Config::from_cli(&cli).unwrap();
        assert!(config.recursive);
        assert!(!config.follow_symlinks);
    }

    #[test]
    fn explicit_cli_flag_overrides_toml() {
        let dir = std::env::temp_dir().join("redact_config_override_test");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let config_path = dir.join("test.toml");
        std::fs::write(
            &config_path,
            "follow_symlinks = true\nbinary = \"fail\"\nmax_file_size = 999\n",
        )
        .unwrap();

        let mut cli = CliArgs::default();
        cli.config = Some(config_path.to_str().unwrap().to_string());
        // Explicitly set --no-follow-symlinks and --binary skip
        cli.follow_symlinks = false;
        cli.explicit_flags.insert("follow_symlinks".into());
        cli.binary = BinaryMode::Skip;
        cli.explicit_flags.insert("binary".into());
        cli.max_file_size = 25 * 1024 * 1024;
        cli.explicit_flags.insert("max_file_size".into());

        let config = Config::from_cli(&cli).unwrap();
        // CLI must win even though TOML says otherwise
        assert!(
            !config.follow_symlinks,
            "CLI --no-follow-symlinks must override TOML"
        );
        assert_eq!(
            config.binary,
            BinaryMode::Skip,
            "CLI --binary skip must override TOML"
        );
        assert_eq!(
            config.max_file_size,
            25 * 1024 * 1024,
            "CLI --max-file-size must override TOML"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn toml_applies_when_flag_not_explicit() {
        let dir = std::env::temp_dir().join("redact_config_apply_test");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let config_path = dir.join("test.toml");
        std::fs::write(&config_path, "follow_symlinks = true\n").unwrap();

        let mut cli = CliArgs::default();
        cli.config = Some(config_path.to_str().unwrap().to_string());
        // No explicit flag set — TOML should apply
        let config = Config::from_cli(&cli).unwrap();
        assert!(
            config.follow_symlinks,
            "TOML should apply when flag not explicitly set"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
