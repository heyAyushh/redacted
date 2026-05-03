use crate::errors::{RedactError, Result};
use crate::text_utils::capitalize_first;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const REDACTED_CONFIG_HOME_OVERRIDE: &str = "REDACTED_CONFIG_HOME";
const REDACTED_DATA_HOME_OVERRIDE: &str = "REDACTED_DATA_HOME";

pub fn config_root() -> Result<PathBuf> {
    if let Some(path) = std::env::var_os(REDACTED_CONFIG_HOME_OVERRIDE) {
        return Ok(PathBuf::from(path));
    }
    if cfg!(windows) {
        if let Some(path) = std::env::var_os("APPDATA") {
            return Ok(PathBuf::from(path).join("redacted"));
        }
    }
    if let Some(path) = std::env::var_os("XDG_CONFIG_HOME") {
        return Ok(PathBuf::from(path).join("redacted"));
    }
    Ok(home_dir()?.join(".config").join("redacted"))
}

pub fn data_root() -> Result<PathBuf> {
    if let Some(path) = std::env::var_os(REDACTED_DATA_HOME_OVERRIDE) {
        return Ok(PathBuf::from(path));
    }
    if cfg!(windows) {
        if let Some(path) = std::env::var_os("APPDATA") {
            return Ok(PathBuf::from(path).join("redacted"));
        }
    }
    if let Some(path) = std::env::var_os("XDG_DATA_HOME") {
        return Ok(PathBuf::from(path).join("redacted"));
    }
    Ok(home_dir()?.join(".local").join("share").join("redacted"))
}

fn home_dir() -> Result<PathBuf> {
    if let Some(path) = std::env::var_os("HOME") {
        return Ok(PathBuf::from(path));
    }
    if let Some(path) = std::env::var_os("USERPROFILE") {
        return Ok(PathBuf::from(path));
    }
    Err(RedactError::Config(
        "Cannot determine home directory for redacted state.".into(),
    ))
}

pub fn parse_key_value_file(path: &Path, context: &str) -> Result<HashMap<String, String>> {
    let content = fs::read_to_string(path).map_err(|error| {
        RedactError::Config(format!(
            "Cannot read {} metadata '{}': {}",
            context,
            path.display(),
            error
        ))
    })?;
    let mut values = HashMap::new();
    for (line_number, raw_line) in content.lines().enumerate() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (key, value) = line.split_once('=').ok_or_else(|| {
            RedactError::Config(format!(
                "Invalid {} metadata line {} in '{}': {}",
                context,
                line_number + 1,
                path.display(),
                raw_line
            ))
        })?;
        values.insert(key.trim().to_string(), value.trim().to_string());
    }
    Ok(values)
}

pub fn parse_required_value(
    values: &HashMap<String, String>,
    key: &str,
    path: &Path,
    context: &str,
) -> Result<String> {
    values.get(key).cloned().ok_or_else(|| {
        RedactError::Config(format!(
            "{} metadata '{}' is missing key '{}'.",
            capitalize_first(context),
            path.display(),
            key
        ))
    })
}

pub fn parse_required_u32(
    values: &HashMap<String, String>,
    key: &str,
    path: &Path,
    context: &str,
) -> Result<u32> {
    let value = parse_required_value(values, key, path, context)?;
    value.parse::<u32>().map_err(|_| {
        RedactError::Config(format!(
            "{} metadata '{}' has invalid {} value '{}'.",
            capitalize_first(context),
            path.display(),
            key,
            value
        ))
    })
}

pub fn parse_required_u64(
    values: &HashMap<String, String>,
    key: &str,
    path: &Path,
    context: &str,
) -> Result<u64> {
    let value = parse_required_value(values, key, path, context)?;
    value.parse::<u64>().map_err(|_| {
        RedactError::Config(format!(
            "{} metadata '{}' has invalid {} value '{}'.",
            capitalize_first(context),
            path.display(),
            key,
            value
        ))
    })
}

pub fn unix_timestamp_now() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| {
            RedactError::Config(format!("System clock error while saving state: {}", error))
        })?
        .as_secs())
}

pub fn yes_or_no(value: bool) -> &'static str {
    if value {
        "yes"
    } else {
        "no"
    }
}
