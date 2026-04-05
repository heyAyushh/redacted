use crate::errors::{RedactError, Result};
use std::fs;
use std::path::{Path, PathBuf};

/// Configuration for directory traversal.
pub struct TraverseConfig {
    pub include_hidden: bool,
    pub follow_symlinks: bool,
    pub max_file_size: u64,
    pub max_depth: usize,
}

impl Default for TraverseConfig {
    fn default() -> Self {
        Self {
            include_hidden: false,
            follow_symlinks: false,
            max_file_size: 25 * 1024 * 1024,
            max_depth: 256,
        }
    }
}

/// Result of processing a file during traversal.
#[derive(Debug)]
pub enum FileEntry {
    /// File is eligible for processing.
    Eligible {
        path: PathBuf,
        relative: PathBuf,
    },
    /// File was skipped with a reason.
    Skipped {
        path: PathBuf,
        reason: String,
    },
}

/// Recursively collect files from a directory, applying safety checks.
pub fn collect_files(
    root: &Path,
    config: &TraverseConfig,
) -> Result<Vec<FileEntry>> {
    let root = root.canonicalize().map_err(|e| {
        RedactError::Traversal(format!("Cannot resolve path '{}': {}", root.display(), e))
    })?;

    let mut entries = Vec::new();
    collect_recursive(&root, &root, config, 0, &mut entries)?;
    entries.sort_by(|a, b| {
        let pa = match a {
            FileEntry::Eligible { path, .. } => path,
            FileEntry::Skipped { path, .. } => path,
        };
        let pb = match b {
            FileEntry::Eligible { path, .. } => path,
            FileEntry::Skipped { path, .. } => path,
        };
        pa.cmp(pb)
    });
    Ok(entries)
}

fn collect_recursive(
    base: &Path,
    current: &Path,
    config: &TraverseConfig,
    depth: usize,
    entries: &mut Vec<FileEntry>,
) -> Result<()> {
    if depth > config.max_depth {
        entries.push(FileEntry::Skipped {
            path: current.to_path_buf(),
            reason: format!("Max depth {} exceeded", config.max_depth),
        });
        return Ok(());
    }

    let read_dir = fs::read_dir(current).map_err(|e| {
        RedactError::Traversal(format!("Cannot read directory '{}': {}", current.display(), e))
    })?;

    for entry in read_dir {
        let entry = entry.map_err(|e| {
            RedactError::Traversal(format!("Error reading entry in '{}': {}", current.display(), e))
        })?;

        let path = entry.path();
        let file_name = entry.file_name();
        let name_str = file_name.to_string_lossy();

        // Skip hidden files/dirs unless configured
        if !config.include_hidden && name_str.starts_with('.') {
            entries.push(FileEntry::Skipped {
                path: path.clone(),
                reason: "Hidden file/directory".into(),
            });
            continue;
        }

        let file_type = entry.file_type().map_err(|e| {
            RedactError::Traversal(format!("Cannot get type of '{}': {}", path.display(), e))
        })?;

        // Symlink handling
        if file_type.is_symlink() {
            if !config.follow_symlinks {
                entries.push(FileEntry::Skipped {
                    path: path.clone(),
                    reason: "Symlink (not following)".into(),
                });
                continue;
            }
            // If following symlinks, resolve and check it doesn't escape root
            match path.canonicalize() {
                Ok(resolved) => {
                    if !resolved.starts_with(base) {
                        entries.push(FileEntry::Skipped {
                            path: path.clone(),
                            reason: "Symlink target outside root (path traversal protection)".into(),
                        });
                        continue;
                    }
                }
                Err(e) => {
                    entries.push(FileEntry::Skipped {
                        path: path.clone(),
                        reason: format!("Cannot resolve symlink: {}", e),
                    });
                    continue;
                }
            }
        }

        if file_type.is_dir() || (file_type.is_symlink() && path.is_dir()) {
            collect_recursive(base, &path, config, depth + 1, entries)?;
        } else if file_type.is_file() || (file_type.is_symlink() && path.is_file()) {
            // Check file size
            match fs::metadata(&path) {
                Ok(meta) => {
                    if meta.len() > config.max_file_size {
                        entries.push(FileEntry::Skipped {
                            path: path.clone(),
                            reason: format!("Exceeds max file size ({} bytes)", meta.len()),
                        });
                        continue;
                    }
                }
                Err(e) => {
                    entries.push(FileEntry::Skipped {
                        path: path.clone(),
                        reason: format!("Cannot stat: {}", e),
                    });
                    continue;
                }
            }

            let relative = path.strip_prefix(base).unwrap_or(&path).to_path_buf();
            entries.push(FileEntry::Eligible {
                path: path.clone(),
                relative,
            });
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn setup_test_dir(suffix: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("redact_traverse_test_{}", suffix));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("sub")).unwrap();
        fs::write(dir.join("a.txt"), "hello").unwrap();
        fs::write(dir.join("sub").join("b.txt"), "world").unwrap();
        fs::write(dir.join(".hidden"), "secret").unwrap();
        dir
    }

    #[test]
    fn collect_skips_hidden() {
        let dir = setup_test_dir("skip_hidden");
        let config = TraverseConfig::default();
        let entries = collect_files(&dir, &config).unwrap();
        let eligible: Vec<_> = entries
            .iter()
            .filter_map(|e| match e {
                FileEntry::Eligible { relative, .. } => Some(relative.clone()),
                _ => None,
            })
            .collect();
        assert_eq!(eligible.len(), 2, "Expected 2 eligible, got: {:?}", eligible);
        assert!(eligible.iter().any(|p| p.to_str().unwrap().contains("a.txt")));
        assert!(eligible.iter().any(|p| p.to_str().unwrap().contains("b.txt")));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn collect_includes_hidden_when_configured() {
        let dir = setup_test_dir("include_hidden");
        let config = TraverseConfig {
            include_hidden: true,
            ..Default::default()
        };
        let entries = collect_files(&dir, &config).unwrap();
        let eligible: Vec<_> = entries
            .iter()
            .filter_map(|e| match e {
                FileEntry::Eligible { .. } => Some(()),
                _ => None,
            })
            .collect();
        assert_eq!(eligible.len(), 3);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn preserves_relative_path() {
        let dir = setup_test_dir("rel_path");
        let config = TraverseConfig::default();
        let entries = collect_files(&dir, &config).unwrap();
        let has_sub = entries.iter().any(|e| match e {
            FileEntry::Eligible { relative, .. } => {
                relative.to_str().unwrap().contains("sub")
            }
            _ => false,
        });
        assert!(has_sub);
        let _ = fs::remove_dir_all(&dir);
    }
}
