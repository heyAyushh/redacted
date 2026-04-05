use crate::errors::{RedactError, Result};
use std::fs;
use std::io::{self, Read, Write};
use std::path::Path;

/// Max bytes to sample for binary detection.
const BINARY_SAMPLE_SIZE: usize = 8192;

/// Read text from stdin.
pub fn read_stdin() -> Result<String> {
    let mut buf = String::new();
    io::stdin().read_to_string(&mut buf)?;
    Ok(buf)
}

/// Check if stdin is piped (not a terminal).
/// Uses /proc/self/fd/0 stat on Linux to determine if stdin is a character device.
pub fn stdin_is_piped() -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::FileTypeExt;
        match fs::metadata("/proc/self/fd/0") {
            Ok(meta) => !meta.file_type().is_char_device(),
            Err(_) => {
                // Fallback: try /dev/stdin
                match fs::metadata("/dev/stdin") {
                    Ok(meta) => !meta.file_type().is_char_device(),
                    Err(_) => false, // Conservative: assume terminal
                }
            }
        }
    }
    #[cfg(not(unix))]
    {
        false
    }
}

/// Read a file, checking size limits.
pub fn read_file(path: &Path, max_size: u64) -> Result<String> {
    let metadata = fs::metadata(path)?;
    if metadata.len() > max_size {
        return Err(RedactError::Io(io::Error::other(format!(
            "File '{}' exceeds max size ({} > {} bytes)",
            path.display(),
            metadata.len(),
            max_size
        ))));
    }

    let bytes = fs::read(path)?;

    if is_binary(&bytes) {
        return Err(RedactError::Detection(format!(
            "File '{}' appears to be binary",
            path.display()
        )));
    }

    String::from_utf8(bytes).map_err(|_| {
        RedactError::Io(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("File '{}' contains invalid UTF-8", path.display()),
        ))
    })
}

/// Read a file in best-effort mode.
///
/// Unlike `read_file`, this never rejects binary or invalid UTF-8 content
/// (other than size checks). Bytes are decoded lossily so callers can still
/// attempt redaction on mixed-content files.
pub fn read_file_best_effort(path: &Path, max_size: u64) -> Result<String> {
    let metadata = fs::metadata(path)?;
    if metadata.len() > max_size {
        return Err(RedactError::Io(io::Error::other(format!(
            "File '{}' exceeds max size ({} > {} bytes)",
            path.display(),
            metadata.len(),
            max_size
        ))));
    }

    let bytes = fs::read(path)?;
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

/// Detect if content is binary by checking for null bytes and high ratio of non-text bytes.
pub fn is_binary(bytes: &[u8]) -> bool {
    let sample = &bytes[..std::cmp::min(bytes.len(), BINARY_SAMPLE_SIZE)];
    if sample.contains(&0) {
        return true;
    }
    let non_text = sample
        .iter()
        .filter(|&&b| b < 0x07 || (b > 0x0D && b < 0x20 && b != 0x1B))
        .count();
    let ratio = non_text as f64 / std::cmp::max(sample.len(), 1) as f64;
    ratio > 0.3
}

/// Write content to a file atomically: write to a temp file in the same dir, then rename.
pub fn atomic_write(path: &Path, content: &str) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| RedactError::AtomicWrite("Cannot determine parent directory".into()))?;
    fs::create_dir_all(parent)?;

    let temp_name = format!(
        ".redact_tmp_{}_{}",
        std::process::id(),
        path.file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "output".into())
    );
    let temp_path = parent.join(&temp_name);

    let result = (|| -> Result<()> {
        let mut file = fs::File::create(&temp_path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            file.set_permissions(fs::Permissions::from_mode(0o600))?;
        }
        file.write_all(content.as_bytes())?;
        file.sync_all()?;
        Ok(())
    })();

    if let Err(e) = result {
        let _ = fs::remove_file(&temp_path);
        return Err(e);
    }

    // Preserve original permissions if the target exists
    #[cfg(unix)]
    if let Ok(meta) = fs::metadata(path) {
        let _ = fs::set_permissions(&temp_path, meta.permissions());
    }

    fs::rename(&temp_path, path).map_err(|e| {
        let _ = fs::remove_file(&temp_path);
        RedactError::AtomicWrite(format!("Failed to rename temp file: {}", e))
    })
}

/// Write content to stdout.
pub fn write_stdout(content: &str) -> Result<()> {
    let stdout = io::stdout();
    let mut handle = stdout.lock();
    handle.write_all(content.as_bytes())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn binary_detection_null_byte() {
        assert!(is_binary(&[0x48, 0x65, 0x00, 0x6C]));
    }

    #[test]
    fn binary_detection_text() {
        assert!(!is_binary(b"Hello, world!\nThis is text."));
    }

    #[test]
    fn binary_detection_utf8() {
        assert!(!is_binary("Héllo wörld 日本語".as_bytes()));
    }

    #[test]
    fn atomic_write_creates_file() {
        let dir = std::env::temp_dir().join("redact_test_atomic");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("test.txt");
        atomic_write(&path, "hello").unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "hello");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn read_file_size_limit() {
        let dir = std::env::temp_dir().join("redact_test_size");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("big.txt");
        fs::write(&path, "x".repeat(100)).unwrap();
        let result = read_file(&path, 10);
        assert!(result.is_err());
        let _ = fs::remove_dir_all(&dir);
    }
}
