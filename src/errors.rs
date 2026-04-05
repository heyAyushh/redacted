use std::fmt;
use std::io;

/// Exit codes following Unix conventions.
/// 0 = success, 1 = operational error, 2 = usage error, 3 = findings found (with --fail-on-find).
pub const EXIT_SUCCESS: i32 = 0;
pub const EXIT_ERROR: i32 = 1;
pub const EXIT_USAGE: i32 = 2;
pub const EXIT_FINDINGS: i32 = 3;

#[derive(Debug)]
pub enum RedactError {
    Io(io::Error),
    Usage(String),
    Config(String),
    Traversal(String),
    Detection(String),
    AtomicWrite(String),
}

impl fmt::Display for RedactError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RedactError::Io(e) => write!(f, "I/O error: {}", e),
            RedactError::Usage(msg) => write!(f, "Usage error: {}", msg),
            RedactError::Config(msg) => write!(f, "Config error: {}", msg),
            RedactError::Traversal(msg) => write!(f, "Traversal error: {}", msg),
            RedactError::Detection(msg) => write!(f, "Detection error: {}", msg),
            RedactError::AtomicWrite(msg) => write!(f, "Atomic write error: {}", msg),
        }
    }
}

impl std::error::Error for RedactError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            RedactError::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for RedactError {
    fn from(e: io::Error) -> Self {
        RedactError::Io(e)
    }
}

impl RedactError {
    pub fn exit_code(&self) -> i32 {
        match self {
            RedactError::Usage(_) => EXIT_USAGE,
            _ => EXIT_ERROR,
        }
    }
}

pub type Result<T> = std::result::Result<T, RedactError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_display_formats_correctly() {
        let e = RedactError::Usage("missing --input".into());
        assert_eq!(e.to_string(), "Usage error: missing --input");
        assert_eq!(e.exit_code(), EXIT_USAGE);
    }

    #[test]
    fn io_error_converts() {
        let io_err = io::Error::new(io::ErrorKind::NotFound, "file gone");
        let e: RedactError = io_err.into();
        assert_eq!(e.exit_code(), EXIT_ERROR);
        assert!(e.to_string().contains("I/O error"));
    }
}
