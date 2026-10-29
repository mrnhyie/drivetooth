use std::path::Path;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum DtError {
    #[error("I/O error on {path}: {source}")]
    Io { path: String, source: std::io::Error },

    #[error("cryptographic failure: {0}")]
    Crypto(String),

    #[error("malformed encrypted data: {0}")]
    Format(String),

    #[error("the password does not unlock this volume")]
    WrongPassword,

    #[error("volume is in an unusable state: {0}")]
    State(String),

    #[error("not enough free space: need {need_mb} MiB, only {free_mb} MiB free on {mount}")]
    Space {
        need_mb: u64,
        free_mb: u64,
        mount: String,
    },

    #[error("operation cancelled")]
    Cancel,

    #[error("{0}")]
    Other(String),
}

pub type DtResult<T> = Result<T, DtError>;

/// Attaches the offending path to I/O errors so the UI can name the file.
pub trait IoCtx<T> {
    fn ctx(self, path: &Path) -> DtResult<T>;
}

impl<T> IoCtx<T> for std::io::Result<T> {
    fn ctx(self, path: &Path) -> DtResult<T> {
        self.map_err(|source| DtError::Io {
            path: path.display().to_string(),
            source,
        })
    }
}
