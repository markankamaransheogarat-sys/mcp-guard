use std::path::PathBuf;
use thiserror::Error;

/// Top-level error type for `mcp-guard`.
#[derive(Debug, Error)]
pub enum GuardError {
    /// I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Configuration parsing or validation error.
    #[error("Configuration error: {0}")]
    Config(String),

    /// TOML deserialization error.
    #[error("Invalid TOML in {path}: {source}")]
    TomlParse {
        path: PathBuf,
        #[source]
        source: Box<toml::de::Error>,
    },

    /// JSON-RPC serialization or parsing error.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// Policy violation error.
    #[error("PolicyDenied: {0}")]
    PolicyDenied(String),

    /// HTTP proxy / upstream error.
    #[error("HTTP proxy error: {0}")]
    HttpProxy(String),

    /// Regex compilation error.
    #[error("Regex error: {0}")]
    Regex(#[from] regex::Error),

    /// Glob compilation error.
    #[error("Glob pattern error: {0}")]
    Glob(#[from] globset::Error),
}

pub type Result<T> = std::result::Result<T, GuardError>;
