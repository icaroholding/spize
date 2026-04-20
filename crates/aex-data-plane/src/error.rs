use thiserror::Error;

pub type DataPlaneResult<T> = Result<T, DataPlaneError>;

#[derive(Debug, Error)]
pub enum DataPlaneError {
    #[error("blob not found: {0}")]
    BlobNotFound(String),

    #[error("ticket error: {0}")]
    Ticket(String),

    #[error("scanner blocked delivery: {verdict}")]
    ScannerBlocked { verdict: String },

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("bind error on {addr}: {source}")]
    Bind {
        addr: String,
        #[source]
        source: std::io::Error,
    },

    #[error("serde: {0}")]
    Serde(#[from] serde_json::Error),
}
