//! Blob sources — how the data plane gets bytes for a transfer.

use std::collections::HashMap;
use std::path::PathBuf;

use async_trait::async_trait;

use crate::error::{DataPlaneError, DataPlaneResult};

#[derive(Debug, Clone)]
pub struct BlobMetadata {
    pub size: u64,
    pub mime: String,
    pub filename: String,
}

#[async_trait]
pub trait BlobSource: Send + Sync {
    async fn metadata(&self, transfer_id: &str) -> DataPlaneResult<BlobMetadata>;

    /// Return the full blob bytes. For small-to-medium files this is simplest.
    /// Streaming will be added alongside range requests in a later version.
    async fn bytes(&self, transfer_id: &str) -> DataPlaneResult<Vec<u8>>;
}

// ---------- In-memory source (tests, small files) ----------

#[derive(Default)]
pub struct InMemoryBlobSource {
    inner: tokio::sync::RwLock<HashMap<String, (BlobMetadata, Vec<u8>)>>,
}

impl InMemoryBlobSource {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn insert(&self, transfer_id: String, metadata: BlobMetadata, bytes: Vec<u8>) {
        self.inner
            .write()
            .await
            .insert(transfer_id, (metadata, bytes));
    }

    pub async fn remove(&self, transfer_id: &str) -> DataPlaneResult<()> {
        self.inner.write().await.remove(transfer_id);
        Ok(())
    }
}

#[async_trait]
impl BlobSource for InMemoryBlobSource {
    async fn metadata(&self, transfer_id: &str) -> DataPlaneResult<BlobMetadata> {
        self.inner
            .read()
            .await
            .get(transfer_id)
            .map(|(m, _)| m.clone())
            .ok_or_else(|| DataPlaneError::BlobNotFound(transfer_id.to_string()))
    }

    async fn bytes(&self, transfer_id: &str) -> DataPlaneResult<Vec<u8>> {
        self.inner
            .read()
            .await
            .get(transfer_id)
            .map(|(_, b)| b.clone())
            .ok_or_else(|| DataPlaneError::BlobNotFound(transfer_id.to_string()))
    }
}

// ---------- Filesystem source ----------

pub struct FileBlobSource {
    root: PathBuf,
    inner: tokio::sync::RwLock<HashMap<String, BlobMetadata>>,
}

impl FileBlobSource {
    pub fn new(root: PathBuf) -> Self {
        Self {
            root,
            inner: tokio::sync::RwLock::new(HashMap::new()),
        }
    }

    pub async fn register(
        &self,
        transfer_id: String,
        metadata: BlobMetadata,
    ) -> DataPlaneResult<()> {
        self.inner.write().await.insert(transfer_id, metadata);
        Ok(())
    }

    fn path_for(&self, transfer_id: &str) -> PathBuf {
        self.root.join(transfer_id)
    }
}

#[async_trait]
impl BlobSource for FileBlobSource {
    async fn metadata(&self, transfer_id: &str) -> DataPlaneResult<BlobMetadata> {
        self.inner
            .read()
            .await
            .get(transfer_id)
            .cloned()
            .ok_or_else(|| DataPlaneError::BlobNotFound(transfer_id.to_string()))
    }

    async fn bytes(&self, transfer_id: &str) -> DataPlaneResult<Vec<u8>> {
        let _ = self.metadata(transfer_id).await?;
        let path = self.path_for(transfer_id);
        let bytes = tokio::fs::read(&path).await.map_err(DataPlaneError::Io)?;
        Ok(bytes)
    }
}
