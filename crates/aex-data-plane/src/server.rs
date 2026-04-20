//! Axum server exposing the data-plane HTTP API.

use std::sync::Arc;

use aex_scanner::{ScanInput, ScanPipeline};
use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use serde::Serialize;
use tokio::sync::RwLock;

use crate::blob::BlobSource;
use crate::error::{DataPlaneError, DataPlaneResult};
use crate::ticket::{Ticket, TicketVerifier};

#[derive(Debug, Clone, Serialize)]
pub struct HealthPayload {
    pub service: &'static str,
    pub version: &'static str,
    pub ok: bool,
}

#[derive(Clone)]
pub struct DataPlaneConfig {
    pub blob_source: Arc<dyn BlobSource>,
    pub ticket_verifier: Arc<TicketVerifier>,
    pub scanner: Option<Arc<ScanPipeline>>,
    pub scan_cache: Arc<RwLock<std::collections::HashMap<String, ScanVerdictCache>>>,
}

#[derive(Debug, Clone)]
pub enum ScanVerdictCache {
    Clean,
    Blocked(String),
}

pub struct DataPlane {
    cfg: DataPlaneConfig,
}

impl DataPlane {
    pub fn new(cfg: DataPlaneConfig) -> Self {
        Self { cfg }
    }

    pub fn router(&self) -> Router {
        Router::new()
            .route("/healthz", get(healthz))
            .route("/blob/:transfer_id", get(get_blob))
            .with_state(self.cfg.clone())
    }
}

async fn healthz() -> Json<HealthPayload> {
    Json(HealthPayload {
        service: "aex-data-plane",
        version: env!("CARGO_PKG_VERSION"),
        ok: true,
    })
}

async fn get_blob(
    State(cfg): State<DataPlaneConfig>,
    Path(transfer_id): Path<String>,
    headers: HeaderMap,
) -> Response {
    match serve(cfg, &transfer_id, &headers).await {
        Ok(resp) => resp,
        Err(err) => {
            let (code, msg) = match &err {
                DataPlaneError::BlobNotFound(_) => (StatusCode::NOT_FOUND, "not found"),
                DataPlaneError::Ticket(_) => (StatusCode::UNAUTHORIZED, "bad ticket"),
                DataPlaneError::ScannerBlocked { .. } => {
                    (StatusCode::FORBIDDEN, "scanner blocked")
                }
                _ => (StatusCode::INTERNAL_SERVER_ERROR, "internal error"),
            };
            tracing::warn!(%transfer_id, error = %err, code = %code, "data-plane refused request");
            (code, msg).into_response()
        }
    }
}

async fn serve(
    cfg: DataPlaneConfig,
    transfer_id: &str,
    headers: &HeaderMap,
) -> DataPlaneResult<Response> {
    // Parse + verify ticket.
    let ticket_header = headers
        .get("x-aex-ticket")
        .ok_or_else(|| DataPlaneError::Ticket("missing X-AEX-Ticket header".into()))?
        .to_str()
        .map_err(|_| DataPlaneError::Ticket("header is not ASCII".into()))?;
    let ticket: Ticket = serde_json::from_str(ticket_header)?;
    let verified = cfg
        .ticket_verifier
        .verify(&ticket)
        .map_err(|e| DataPlaneError::Ticket(e.to_string()))?;

    if verified.transfer_id != *transfer_id {
        return Err(DataPlaneError::Ticket(format!(
            "ticket transfer {} does not match URL {}",
            verified.transfer_id, transfer_id
        )));
    }

    // Metadata + scan (cached by transfer_id).
    let metadata = cfg.blob_source.metadata(transfer_id).await?;

    if let Some(scanner) = cfg.scanner.as_ref() {
        let cached = { cfg.scan_cache.read().await.get(transfer_id).cloned() };
        match cached {
            Some(ScanVerdictCache::Clean) => {}
            Some(ScanVerdictCache::Blocked(reason)) => {
                return Err(DataPlaneError::ScannerBlocked { verdict: reason });
            }
            None => {
                let bytes = cfg.blob_source.bytes(transfer_id).await?;
                let input = ScanInput::new(&bytes)
                    .with_filename(&metadata.filename)
                    .with_declared_mime(&metadata.mime);
                let verdict = scanner.scan(&input).await;
                if verdict.is_blocking() {
                    let reason = serde_json::to_string(&verdict).unwrap_or_else(|_| {
                        format!("{:?}", verdict.overall)
                    });
                    cfg.scan_cache
                        .write()
                        .await
                        .insert(transfer_id.to_string(), ScanVerdictCache::Blocked(reason.clone()));
                    return Err(DataPlaneError::ScannerBlocked { verdict: reason });
                }
                cfg.scan_cache
                    .write()
                    .await
                    .insert(transfer_id.to_string(), ScanVerdictCache::Clean);
            }
        }
    }

    // Stream payload.
    let bytes = cfg.blob_source.bytes(transfer_id).await?;
    let mut response_headers = HeaderMap::new();
    response_headers.insert(
        header::CONTENT_TYPE,
        metadata.mime.parse().unwrap_or_else(|_| {
            "application/octet-stream"
                .parse()
                .expect("fallback mime parses")
        }),
    );
    response_headers.insert(
        header::CONTENT_LENGTH,
        metadata.size.to_string().parse().unwrap(),
    );
    response_headers.insert(
        header::CONTENT_DISPOSITION,
        format!("attachment; filename=\"{}\"", metadata.filename)
            .parse()
            .unwrap(),
    );
    Ok((response_headers, Body::from(bytes)).into_response())
}
