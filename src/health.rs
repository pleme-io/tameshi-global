//! Health and readiness check endpoints.

use axum::http::StatusCode;
use axum::Json;
use serde::Serialize;
use std::sync::Arc;

use crate::state::GlobalStateRootChain;

/// Health check response.
#[derive(Clone, Debug, Serialize)]
pub struct HealthResponse {
    /// Server status: "healthy" or "unhealthy".
    pub status: String,
    /// Number of entries in the chain.
    pub chain_length: usize,
    /// Number of registered clusters.
    pub cluster_count: usize,
    /// Whether the chain integrity is valid.
    pub chain_valid: bool,
}

/// Readiness check response.
#[derive(Clone, Debug, Serialize)]
pub struct ReadyResponse {
    /// Whether the server is ready to accept requests.
    pub ready: bool,
    /// Reason if not ready.
    pub reason: Option<String>,
}

/// Build health check result (testable without axum response types).
#[must_use]
pub fn check_health(state: &GlobalStateRootChain) -> (StatusCode, HealthResponse) {
    let chain_valid = state.verify_integrity();
    let response = HealthResponse {
        status: if chain_valid {
            "healthy".to_string()
        } else {
            "unhealthy".to_string()
        },
        chain_length: state.len(),
        cluster_count: state.cluster_count(),
        chain_valid,
    };

    let status_code = if chain_valid {
        StatusCode::OK
    } else {
        StatusCode::INTERNAL_SERVER_ERROR
    };

    (status_code, response)
}

/// Build readiness check result (testable without axum response types).
#[must_use]
pub fn check_ready(state: &GlobalStateRootChain) -> (StatusCode, ReadyResponse) {
    let chain_valid = state.verify_integrity();
    let response = ReadyResponse {
        ready: chain_valid,
        reason: if chain_valid {
            None
        } else {
            Some("chain integrity check failed".to_string())
        },
    };

    let status_code = if chain_valid {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };

    (status_code, response)
}

/// Handle GET /healthz.
pub async fn healthz(
    axum::extract::State(state): axum::extract::State<Arc<GlobalStateRootChain>>,
) -> (StatusCode, Json<HealthResponse>) {
    let (status, body) = check_health(&state);
    (status, Json(body))
}

/// Handle GET /readyz.
pub async fn readyz(
    axum::extract::State(state): axum::extract::State<Arc<GlobalStateRootChain>>,
) -> (StatusCode, Json<ReadyResponse>) {
    let (status, body) = check_ready(&state);
    (status, Json(body))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::{ClusterRootEntry, ClusterStatus};

    #[test]
    fn health_response_serde() {
        let resp = HealthResponse {
            status: "healthy".into(),
            chain_length: 10,
            cluster_count: 3,
            chain_valid: true,
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("healthy"));
        assert!(json.contains("10"));
    }

    #[test]
    fn ready_response_serde_ready() {
        let resp = ReadyResponse {
            ready: true,
            reason: None,
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("true"));
    }

    #[test]
    fn ready_response_serde_not_ready() {
        let resp = ReadyResponse {
            ready: false,
            reason: Some("not initialized".into()),
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("not initialized"));
    }

    #[test]
    fn healthz_empty_chain_ok() {
        let state = GlobalStateRootChain::new();
        let (status, body) = check_health(&state);
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body.status, "healthy");
        assert!(body.chain_valid);
        assert_eq!(body.chain_length, 0);
        assert_eq!(body.cluster_count, 0);
    }

    #[test]
    fn healthz_with_clusters() {
        let state = GlobalStateRootChain::new();
        state.update_cluster(ClusterRootEntry {
            cluster_id: "plo".into(),
            cluster_root: [1u8; 32],
            node_count: 3,
            artifact_count: 100,
            last_reported: chrono::Utc::now(),
            status: ClusterStatus::Active,
        });
        let (status, body) = check_health(&state);
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body.chain_length, 1);
        assert_eq!(body.cluster_count, 1);
    }

    #[test]
    fn readyz_empty_chain_ok() {
        let state = GlobalStateRootChain::new();
        let (status, body) = check_ready(&state);
        assert_eq!(status, StatusCode::OK);
        assert!(body.ready);
        assert!(body.reason.is_none());
    }

    #[test]
    fn readyz_with_clusters() {
        let state = GlobalStateRootChain::new();
        state.update_cluster(ClusterRootEntry {
            cluster_id: "plo".into(),
            cluster_root: [1u8; 32],
            node_count: 3,
            artifact_count: 100,
            last_reported: chrono::Utc::now(),
            status: ClusterStatus::Active,
        });
        let (status, body) = check_ready(&state);
        assert_eq!(status, StatusCode::OK);
        assert!(body.ready);
    }
}
