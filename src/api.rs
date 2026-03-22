//! REST API handlers for the global state root server.
//!
//! Endpoints:
//! - `GET  /api/v1/global/state-root`           — current global state root
//! - `GET  /api/v1/global/blast-radius?hash=...` — blast radius for a hash
//! - `GET  /api/v1/global/clusters`              — all cluster entries
//! - `GET  /api/v1/global/clusters/:id`          — single cluster entry
//! - `POST /api/v1/global/clusters/:id/report`   — accept cluster report
//! - `POST /api/v1/global/revoke-everywhere`      — cross-cluster revocation
//! - `GET  /api/v1/global/health`                 — API-level health

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::metrics::Metrics;
use crate::remediation::{MockRevocationClient, Remediator, RevocationClient};
use crate::reporter::{ClusterReporter, ClusterRootReport};
use crate::reverse_index::ReverseIndex;
use crate::state::GlobalStateRootChain;

/// Shared application state for all handlers.
pub struct AppState<C: RevocationClient = MockRevocationClient> {
    pub reporter: ClusterReporter,
    pub chain: Arc<GlobalStateRootChain>,
    pub index: Arc<ReverseIndex>,
    pub remediator: Arc<tokio::sync::RwLock<Remediator<C>>>,
    pub metrics: Arc<Metrics>,
}

/// Query parameters for blast radius.
#[derive(Debug, Deserialize)]
pub struct BlastRadiusQuery {
    /// Hex-encoded hash to look up.
    pub hash: String,
}

/// Blast radius response.
#[derive(Debug, Serialize, Deserialize)]
pub struct BlastRadiusResponse {
    /// Hex-encoded query hash.
    pub query_hash: String,
    /// Clusters affected.
    pub clusters_affected: Vec<String>,
    /// Total locations.
    pub total_locations: usize,
    /// Per-location details.
    pub locations: Vec<LocationDetail>,
}

/// Single location detail in blast radius.
#[derive(Debug, Serialize, Deserialize)]
pub struct LocationDetail {
    pub cluster_id: String,
    pub node: String,
    pub namespace: String,
    pub binary_path: String,
}

/// Report acceptance response.
#[derive(Debug, Serialize, Deserialize)]
pub struct ReportResponse {
    /// New global state root sequence.
    pub sequence: u64,
    /// Hex-encoded new root hash.
    pub root_hash: String,
}

/// Error response body.
#[derive(Debug, Serialize, Deserialize)]
pub struct ErrorResponse {
    pub error: String,
}

/// Revocation request body.
#[derive(Debug, Deserialize)]
pub struct RevokeRequest {
    /// Hex-encoded hash to revoke.
    pub hash: String,
    /// Reason for revocation.
    pub reason: String,
}

/// Revocation response.
#[derive(Debug, Serialize, Deserialize)]
pub struct RevokeResponse {
    /// Per-cluster results.
    pub results: Vec<ClusterRevocationResult>,
    /// Total clusters targeted.
    pub total_clusters: usize,
    /// Clusters that succeeded.
    pub succeeded: usize,
    /// Clusters that failed.
    pub failed: usize,
}

/// Per-cluster result in revocation response.
#[derive(Debug, Serialize, Deserialize)]
pub struct ClusterRevocationResult {
    pub cluster_id: String,
    pub success: bool,
    pub error: Option<String>,
    pub artifacts_revoked: u64,
}

/// Cluster list response.
#[derive(Debug, Serialize, Deserialize)]
pub struct ClustersResponse {
    pub clusters: Vec<ClusterDetail>,
    pub total: usize,
}

/// Single cluster detail.
#[derive(Debug, Serialize, Deserialize)]
pub struct ClusterDetail {
    pub cluster_id: String,
    pub cluster_root: String,
    pub node_count: u32,
    pub artifact_count: u64,
    pub last_reported: String,
    pub status: String,
}

/// State root response.
#[derive(Debug, Serialize, Deserialize)]
pub struct StateRootResponse {
    pub root_hash: String,
    pub cluster_count: usize,
    pub sequence: u64,
    pub previous_root: String,
    pub computed_at: String,
}

/// GET /api/v1/global/state-root
pub async fn get_state_root<C: RevocationClient>(
    State(state): State<Arc<AppState<C>>>,
) -> Result<Json<StateRootResponse>, (StatusCode, Json<ErrorResponse>)> {
    match state.chain.latest() {
        Some(root) => Ok(Json(StateRootResponse {
            root_hash: const_hex::encode(root.root_hash),
            cluster_count: root.cluster_count,
            sequence: root.sequence,
            previous_root: const_hex::encode(root.previous_root),
            computed_at: root.computed_at.to_rfc3339(),
        })),
        None => Err((
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "no state root computed yet".into(),
            }),
        )),
    }
}

/// GET /api/v1/global/blast-radius?hash=...
pub async fn get_blast_radius<C: RevocationClient>(
    State(state): State<Arc<AppState<C>>>,
    Query(params): Query<BlastRadiusQuery>,
) -> Result<Json<BlastRadiusResponse>, (StatusCode, Json<ErrorResponse>)> {
    let hash_bytes: [u8; 32] = const_hex::decode(&params.hash)
        .ok()
        .and_then(|b| <[u8; 32]>::try_from(b).ok())
        .ok_or_else(|| {
            (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "invalid hash: must be 64 hex characters".into(),
                }),
            )
        })?;

    state.metrics.hash_lookups.inc();

    let locations = state.index.lookup(&hash_bytes);
    let clusters = state.index.clusters_for_hash(&hash_bytes);

    Ok(Json(BlastRadiusResponse {
        query_hash: params.hash,
        clusters_affected: clusters,
        total_locations: locations.len(),
        locations: locations
            .into_iter()
            .map(|l| LocationDetail {
                cluster_id: l.cluster_id,
                node: l.node,
                namespace: l.namespace,
                binary_path: l.binary_path,
            })
            .collect(),
    }))
}

/// GET /api/v1/global/clusters
pub async fn get_clusters<C: RevocationClient>(
    State(state): State<Arc<AppState<C>>>,
) -> Json<ClustersResponse> {
    let clusters = state.chain.clusters();
    let details: Vec<ClusterDetail> = clusters
        .values()
        .map(|e| ClusterDetail {
            cluster_id: e.cluster_id.clone(),
            cluster_root: const_hex::encode(e.cluster_root),
            node_count: e.node_count,
            artifact_count: e.artifact_count,
            last_reported: e.last_reported.to_rfc3339(),
            status: format!("{:?}", e.status),
        })
        .collect();
    let total = details.len();
    Json(ClustersResponse {
        clusters: details,
        total,
    })
}

/// GET /api/v1/global/clusters/:id
pub async fn get_cluster<C: RevocationClient>(
    State(state): State<Arc<AppState<C>>>,
    Path(cluster_id): Path<String>,
) -> Result<Json<ClusterDetail>, (StatusCode, Json<ErrorResponse>)> {
    match state.chain.get_cluster(&cluster_id) {
        Some(e) => Ok(Json(ClusterDetail {
            cluster_id: e.cluster_id,
            cluster_root: const_hex::encode(e.cluster_root),
            node_count: e.node_count,
            artifact_count: e.artifact_count,
            last_reported: e.last_reported.to_rfc3339(),
            status: format!("{:?}", e.status),
        })),
        None => Err((
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: format!("cluster not found: {cluster_id}"),
            }),
        )),
    }
}

/// POST /api/v1/global/clusters/:id/report
pub async fn post_report<C: RevocationClient>(
    State(state): State<Arc<AppState<C>>>,
    Path(cluster_id): Path<String>,
    Json(mut report): Json<ClusterRootReport>,
) -> Result<Json<ReportResponse>, (StatusCode, Json<ErrorResponse>)> {
    // Override cluster_id from path
    report.cluster_id = cluster_id;

    match state.reporter.accept_report(report) {
        Ok(sequence) => {
            state.metrics.reports_accepted.inc();
            state
                .metrics
                .cluster_count
                .set(state.chain.cluster_count() as i64);
            state.metrics.chain_length.set(state.chain.len() as i64);

            let root_hash = state
                .chain
                .latest()
                .map(|r| const_hex::encode(r.root_hash))
                .unwrap_or_default();

            Ok(Json(ReportResponse {
                sequence,
                root_hash,
            }))
        }
        Err(e) => {
            state.metrics.reports_rejected.inc();
            Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: e.to_string(),
                }),
            ))
        }
    }
}

/// POST /api/v1/global/revoke-everywhere
pub async fn post_revoke<C: RevocationClient>(
    State(state): State<Arc<AppState<C>>>,
    Json(req): Json<RevokeRequest>,
) -> Result<Json<RevokeResponse>, (StatusCode, Json<ErrorResponse>)> {
    let hash_bytes: [u8; 32] = const_hex::decode(&req.hash)
        .ok()
        .and_then(|b| <[u8; 32]>::try_from(b).ok())
        .ok_or_else(|| {
            (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "invalid hash: must be 64 hex characters".into(),
                }),
            )
        })?;

    state.metrics.revocations_initiated.inc();

    let remediator = state.remediator.read().await;
    let results = remediator.revoke_everywhere(&hash_bytes, &req.reason).await;

    let succeeded = results.iter().filter(|r| r.success).count();
    let failed = results.iter().filter(|r| !r.success).count();

    state
        .metrics
        .revocations_succeeded
        .inc_by(succeeded as u64);
    state.metrics.revocations_failed.inc_by(failed as u64);

    let total_clusters = results.len();
    let cluster_results: Vec<ClusterRevocationResult> = results
        .into_iter()
        .map(|r| ClusterRevocationResult {
            cluster_id: r.cluster_id,
            success: r.success,
            error: r.error,
            artifacts_revoked: r.artifacts_revoked,
        })
        .collect();

    Ok(Json(RevokeResponse {
        results: cluster_results,
        total_clusters,
        succeeded,
        failed,
    }))
}

/// GET /api/v1/global/health
pub async fn api_health<C: RevocationClient>(
    State(state): State<Arc<AppState<C>>>,
) -> Json<serde_json::Value> {
    let chain_valid = state.chain.verify_integrity();
    Json(serde_json::json!({
        "status": if chain_valid { "healthy" } else { "unhealthy" },
        "chain_length": state.chain.len(),
        "cluster_count": state.chain.cluster_count(),
        "index_hashes": state.index.hash_count(),
        "index_locations": state.index.total_locations(),
    }))
}

/// Build the axum router for the API.
pub fn router<C: RevocationClient + 'static>(
    state: Arc<AppState<C>>,
) -> axum::Router {
    use axum::routing::{get, post};

    axum::Router::new()
        .route("/api/v1/global/state-root", get(get_state_root::<C>))
        .route("/api/v1/global/blast-radius", get(get_blast_radius::<C>))
        .route("/api/v1/global/clusters", get(get_clusters::<C>))
        .route("/api/v1/global/clusters/{id}", get(get_cluster::<C>))
        .route(
            "/api/v1/global/clusters/{id}/report",
            post(post_report::<C>),
        )
        .route(
            "/api/v1/global/revoke-everywhere",
            post(post_revoke::<C>),
        )
        .route("/api/v1/global/health", get(api_health::<C>))
        .with_state(state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::remediation::MockRevocationClient;
    use crate::reverse_index::ArtifactLocation;
    use axum::body::Body;
    use axum::http::Request;
    use std::collections::BTreeMap;
    use tower::ServiceExt;

    fn make_app_state() -> Arc<AppState<MockRevocationClient>> {
        let chain = Arc::new(GlobalStateRootChain::new());
        let index = Arc::new(ReverseIndex::new());
        let reporter = ClusterReporter::new(Arc::clone(&chain), Arc::clone(&index));
        let remediator = Remediator::new(BTreeMap::new(), MockRevocationClient::new());
        let metrics = Arc::new(Metrics::new());

        Arc::new(AppState {
            reporter,
            chain,
            index,
            remediator: Arc::new(tokio::sync::RwLock::new(remediator)),
            metrics,
        })
    }

    fn make_app(
        state: Arc<AppState<MockRevocationClient>>,
    ) -> axum::Router {
        router(state)
    }

    #[tokio::test]
    async fn get_state_root_empty() {
        let state = make_app_state();
        let app = make_app(state);
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/global/state-root")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn get_state_root_after_report() {
        let state = make_app_state();
        // Manually update to have a root
        state.chain.update_cluster(crate::state::ClusterRootEntry {
            cluster_id: "plo".into(),
            cluster_root: [1u8; 32],
            node_count: 3,
            artifact_count: 100,
            last_reported: chrono::Utc::now(),
            status: crate::state::ClusterStatus::Active,
        });

        let app = make_app(state);
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/global/state-root")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn get_clusters_empty() {
        let state = make_app_state();
        let app = make_app(state);
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/global/clusters")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
            .await
            .unwrap();
        let json: ClustersResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(json.total, 0);
    }

    #[tokio::test]
    async fn get_clusters_with_data() {
        let state = make_app_state();
        state.chain.update_cluster(crate::state::ClusterRootEntry {
            cluster_id: "plo".into(),
            cluster_root: [1u8; 32],
            node_count: 3,
            artifact_count: 100,
            last_reported: chrono::Utc::now(),
            status: crate::state::ClusterStatus::Active,
        });
        let app = make_app(state);
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/global/clusters")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
            .await
            .unwrap();
        let json: ClustersResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(json.total, 1);
    }

    #[tokio::test]
    async fn get_cluster_not_found() {
        let state = make_app_state();
        let app = make_app(state);
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/global/clusters/nope")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn get_cluster_found() {
        let state = make_app_state();
        state.chain.update_cluster(crate::state::ClusterRootEntry {
            cluster_id: "plo".into(),
            cluster_root: [1u8; 32],
            node_count: 3,
            artifact_count: 100,
            last_reported: chrono::Utc::now(),
            status: crate::state::ClusterStatus::Active,
        });
        let app = make_app(state);
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/global/clusters/plo")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn blast_radius_empty() {
        let state = make_app_state();
        let hash_hex = const_hex::encode([1u8; 32]);
        let app = make_app(state);
        let resp = app
            .oneshot(
                Request::builder()
                    .uri(&format!("/api/v1/global/blast-radius?hash={hash_hex}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
            .await
            .unwrap();
        let json: BlastRadiusResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(json.total_locations, 0);
    }

    #[tokio::test]
    async fn blast_radius_with_data() {
        let state = make_app_state();
        state.index.insert(ArtifactLocation {
            cluster_id: "plo".into(),
            node: "node-1".into(),
            namespace: "default".into(),
            binary_path: "/usr/bin/app".into(),
            composed_root: [1u8; 32],
        });
        let hash_hex = const_hex::encode([1u8; 32]);
        let app = make_app(state);
        let resp = app
            .oneshot(
                Request::builder()
                    .uri(&format!("/api/v1/global/blast-radius?hash={hash_hex}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
            .await
            .unwrap();
        let json: BlastRadiusResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(json.total_locations, 1);
        assert_eq!(json.clusters_affected, vec!["plo"]);
    }

    #[tokio::test]
    async fn blast_radius_invalid_hash() {
        let state = make_app_state();
        let app = make_app(state);
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/global/blast-radius?hash=badhex")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn post_report_valid() {
        let state = make_app_state();
        let report = ClusterRootReport {
            cluster_id: "plo".into(),
            cluster_root: [1u8; 32],
            node_count: 3,
            artifact_count: 100,
            reported_at: chrono::Utc::now(),
            artifacts: vec![],
        };
        let body = serde_json::to_string(&report).unwrap();
        let app = make_app(state);
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/global/clusters/plo/report")
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn post_report_invalid_node_count() {
        let state = make_app_state();
        let report = ClusterRootReport {
            cluster_id: "plo".into(),
            cluster_root: [1u8; 32],
            node_count: 0,
            artifact_count: 100,
            reported_at: chrono::Utc::now(),
            artifacts: vec![],
        };
        let body = serde_json::to_string(&report).unwrap();
        let app = make_app(state);
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/global/clusters/plo/report")
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn post_revoke_empty_clusters() {
        let state = make_app_state();
        let req = serde_json::json!({
            "hash": const_hex::encode([1u8; 32]),
            "reason": "CVE-2026-001",
        });
        let app = make_app(state);
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/global/revoke-everywhere")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_string(&req).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
            .await
            .unwrap();
        let json: RevokeResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(json.total_clusters, 0);
    }

    #[tokio::test]
    async fn post_revoke_invalid_hash() {
        let state = make_app_state();
        let req = serde_json::json!({
            "hash": "bad",
            "reason": "test",
        });
        let app = make_app(state);
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/global/revoke-everywhere")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_string(&req).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn api_health_endpoint() {
        let state = make_app_state();
        let app = make_app(state);
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/global/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn report_increments_metrics() {
        let state = make_app_state();
        let report = ClusterRootReport {
            cluster_id: "plo".into(),
            cluster_root: [1u8; 32],
            node_count: 3,
            artifact_count: 100,
            reported_at: chrono::Utc::now(),
            artifacts: vec![],
        };
        let body = serde_json::to_string(&report).unwrap();
        let app = make_app(Arc::clone(&state));
        app.oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/global/clusters/plo/report")
                .header("content-type", "application/json")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(state.metrics.reports_accepted.get(), 1);
    }

    #[tokio::test]
    async fn rejected_report_increments_metrics() {
        let state = make_app_state();
        let report = ClusterRootReport {
            cluster_id: "plo".into(),
            cluster_root: [1u8; 32],
            node_count: 0,
            artifact_count: 100,
            reported_at: chrono::Utc::now(),
            artifacts: vec![],
        };
        let body = serde_json::to_string(&report).unwrap();
        let app = make_app(Arc::clone(&state));
        app.oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/global/clusters/plo/report")
                .header("content-type", "application/json")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(state.metrics.reports_rejected.get(), 1);
    }

    #[test]
    fn blast_radius_response_serde() {
        let resp = BlastRadiusResponse {
            query_hash: "abc".into(),
            clusters_affected: vec!["plo".into()],
            total_locations: 1,
            locations: vec![LocationDetail {
                cluster_id: "plo".into(),
                node: "n1".into(),
                namespace: "default".into(),
                binary_path: "/bin/app".into(),
            }],
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("plo"));
    }

    #[test]
    fn report_response_serde() {
        let resp = ReportResponse {
            sequence: 42,
            root_hash: "abc".into(),
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("42"));
    }

    #[test]
    fn error_response_serde() {
        let resp = ErrorResponse {
            error: "something broke".into(),
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("something broke"));
    }

    #[test]
    fn revoke_response_serde() {
        let resp = RevokeResponse {
            results: vec![],
            total_clusters: 0,
            succeeded: 0,
            failed: 0,
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("total_clusters"));
    }

    #[test]
    fn clusters_response_serde() {
        let resp = ClustersResponse {
            clusters: vec![],
            total: 0,
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("total"));
    }
}
