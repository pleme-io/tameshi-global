//! End-to-end integration tests with mock clusters.

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

use tameshi_global::api::{self, AppState, BlastRadiusResponse, ClustersResponse, ReportResponse, RevokeResponse, StateRootResponse};
use tameshi_global::metrics::Metrics;
use tameshi_global::remediation::{MockRevocationClient, Remediator, RevocationResponse};
use tameshi_global::reporter::{ClusterReporter, ClusterRootReport};
use tameshi_global::reverse_index::{ArtifactLocation, ReverseIndex};
use tameshi_global::state::GlobalStateRootChain;

fn make_app_state_with_remediator(
    client: MockRevocationClient,
    endpoints: BTreeMap<String, String>,
) -> Arc<AppState<MockRevocationClient>> {
    let chain = Arc::new(GlobalStateRootChain::new());
    let index = Arc::new(ReverseIndex::new());
    let reporter = ClusterReporter::new(Arc::clone(&chain), Arc::clone(&index));
    let remediator = Remediator::new(endpoints, client);
    let metrics = Arc::new(Metrics::new());

    Arc::new(AppState {
        reporter,
        chain,
        index,
        remediator: Arc::new(tokio::sync::RwLock::new(remediator)),
        metrics,
    })
}

fn make_artifact(cluster: &str, node: &str, hash: [u8; 32]) -> ArtifactLocation {
    ArtifactLocation {
        cluster_id: cluster.to_string(),
        node: node.to_string(),
        namespace: "prod".to_string(),
        binary_path: format!("/usr/bin/{cluster}-app"),
        composed_root: hash,
    }
}

/// Compute the expected cluster root from artifacts (sort + dedup + concat + blake3).
fn compute_expected_root(artifacts: &[ArtifactLocation]) -> [u8; 32] {
    let mut hashes: Vec<[u8; 32]> = artifacts.iter().map(|a| a.composed_root).collect();
    hashes.sort();
    hashes.dedup();
    let mut data = Vec::with_capacity(hashes.len() * 32);
    for h in &hashes {
        data.extend_from_slice(h);
    }
    *blake3::hash(&data).as_bytes()
}

#[tokio::test]
async fn full_pipeline_three_clusters() {
    let client = MockRevocationClient::new();
    let mut endpoints = BTreeMap::new();
    endpoints.insert("plo".to_string(), "http://plo:8080".to_string());
    endpoints.insert("zek".to_string(), "http://zek:8080".to_string());
    endpoints.insert("edge".to_string(), "http://edge:8080".to_string());

    client.set_response("http://plo:8080", RevocationResponse {
        success: true,
        artifacts_revoked: 2,
        error: None,
    });
    client.set_response("http://zek:8080", RevocationResponse {
        success: true,
        artifacts_revoked: 1,
        error: None,
    });
    client.set_response("http://edge:8080", RevocationResponse {
        success: false,
        artifacts_revoked: 0,
        error: Some("timeout".into()),
    });

    let state = make_app_state_with_remediator(client, endpoints);

    // Step 1: Report from 3 clusters
    let plo_artifacts = vec![
        make_artifact("plo", "node-1", [1u8; 32]),
        make_artifact("plo", "node-2", [2u8; 32]),
    ];
    let plo_root = compute_expected_root(&plo_artifacts);

    let zek_artifacts = vec![
        make_artifact("zek", "node-1", [1u8; 32]), // same hash as plo!
        make_artifact("zek", "node-1", [3u8; 32]),
    ];
    let zek_root = compute_expected_root(&zek_artifacts);

    let edge_artifacts = vec![
        make_artifact("edge", "node-1", [4u8; 32]),
    ];
    let edge_root = compute_expected_root(&edge_artifacts);

    // Submit plo report
    let report = ClusterRootReport {
        cluster_id: "plo".into(),
        cluster_root: plo_root,
        node_count: 2,
        artifact_count: 2,
        reported_at: chrono::Utc::now(),
        artifacts: plo_artifacts,
    };
    let app = api::router(Arc::clone(&state));
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/global/clusters/plo/report")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&report).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
    let report_resp: ReportResponse = serde_json::from_slice(&body).unwrap();
    assert_eq!(report_resp.sequence, 0);

    // Submit zek report
    let report = ClusterRootReport {
        cluster_id: "zek".into(),
        cluster_root: zek_root,
        node_count: 1,
        artifact_count: 2,
        reported_at: chrono::Utc::now(),
        artifacts: zek_artifacts,
    };
    let app = api::router(Arc::clone(&state));
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/global/clusters/zek/report")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&report).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Submit edge report
    let report = ClusterRootReport {
        cluster_id: "edge".into(),
        cluster_root: edge_root,
        node_count: 1,
        artifact_count: 1,
        reported_at: chrono::Utc::now(),
        artifacts: edge_artifacts,
    };
    let app = api::router(Arc::clone(&state));
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/global/clusters/edge/report")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&report).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Step 2: Verify state root
    let app = api::router(Arc::clone(&state));
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
    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
    let root: StateRootResponse = serde_json::from_slice(&body).unwrap();
    assert_eq!(root.cluster_count, 3);
    assert_eq!(root.sequence, 2);

    // Step 3: Check clusters
    let app = api::router(Arc::clone(&state));
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/global/clusters")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
    let clusters: ClustersResponse = serde_json::from_slice(&body).unwrap();
    assert_eq!(clusters.total, 3);

    // Step 4: Blast radius for hash [1u8;32] — should be in plo and zek
    let hash_hex = const_hex::encode([1u8; 32]);
    let app = api::router(Arc::clone(&state));
    let resp = app
        .oneshot(
            Request::builder()
                .uri(&format!("/api/v1/global/blast-radius?hash={hash_hex}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
    let blast: BlastRadiusResponse = serde_json::from_slice(&body).unwrap();
    assert_eq!(blast.clusters_affected.len(), 2);
    assert!(blast.clusters_affected.contains(&"plo".to_string()));
    assert!(blast.clusters_affected.contains(&"zek".to_string()));
    assert_eq!(blast.total_locations, 2);

    // Step 5: Revoke everywhere
    let revoke_req = serde_json::json!({
        "hash": hash_hex,
        "reason": "CVE-2026-001",
    });
    let app = api::router(Arc::clone(&state));
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/global/revoke-everywhere")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&revoke_req).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
    let revoke: RevokeResponse = serde_json::from_slice(&body).unwrap();
    assert_eq!(revoke.total_clusters, 3);
    assert_eq!(revoke.succeeded, 2);
    assert_eq!(revoke.failed, 1);

    // Step 6: Verify chain integrity
    assert!(state.chain.verify_integrity());

    // Step 7: Check metrics
    assert_eq!(state.metrics.reports_accepted.get(), 3);
    assert!(state.metrics.hash_lookups.get() >= 1);
    assert_eq!(state.metrics.revocations_initiated.get(), 1);
}

#[tokio::test]
async fn report_then_update_same_cluster() {
    let state = make_app_state_with_remediator(MockRevocationClient::new(), BTreeMap::new());

    // First report
    let report = ClusterRootReport {
        cluster_id: "plo".into(),
        cluster_root: [1u8; 32],
        node_count: 3,
        artifact_count: 100,
        reported_at: chrono::Utc::now(),
        artifacts: vec![],
    };
    let app = api::router(Arc::clone(&state));
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/global/clusters/plo/report")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&report).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Second report — updates the same cluster
    let report2 = ClusterRootReport {
        cluster_id: "plo".into(),
        cluster_root: [2u8; 32],
        node_count: 5,
        artifact_count: 200,
        reported_at: chrono::Utc::now(),
        artifacts: vec![],
    };
    let app = api::router(Arc::clone(&state));
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/global/clusters/plo/report")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&report2).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Verify cluster was updated
    let entry = state.chain.get_cluster("plo").unwrap();
    assert_eq!(entry.cluster_root, [2u8; 32]);
    assert_eq!(entry.node_count, 5);

    // Chain has 2 entries but only 1 cluster
    assert_eq!(state.chain.len(), 2);
    assert_eq!(state.chain.cluster_count(), 1);
}

#[tokio::test]
async fn health_endpoint_returns_ok() {
    let state = make_app_state_with_remediator(MockRevocationClient::new(), BTreeMap::new());
    let app = api::router(state);
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
    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["status"], "healthy");
}

#[tokio::test]
async fn chain_integrity_preserved_across_operations() {
    let state = make_app_state_with_remediator(MockRevocationClient::new(), BTreeMap::new());

    // Add 5 clusters
    for i in 0..5u8 {
        let report = ClusterRootReport {
            cluster_id: format!("c{i}"),
            cluster_root: [i; 32],
            node_count: 1,
            artifact_count: 10,
            reported_at: chrono::Utc::now(),
            artifacts: vec![],
        };
        let app = api::router(Arc::clone(&state));
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(&format!("/api/v1/global/clusters/c{i}/report"))
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_string(&report).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    // Update 2 clusters
    for i in 0..2u8 {
        let report = ClusterRootReport {
            cluster_id: format!("c{i}"),
            cluster_root: [i + 100; 32],
            node_count: 2,
            artifact_count: 20,
            reported_at: chrono::Utc::now(),
            artifacts: vec![],
        };
        let app = api::router(Arc::clone(&state));
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(&format!("/api/v1/global/clusters/c{i}/report"))
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_string(&report).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    assert_eq!(state.chain.len(), 7); // 5 + 2
    assert_eq!(state.chain.cluster_count(), 5);
    assert!(state.chain.verify_integrity());
}
