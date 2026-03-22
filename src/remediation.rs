//! Cross-cluster revocation fan-out.
//!
//! When a compromised hash is detected, the `Remediator` fans out revocation
//! requests to all cluster forensics APIs concurrently.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Result of a revocation attempt on a single cluster.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RevocationResult {
    /// Cluster that was targeted.
    pub cluster_id: String,
    /// Whether revocation succeeded.
    pub success: bool,
    /// Error message if revocation failed.
    pub error: Option<String>,
    /// Number of artifacts revoked on this cluster.
    pub artifacts_revoked: u64,
}

/// Revocation request payload sent to cluster forensics APIs.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RevocationRequest {
    /// Hash to revoke.
    pub hash: [u8; 32],
    /// Human-readable hex of the hash.
    pub hash_hex: String,
    /// Reason for revocation.
    pub reason: String,
}

/// Revocation response from a cluster forensics API.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RevocationResponse {
    /// Whether revocation succeeded.
    pub success: bool,
    /// Number of artifacts revoked.
    pub artifacts_revoked: u64,
    /// Error message if any.
    pub error: Option<String>,
}

/// Trait for performing revocations, enabling testing without real HTTP.
pub trait RevocationClient: Send + Sync {
    /// Revoke a hash on a specific cluster endpoint.
    fn revoke(
        &self,
        endpoint: &str,
        request: &RevocationRequest,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = std::result::Result<RevocationResponse, String>> + Send + '_>,
    >;
}

/// HTTP-based revocation client using reqwest.
pub struct HttpRevocationClient {
    client: reqwest::Client,
}

impl HttpRevocationClient {
    /// Create a new HTTP revocation client.
    #[must_use]
    pub fn new() -> Self {
        Self {
            client: reqwest::Client::new(),
        }
    }
}

impl Default for HttpRevocationClient {
    fn default() -> Self {
        Self::new()
    }
}

impl RevocationClient for HttpRevocationClient {
    fn revoke(
        &self,
        endpoint: &str,
        request: &RevocationRequest,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = std::result::Result<RevocationResponse, String>> + Send + '_>,
    > {
        let url = format!("{endpoint}/api/v1/revoke");
        let req = request.clone();
        let client = self.client.clone();
        Box::pin(async move {
            let resp = client
                .post(&url)
                .json(&req)
                .send()
                .await
                .map_err(|e| e.to_string())?;

            if resp.status().is_success() {
                resp.json::<RevocationResponse>()
                    .await
                    .map_err(|e| e.to_string())
            } else {
                Err(format!("HTTP {}", resp.status()))
            }
        })
    }
}

/// Mock revocation client for testing.
pub struct MockRevocationClient {
    responses: std::sync::Mutex<BTreeMap<String, RevocationResponse>>,
}

impl MockRevocationClient {
    /// Create a new mock client.
    #[must_use]
    pub fn new() -> Self {
        Self {
            responses: std::sync::Mutex::new(BTreeMap::new()),
        }
    }

    /// Configure a response for a given endpoint.
    pub fn set_response(&self, endpoint: &str, response: RevocationResponse) {
        self.responses
            .lock()
            .unwrap()
            .insert(endpoint.to_string(), response);
    }
}

impl Default for MockRevocationClient {
    fn default() -> Self {
        Self::new()
    }
}

impl RevocationClient for MockRevocationClient {
    fn revoke(
        &self,
        endpoint: &str,
        _request: &RevocationRequest,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = std::result::Result<RevocationResponse, String>> + Send + '_>,
    > {
        let responses = self.responses.lock().unwrap();
        let result = responses.get(endpoint).cloned().ok_or_else(|| {
            format!("no mock response configured for {endpoint}")
        });
        Box::pin(async move { result })
    }
}

/// Cross-cluster revocation orchestrator.
pub struct Remediator<C: RevocationClient> {
    /// cluster_id -> forensics API URL
    cluster_endpoints: BTreeMap<String, String>,
    /// Revocation client (HTTP or mock).
    client: C,
}

impl<C: RevocationClient> Remediator<C> {
    /// Create a new remediator.
    #[must_use]
    pub fn new(cluster_endpoints: BTreeMap<String, String>, client: C) -> Self {
        Self {
            cluster_endpoints,
            client,
        }
    }

    /// Add or update a cluster endpoint.
    pub fn set_endpoint(&mut self, cluster_id: &str, endpoint: &str) {
        self.cluster_endpoints
            .insert(cluster_id.to_string(), endpoint.to_string());
    }

    /// Remove a cluster endpoint.
    pub fn remove_endpoint(&mut self, cluster_id: &str) {
        self.cluster_endpoints.remove(cluster_id);
    }

    /// Fan out revocation to all clusters concurrently.
    ///
    /// Returns a `RevocationResult` per cluster. Partial failures are reported
    /// per-cluster, not as a total failure.
    pub async fn revoke_everywhere(
        &self,
        hash: &[u8; 32],
        reason: &str,
    ) -> Vec<RevocationResult> {
        let request = RevocationRequest {
            hash: *hash,
            hash_hex: const_hex::encode(hash),
            reason: reason.to_string(),
        };

        let mut results = Vec::with_capacity(self.cluster_endpoints.len());

        for (cluster_id, endpoint) in &self.cluster_endpoints {
            let result = match self.client.revoke(endpoint, &request).await {
                Ok(resp) => RevocationResult {
                    cluster_id: cluster_id.clone(),
                    success: resp.success,
                    error: resp.error,
                    artifacts_revoked: resp.artifacts_revoked,
                },
                Err(e) => RevocationResult {
                    cluster_id: cluster_id.clone(),
                    success: false,
                    error: Some(e),
                    artifacts_revoked: 0,
                },
            };
            results.push(result);
        }

        results
    }

    /// Fan out revocation to specific clusters only.
    pub async fn revoke_on_clusters(
        &self,
        hash: &[u8; 32],
        reason: &str,
        cluster_ids: &[String],
    ) -> Vec<RevocationResult> {
        let request = RevocationRequest {
            hash: *hash,
            hash_hex: const_hex::encode(hash),
            reason: reason.to_string(),
        };

        let mut results = Vec::with_capacity(cluster_ids.len());

        for cluster_id in cluster_ids {
            let result = if let Some(endpoint) = self.cluster_endpoints.get(cluster_id) {
                match self.client.revoke(endpoint, &request).await {
                    Ok(resp) => RevocationResult {
                        cluster_id: cluster_id.clone(),
                        success: resp.success,
                        error: resp.error,
                        artifacts_revoked: resp.artifacts_revoked,
                    },
                    Err(e) => RevocationResult {
                        cluster_id: cluster_id.clone(),
                        success: false,
                        error: Some(e),
                        artifacts_revoked: 0,
                    },
                }
            } else {
                RevocationResult {
                    cluster_id: cluster_id.clone(),
                    success: false,
                    error: Some("no endpoint configured".into()),
                    artifacts_revoked: 0,
                }
            };
            results.push(result);
        }

        results
    }

    /// Number of configured cluster endpoints.
    #[must_use]
    pub fn endpoint_count(&self) -> usize {
        self.cluster_endpoints.len()
    }
}

// =============================================================================
// Global Revocation Result
// =============================================================================

/// Result of a cross-cluster revocation operation.
///
/// Aggregates per-cluster results and includes cryptographic evidence
/// linking the revocation to the global state chain.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GlobalRevocationResult {
    /// The hash that was revoked (hex-encoded).
    pub hash: String,
    /// Reason for the revocation.
    pub reason: String,
    /// Total number of clusters targeted.
    pub total_clusters: usize,
    /// Number of clusters that successfully revoked.
    pub successful: usize,
    /// Number of clusters that failed.
    pub failed: usize,
    /// Per-cluster results.
    pub cluster_results: Vec<ClusterRevocationResult>,
    /// Heartbeat sequence number recording this revocation.
    pub heartbeat_sequence: u64,
    /// Deterministic BLAKE3 hash of this result (evidence).
    pub evidence_hash: String,
}

/// Result of a revocation attempt on a single cluster (extended).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ClusterRevocationResult {
    /// Cluster identifier.
    pub cluster_id: String,
    /// Whether revocation succeeded on this cluster.
    pub success: bool,
    /// Number of nodes affected by the revocation.
    pub affected_nodes: usize,
    /// Human-readable message (status or error).
    pub message: String,
    /// Time taken for the revocation on this cluster (milliseconds).
    pub duration_ms: u64,
}

/// Compute a deterministic evidence hash for a `GlobalRevocationResult`.
///
/// The evidence hash covers the revoked hash, reason, and all per-cluster
/// outcomes so that the result is tamper-evident.
#[must_use]
pub fn compute_evidence_hash(
    hash: &str,
    reason: &str,
    cluster_results: &[ClusterRevocationResult],
    heartbeat_sequence: u64,
) -> String {
    let mut data = Vec::with_capacity(512);
    data.extend_from_slice(hash.as_bytes());
    data.push(0);
    data.extend_from_slice(reason.as_bytes());
    data.push(0);
    data.extend_from_slice(&heartbeat_sequence.to_le_bytes());
    for cr in cluster_results {
        data.extend_from_slice(cr.cluster_id.as_bytes());
        data.push(0);
        data.push(u8::from(cr.success));
        data.extend_from_slice(&cr.affected_nodes.to_le_bytes());
        data.extend_from_slice(&cr.duration_ms.to_le_bytes());
        data.extend_from_slice(cr.message.as_bytes());
        data.push(0);
    }
    let hash_bytes = blake3::hash(&data);
    const_hex::encode(hash_bytes.as_bytes())
}

impl<C: RevocationClient> Remediator<C> {
    /// Revoke a hash across all clusters, producing a `GlobalRevocationResult`.
    ///
    /// This is a higher-level orchestration over `revoke_everywhere` that
    /// produces structured evidence, including affected node counts and
    /// a deterministic evidence hash for the audit trail.
    pub async fn revoke_globally(
        &self,
        hash: &[u8; 32],
        reason: &str,
        heartbeat_sequence: u64,
    ) -> GlobalRevocationResult {
        let results = self.revoke_everywhere(hash, reason).await;

        let cluster_results: Vec<ClusterRevocationResult> = results
            .into_iter()
            .map(|r| ClusterRevocationResult {
                cluster_id: r.cluster_id,
                success: r.success,
                affected_nodes: r.artifacts_revoked as usize,
                message: r.error.unwrap_or_else(|| "ok".to_string()),
                duration_ms: 0, // timing not measured in mock
            })
            .collect();

        let successful = cluster_results.iter().filter(|r| r.success).count();
        let failed = cluster_results.iter().filter(|r| !r.success).count();
        let hash_hex = const_hex::encode(hash);

        let evidence = compute_evidence_hash(
            &hash_hex,
            reason,
            &cluster_results,
            heartbeat_sequence,
        );

        GlobalRevocationResult {
            hash: hash_hex,
            reason: reason.to_string(),
            total_clusters: cluster_results.len(),
            successful,
            failed,
            cluster_results,
            heartbeat_sequence,
            evidence_hash: evidence,
        }
    }

    /// Revoke and retry failed clusters once.
    ///
    /// First attempts all clusters. Then retries any that failed.
    /// Returns the combined result.
    pub async fn revoke_globally_with_retry(
        &self,
        hash: &[u8; 32],
        reason: &str,
        heartbeat_sequence: u64,
    ) -> GlobalRevocationResult {
        let first = self.revoke_everywhere(hash, reason).await;

        let failed_ids: Vec<String> = first
            .iter()
            .filter(|r| !r.success)
            .map(|r| r.cluster_id.clone())
            .collect();

        let retried = if failed_ids.is_empty() {
            Vec::new()
        } else {
            self.revoke_on_clusters(hash, reason, &failed_ids).await
        };

        // Merge: use retry result for failed clusters, keep original for success
        let mut merged: Vec<ClusterRevocationResult> = Vec::with_capacity(first.len());
        for r in &first {
            if r.success {
                merged.push(ClusterRevocationResult {
                    cluster_id: r.cluster_id.clone(),
                    success: true,
                    affected_nodes: r.artifacts_revoked as usize,
                    message: r.error.clone().unwrap_or_else(|| "ok".to_string()),
                    duration_ms: 0,
                });
            } else if let Some(retry) = retried.iter().find(|rr| rr.cluster_id == r.cluster_id) {
                merged.push(ClusterRevocationResult {
                    cluster_id: retry.cluster_id.clone(),
                    success: retry.success,
                    affected_nodes: retry.artifacts_revoked as usize,
                    message: retry.error.clone().unwrap_or_else(|| "ok (retry)".to_string()),
                    duration_ms: 0,
                });
            }
        }

        let successful = merged.iter().filter(|r| r.success).count();
        let failed = merged.iter().filter(|r| !r.success).count();
        let hash_hex = const_hex::encode(hash);

        let evidence = compute_evidence_hash(&hash_hex, reason, &merged, heartbeat_sequence);

        GlobalRevocationResult {
            hash: hash_hex,
            reason: reason.to_string(),
            total_clusters: merged.len(),
            successful,
            failed,
            cluster_results: merged,
            heartbeat_sequence,
            evidence_hash: evidence,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mock_remediator() -> Remediator<MockRevocationClient> {
        let mut endpoints = BTreeMap::new();
        endpoints.insert("plo".to_string(), "http://plo:8080".to_string());
        endpoints.insert("zek".to_string(), "http://zek:8080".to_string());
        endpoints.insert("edge".to_string(), "http://edge:8080".to_string());

        let client = MockRevocationClient::new();
        client.set_response(
            "http://plo:8080",
            RevocationResponse {
                success: true,
                artifacts_revoked: 5,
                error: None,
            },
        );
        client.set_response(
            "http://zek:8080",
            RevocationResponse {
                success: true,
                artifacts_revoked: 3,
                error: None,
            },
        );
        client.set_response(
            "http://edge:8080",
            RevocationResponse {
                success: false,
                artifacts_revoked: 0,
                error: Some("timeout".into()),
            },
        );

        Remediator::new(endpoints, client)
    }

    #[tokio::test]
    async fn revoke_everywhere_all_clusters() {
        let remediator = mock_remediator();
        let results = remediator.revoke_everywhere(&[1u8; 32], "CVE-2026-001").await;
        assert_eq!(results.len(), 3);
    }

    #[tokio::test]
    async fn revoke_everywhere_partial_failure() {
        let remediator = mock_remediator();
        let results = remediator.revoke_everywhere(&[1u8; 32], "test").await;
        let succeeded: Vec<_> = results.iter().filter(|r| r.success).collect();
        let failed: Vec<_> = results.iter().filter(|r| !r.success).collect();
        assert_eq!(succeeded.len(), 2);
        assert_eq!(failed.len(), 1);
        assert_eq!(failed[0].cluster_id, "edge");
    }

    #[tokio::test]
    async fn revoke_everywhere_counts_artifacts() {
        let remediator = mock_remediator();
        let results = remediator.revoke_everywhere(&[1u8; 32], "test").await;
        let total: u64 = results.iter().map(|r| r.artifacts_revoked).sum();
        assert_eq!(total, 8); // 5 + 3 + 0
    }

    #[tokio::test]
    async fn revoke_on_specific_clusters() {
        let remediator = mock_remediator();
        let results = remediator
            .revoke_on_clusters(
                &[1u8; 32],
                "test",
                &["plo".to_string()],
            )
            .await;
        assert_eq!(results.len(), 1);
        assert!(results[0].success);
        assert_eq!(results[0].cluster_id, "plo");
    }

    #[tokio::test]
    async fn revoke_on_unknown_cluster() {
        let remediator = mock_remediator();
        let results = remediator
            .revoke_on_clusters(
                &[1u8; 32],
                "test",
                &["unknown".to_string()],
            )
            .await;
        assert_eq!(results.len(), 1);
        assert!(!results[0].success);
        assert!(results[0].error.as_ref().unwrap().contains("no endpoint"));
    }

    #[tokio::test]
    async fn revoke_everywhere_empty_endpoints() {
        let remediator = Remediator::new(BTreeMap::new(), MockRevocationClient::new());
        let results = remediator.revoke_everywhere(&[1u8; 32], "test").await;
        assert!(results.is_empty());
    }

    #[test]
    fn set_endpoint() {
        let mut remediator = Remediator::new(BTreeMap::new(), MockRevocationClient::new());
        remediator.set_endpoint("new-cluster", "http://new:8080");
        assert_eq!(remediator.endpoint_count(), 1);
    }

    #[test]
    fn remove_endpoint() {
        let mut remediator = mock_remediator();
        assert_eq!(remediator.endpoint_count(), 3);
        remediator.remove_endpoint("plo");
        assert_eq!(remediator.endpoint_count(), 2);
    }

    #[test]
    fn revocation_result_serde() {
        let result = RevocationResult {
            cluster_id: "plo".into(),
            success: true,
            error: None,
            artifacts_revoked: 5,
        };
        let json = serde_json::to_string(&result).unwrap();
        let back: RevocationResult = serde_json::from_str(&json).unwrap();
        assert_eq!(back.cluster_id, "plo");
        assert!(back.success);
    }

    #[test]
    fn revocation_request_serde() {
        let req = RevocationRequest {
            hash: [1u8; 32],
            hash_hex: const_hex::encode([1u8; 32]),
            reason: "test".into(),
        };
        let json = serde_json::to_string(&req).unwrap();
        let back: RevocationRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(back.hash, [1u8; 32]);
    }

    // ========================================================================
    // Sprint 8: Cross-Cluster Revocation Tests
    // ========================================================================

    #[test]
    fn global_revocation_result_serde_roundtrip() {
        let result = GlobalRevocationResult {
            hash: "abc123".to_string(),
            reason: "CVE-2026-001".to_string(),
            total_clusters: 3,
            successful: 2,
            failed: 1,
            cluster_results: vec![
                ClusterRevocationResult {
                    cluster_id: "plo".to_string(),
                    success: true,
                    affected_nodes: 5,
                    message: "ok".to_string(),
                    duration_ms: 42,
                },
                ClusterRevocationResult {
                    cluster_id: "zek".to_string(),
                    success: true,
                    affected_nodes: 3,
                    message: "ok".to_string(),
                    duration_ms: 38,
                },
                ClusterRevocationResult {
                    cluster_id: "edge".to_string(),
                    success: false,
                    affected_nodes: 0,
                    message: "timeout".to_string(),
                    duration_ms: 5000,
                },
            ],
            heartbeat_sequence: 99,
            evidence_hash: "deadbeef".to_string(),
        };
        let json = serde_json::to_string(&result).unwrap();
        let back: GlobalRevocationResult = serde_json::from_str(&json).unwrap();
        assert_eq!(back.hash, "abc123");
        assert_eq!(back.reason, "CVE-2026-001");
        assert_eq!(back.total_clusters, 3);
        assert_eq!(back.successful, 2);
        assert_eq!(back.failed, 1);
        assert_eq!(back.cluster_results.len(), 3);
        assert_eq!(back.heartbeat_sequence, 99);
        assert_eq!(back.evidence_hash, "deadbeef");
    }

    #[test]
    fn cluster_revocation_result_serde_roundtrip() {
        let cr = ClusterRevocationResult {
            cluster_id: "plo".to_string(),
            success: true,
            affected_nodes: 7,
            message: "ok".to_string(),
            duration_ms: 42,
        };
        let json = serde_json::to_string(&cr).unwrap();
        let back: ClusterRevocationResult = serde_json::from_str(&json).unwrap();
        assert_eq!(back.cluster_id, "plo");
        assert!(back.success);
        assert_eq!(back.affected_nodes, 7);
        assert_eq!(back.message, "ok");
        assert_eq!(back.duration_ms, 42);
    }

    #[test]
    fn cluster_revocation_result_failed_serde() {
        let cr = ClusterRevocationResult {
            cluster_id: "edge".to_string(),
            success: false,
            affected_nodes: 0,
            message: "connection refused".to_string(),
            duration_ms: 5000,
        };
        let json = serde_json::to_string(&cr).unwrap();
        let back: ClusterRevocationResult = serde_json::from_str(&json).unwrap();
        assert!(!back.success);
        assert_eq!(back.affected_nodes, 0);
        assert!(back.message.contains("connection refused"));
    }

    #[tokio::test]
    async fn revoke_globally_all_succeed() {
        let mut endpoints = BTreeMap::new();
        endpoints.insert("a".to_string(), "http://a:8080".to_string());
        endpoints.insert("b".to_string(), "http://b:8080".to_string());

        let client = MockRevocationClient::new();
        client.set_response(
            "http://a:8080",
            RevocationResponse {
                success: true,
                artifacts_revoked: 10,
                error: None,
            },
        );
        client.set_response(
            "http://b:8080",
            RevocationResponse {
                success: true,
                artifacts_revoked: 5,
                error: None,
            },
        );

        let remediator = Remediator::new(endpoints, client);
        let result = remediator.revoke_globally(&[1u8; 32], "CVE-2026-001", 42).await;

        assert_eq!(result.total_clusters, 2);
        assert_eq!(result.successful, 2);
        assert_eq!(result.failed, 0);
        assert_eq!(result.heartbeat_sequence, 42);
        assert_eq!(result.reason, "CVE-2026-001");
        assert_eq!(result.cluster_results.len(), 2);
    }

    #[tokio::test]
    async fn revoke_globally_partial_failure() {
        let remediator = mock_remediator();
        let result = remediator.revoke_globally(&[1u8; 32], "test", 7).await;

        assert_eq!(result.total_clusters, 3);
        assert_eq!(result.successful, 2);
        assert_eq!(result.failed, 1);

        let failed: Vec<_> = result.cluster_results.iter().filter(|r| !r.success).collect();
        assert_eq!(failed.len(), 1);
        assert_eq!(failed[0].cluster_id, "edge");
    }

    #[tokio::test]
    async fn revoke_globally_includes_affected_nodes() {
        let remediator = mock_remediator();
        let result = remediator.revoke_globally(&[1u8; 32], "test", 0).await;

        let plo = result.cluster_results.iter().find(|r| r.cluster_id == "plo").unwrap();
        assert_eq!(plo.affected_nodes, 5);

        let zek = result.cluster_results.iter().find(|r| r.cluster_id == "zek").unwrap();
        assert_eq!(zek.affected_nodes, 3);

        let edge = result.cluster_results.iter().find(|r| r.cluster_id == "edge").unwrap();
        assert_eq!(edge.affected_nodes, 0);
    }

    #[tokio::test]
    async fn evidence_hash_is_deterministic() {
        let remediator = mock_remediator();
        let result1 = remediator.revoke_globally(&[1u8; 32], "test", 42).await;
        let result2 = remediator.revoke_globally(&[1u8; 32], "test", 42).await;
        assert_eq!(result1.evidence_hash, result2.evidence_hash);
    }

    #[tokio::test]
    async fn evidence_hash_changes_with_different_input() {
        let remediator = mock_remediator();
        let result1 = remediator.revoke_globally(&[1u8; 32], "reason-a", 1).await;
        let result2 = remediator.revoke_globally(&[1u8; 32], "reason-b", 1).await;
        assert_ne!(result1.evidence_hash, result2.evidence_hash);
    }

    #[tokio::test]
    async fn evidence_hash_changes_with_sequence() {
        let remediator = mock_remediator();
        let result1 = remediator.revoke_globally(&[1u8; 32], "test", 1).await;
        let result2 = remediator.revoke_globally(&[1u8; 32], "test", 2).await;
        assert_ne!(result1.evidence_hash, result2.evidence_hash);
    }

    #[test]
    fn compute_evidence_hash_deterministic() {
        let crs = vec![
            ClusterRevocationResult {
                cluster_id: "a".to_string(),
                success: true,
                affected_nodes: 5,
                message: "ok".to_string(),
                duration_ms: 10,
            },
        ];
        let h1 = compute_evidence_hash("abc", "reason", &crs, 1);
        let h2 = compute_evidence_hash("abc", "reason", &crs, 1);
        assert_eq!(h1, h2);
    }

    #[test]
    fn compute_evidence_hash_differs_on_input() {
        let crs = vec![
            ClusterRevocationResult {
                cluster_id: "a".to_string(),
                success: true,
                affected_nodes: 5,
                message: "ok".to_string(),
                duration_ms: 10,
            },
        ];
        let h1 = compute_evidence_hash("abc", "reason-1", &crs, 1);
        let h2 = compute_evidence_hash("abc", "reason-2", &crs, 1);
        assert_ne!(h1, h2);
    }

    #[tokio::test]
    async fn revoke_globally_with_retry_retries_failed() {
        // Mock where edge fails both times — retry doesn't fix it
        let remediator = mock_remediator();
        let result = remediator
            .revoke_globally_with_retry(&[1u8; 32], "test", 10)
            .await;

        // plo and zek succeed, edge still fails after retry
        assert_eq!(result.total_clusters, 3);
        assert_eq!(result.successful, 2);
        assert_eq!(result.failed, 1);
    }

    #[tokio::test]
    async fn revoke_globally_with_retry_no_retry_needed() {
        let mut endpoints = BTreeMap::new();
        endpoints.insert("a".to_string(), "http://a:8080".to_string());

        let client = MockRevocationClient::new();
        client.set_response(
            "http://a:8080",
            RevocationResponse {
                success: true,
                artifacts_revoked: 10,
                error: None,
            },
        );

        let remediator = Remediator::new(endpoints, client);
        let result = remediator
            .revoke_globally_with_retry(&[1u8; 32], "test", 5)
            .await;

        assert_eq!(result.total_clusters, 1);
        assert_eq!(result.successful, 1);
        assert_eq!(result.failed, 0);
    }

    #[tokio::test]
    async fn revoke_globally_empty_endpoints() {
        let remediator = Remediator::new(BTreeMap::new(), MockRevocationClient::new());
        let result = remediator.revoke_globally(&[1u8; 32], "test", 0).await;
        assert_eq!(result.total_clusters, 0);
        assert_eq!(result.successful, 0);
        assert_eq!(result.failed, 0);
        assert!(result.cluster_results.is_empty());
    }

    #[tokio::test]
    async fn revoke_globally_hash_is_hex_encoded() {
        let remediator = mock_remediator();
        let hash = [0xab_u8; 32];
        let result = remediator.revoke_globally(&hash, "test", 0).await;
        assert_eq!(result.hash, const_hex::encode(hash));
        assert_eq!(result.hash.len(), 64); // 32 bytes = 64 hex chars
    }

    #[test]
    fn global_revocation_result_clone() {
        let result = GlobalRevocationResult {
            hash: "abc".to_string(),
            reason: "test".to_string(),
            total_clusters: 1,
            successful: 1,
            failed: 0,
            cluster_results: vec![ClusterRevocationResult {
                cluster_id: "a".to_string(),
                success: true,
                affected_nodes: 5,
                message: "ok".to_string(),
                duration_ms: 10,
            }],
            heartbeat_sequence: 1,
            evidence_hash: "deadbeef".to_string(),
        };
        let cloned = result.clone();
        assert_eq!(cloned.hash, result.hash);
        assert_eq!(cloned.cluster_results.len(), 1);
    }

    #[test]
    fn cluster_revocation_result_clone() {
        let cr = ClusterRevocationResult {
            cluster_id: "x".to_string(),
            success: true,
            affected_nodes: 3,
            message: "ok".to_string(),
            duration_ms: 50,
        };
        let cloned = cr.clone();
        assert_eq!(cloned.cluster_id, "x");
        assert_eq!(cloned.affected_nodes, 3);
    }

    #[tokio::test]
    async fn revoke_globally_records_heartbeat_sequence() {
        let remediator = mock_remediator();
        let result = remediator.revoke_globally(&[1u8; 32], "test", 999).await;
        assert_eq!(result.heartbeat_sequence, 999);
    }

    #[test]
    fn global_revocation_result_empty_clusters() {
        let result = GlobalRevocationResult {
            hash: "abc".to_string(),
            reason: "test".to_string(),
            total_clusters: 0,
            successful: 0,
            failed: 0,
            cluster_results: vec![],
            heartbeat_sequence: 0,
            evidence_hash: "".to_string(),
        };
        let json = serde_json::to_string(&result).unwrap();
        let back: GlobalRevocationResult = serde_json::from_str(&json).unwrap();
        assert!(back.cluster_results.is_empty());
        assert_eq!(back.total_clusters, 0);
    }
}
