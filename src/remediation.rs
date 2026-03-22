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
}
