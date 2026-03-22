//! Cluster report acceptance and state update.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::error::{Error, Result};
use crate::reverse_index::{ArtifactLocation, ReverseIndex};
use crate::state::{ClusterRootEntry, ClusterStatus, GlobalStateRootChain};

/// Report sent by a local cluster to the master server.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ClusterRootReport {
    /// Unique cluster identifier.
    pub cluster_id: String,
    /// BLAKE3 Merkle root of all composed_roots on this cluster.
    pub cluster_root: [u8; 32],
    /// Number of nodes reporting attestations.
    pub node_count: u32,
    /// Total number of CertificationArtifacts across all nodes.
    pub artifact_count: u64,
    /// When this report was generated.
    pub reported_at: DateTime<Utc>,
    /// Artifact locations for reverse index updates.
    pub artifacts: Vec<ArtifactLocation>,
}

/// Accepts cluster reports, verifies them, and updates global state.
pub struct ClusterReporter {
    state: Arc<GlobalStateRootChain>,
    index: Arc<ReverseIndex>,
}

impl ClusterReporter {
    /// Create a new reporter.
    #[must_use]
    pub fn new(state: Arc<GlobalStateRootChain>, index: Arc<ReverseIndex>) -> Self {
        Self { state, index }
    }

    /// Accept a cluster report and update state.
    ///
    /// Validates the report, updates the cluster entry in the chain,
    /// and refreshes the reverse index.
    ///
    /// Returns the new global state root sequence number.
    ///
    /// # Errors
    ///
    /// Returns an error if the report is invalid or the cluster is revoked.
    pub fn accept_report(&self, report: ClusterRootReport) -> Result<u64> {
        self.accept_report_with_time(report, Utc::now())
    }

    /// Accept a report with an explicit timestamp for deterministic testing.
    ///
    /// # Errors
    ///
    /// Returns an error if the report is invalid or the cluster is revoked.
    pub fn accept_report_with_time(
        &self,
        report: ClusterRootReport,
        now: DateTime<Utc>,
    ) -> Result<u64> {
        // Validate report
        if report.cluster_id.is_empty() {
            return Err(Error::InvalidReport("empty cluster_id".into()));
        }
        if report.node_count == 0 {
            return Err(Error::InvalidReport("node_count must be > 0".into()));
        }

        // Check if cluster is revoked
        if let Some(existing) = self.state.get_cluster(&report.cluster_id) {
            if existing.status == ClusterStatus::Revoked {
                return Err(Error::ClusterRevoked(report.cluster_id.clone()));
            }
        }

        // Verify artifact hashes match the reported root
        if !report.artifacts.is_empty() {
            let computed = compute_root_from_artifacts(&report.artifacts);
            if computed != report.cluster_root {
                return Err(Error::HashVerification(format!(
                    "reported root does not match computed root from artifacts for cluster {}",
                    report.cluster_id
                )));
            }
        }

        // Update cluster entry
        let entry = ClusterRootEntry {
            cluster_id: report.cluster_id.clone(),
            cluster_root: report.cluster_root,
            node_count: report.node_count,
            artifact_count: report.artifact_count,
            last_reported: report.reported_at,
            status: ClusterStatus::Active,
        };

        let sequence = self.state.update_cluster_with_time(entry, now);

        // Update reverse index
        self.index
            .update_cluster(&report.cluster_id, report.artifacts);

        Ok(sequence)
    }
}

/// Compute a cluster root from artifact locations.
///
/// Sorts composed_root hashes for determinism, then concatenates and BLAKE3-hashes.
#[must_use]
fn compute_root_from_artifacts(artifacts: &[ArtifactLocation]) -> [u8; 32] {
    let mut hashes: Vec<[u8; 32]> = artifacts.iter().map(|a| a.composed_root).collect();
    hashes.sort();
    hashes.dedup();
    let mut data = Vec::with_capacity(hashes.len() * 32);
    for h in &hashes {
        data.extend_from_slice(h);
    }
    *blake3::hash(&data).as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_reporter() -> (ClusterReporter, Arc<GlobalStateRootChain>, Arc<ReverseIndex>) {
        let state = Arc::new(GlobalStateRootChain::new());
        let index = Arc::new(ReverseIndex::new());
        let reporter = ClusterReporter::new(Arc::clone(&state), Arc::clone(&index));
        (reporter, state, index)
    }

    fn make_artifact(cluster: &str, hash: [u8; 32]) -> ArtifactLocation {
        ArtifactLocation {
            cluster_id: cluster.to_string(),
            node: "node-1".to_string(),
            namespace: "default".to_string(),
            binary_path: "/usr/bin/app".to_string(),
            composed_root: hash,
        }
    }

    fn make_report_no_artifacts(cluster: &str, root: [u8; 32]) -> ClusterRootReport {
        ClusterRootReport {
            cluster_id: cluster.to_string(),
            cluster_root: root,
            node_count: 3,
            artifact_count: 100,
            reported_at: Utc::now(),
            artifacts: vec![],
        }
    }

    fn make_report_with_artifacts(cluster: &str, artifacts: Vec<ArtifactLocation>) -> ClusterRootReport {
        let root = compute_root_from_artifacts(&artifacts);
        ClusterRootReport {
            cluster_id: cluster.to_string(),
            cluster_root: root,
            node_count: 3,
            artifact_count: artifacts.len() as u64,
            reported_at: Utc::now(),
            artifacts,
        }
    }

    #[test]
    fn accept_valid_report_no_artifacts() {
        let (reporter, state, _) = make_reporter();
        let report = make_report_no_artifacts("plo", [1u8; 32]);
        let seq = reporter.accept_report(report).unwrap();
        assert_eq!(seq, 0);
        assert_eq!(state.cluster_count(), 1);
    }

    #[test]
    fn accept_report_updates_state() {
        let (reporter, state, _) = make_reporter();
        reporter.accept_report(make_report_no_artifacts("plo", [1u8; 32])).unwrap();
        let entry = state.get_cluster("plo").unwrap();
        assert_eq!(entry.cluster_root, [1u8; 32]);
        assert_eq!(entry.status, ClusterStatus::Active);
    }

    #[test]
    fn accept_report_with_artifacts() {
        let (reporter, _, index) = make_reporter();
        let artifacts = vec![
            make_artifact("plo", [1u8; 32]),
            make_artifact("plo", [2u8; 32]),
        ];
        let report = make_report_with_artifacts("plo", artifacts);
        reporter.accept_report(report).unwrap();
        assert!(index.contains(&[1u8; 32]));
        assert!(index.contains(&[2u8; 32]));
    }

    #[test]
    fn accept_report_updates_reverse_index() {
        let (reporter, _, index) = make_reporter();
        let artifacts = vec![make_artifact("plo", [1u8; 32])];
        reporter.accept_report(make_report_with_artifacts("plo", artifacts)).unwrap();
        let locs = index.lookup(&[1u8; 32]);
        assert_eq!(locs.len(), 1);
        assert_eq!(locs[0].cluster_id, "plo");
    }

    #[test]
    fn reject_empty_cluster_id() {
        let (reporter, _, _) = make_reporter();
        let report = make_report_no_artifacts("", [1u8; 32]);
        let err = reporter.accept_report(report).unwrap_err();
        assert!(matches!(err, Error::InvalidReport(_)));
    }

    #[test]
    fn reject_zero_node_count() {
        let (reporter, _, _) = make_reporter();
        let mut report = make_report_no_artifacts("plo", [1u8; 32]);
        report.node_count = 0;
        let err = reporter.accept_report(report).unwrap_err();
        assert!(matches!(err, Error::InvalidReport(_)));
    }

    #[test]
    fn reject_revoked_cluster() {
        let (reporter, state, _) = make_reporter();
        reporter.accept_report(make_report_no_artifacts("plo", [1u8; 32])).unwrap();
        state.revoke_cluster("plo");
        let err = reporter
            .accept_report(make_report_no_artifacts("plo", [2u8; 32]))
            .unwrap_err();
        assert!(matches!(err, Error::ClusterRevoked(_)));
    }

    #[test]
    fn reject_mismatched_root() {
        let (reporter, _, _) = make_reporter();
        let artifacts = vec![make_artifact("plo", [1u8; 32])];
        let report = ClusterRootReport {
            cluster_id: "plo".to_string(),
            cluster_root: [99u8; 32], // wrong root
            node_count: 3,
            artifact_count: 1,
            reported_at: Utc::now(),
            artifacts,
        };
        let err = reporter.accept_report(report).unwrap_err();
        assert!(matches!(err, Error::HashVerification(_)));
    }

    #[test]
    fn multiple_reports_increment_sequence() {
        let (reporter, _, _) = make_reporter();
        assert_eq!(
            reporter.accept_report(make_report_no_artifacts("a", [1u8; 32])).unwrap(),
            0
        );
        assert_eq!(
            reporter.accept_report(make_report_no_artifacts("b", [2u8; 32])).unwrap(),
            1
        );
        assert_eq!(
            reporter.accept_report(make_report_no_artifacts("a", [3u8; 32])).unwrap(),
            2
        );
    }

    #[test]
    fn report_replaces_previous_artifacts() {
        let (reporter, _, index) = make_reporter();

        // First report
        let artifacts1 = vec![make_artifact("plo", [1u8; 32])];
        reporter.accept_report(make_report_with_artifacts("plo", artifacts1)).unwrap();
        assert!(index.contains(&[1u8; 32]));

        // Second report replaces
        let artifacts2 = vec![make_artifact("plo", [2u8; 32])];
        reporter.accept_report(make_report_with_artifacts("plo", artifacts2)).unwrap();
        assert!(!index.contains(&[1u8; 32]));
        assert!(index.contains(&[2u8; 32]));
    }

    #[test]
    fn report_preserves_other_cluster_artifacts() {
        let (reporter, _, index) = make_reporter();

        let a1 = vec![make_artifact("plo", [1u8; 32])];
        reporter.accept_report(make_report_with_artifacts("plo", a1)).unwrap();

        let a2 = vec![make_artifact("zek", [2u8; 32])];
        reporter.accept_report(make_report_with_artifacts("zek", a2)).unwrap();

        assert!(index.contains(&[1u8; 32]));
        assert!(index.contains(&[2u8; 32]));
    }

    #[test]
    fn accept_report_with_time() {
        let (reporter, state, _) = make_reporter();
        let now = Utc::now();
        let report = make_report_no_artifacts("plo", [1u8; 32]);
        reporter.accept_report_with_time(report, now).unwrap();
        let latest = state.latest().unwrap();
        assert_eq!(latest.computed_at, now);
    }

    #[test]
    fn report_serde_roundtrip() {
        let report = make_report_no_artifacts("plo", [1u8; 32]);
        let json = serde_json::to_string(&report).unwrap();
        let back: ClusterRootReport = serde_json::from_str(&json).unwrap();
        assert_eq!(back.cluster_id, "plo");
        assert_eq!(back.cluster_root, [1u8; 32]);
    }

    #[test]
    fn report_with_artifacts_serde_roundtrip() {
        let artifacts = vec![make_artifact("plo", [1u8; 32])];
        let report = make_report_with_artifacts("plo", artifacts);
        let json = serde_json::to_string(&report).unwrap();
        let back: ClusterRootReport = serde_json::from_str(&json).unwrap();
        assert_eq!(back.artifacts.len(), 1);
    }

    #[test]
    fn compute_root_deterministic() {
        let a1 = vec![
            make_artifact("plo", [1u8; 32]),
            make_artifact("plo", [2u8; 32]),
        ];
        let a2 = vec![
            make_artifact("plo", [2u8; 32]),
            make_artifact("plo", [1u8; 32]),
        ];
        assert_eq!(
            compute_root_from_artifacts(&a1),
            compute_root_from_artifacts(&a2),
        );
    }

    #[test]
    fn compute_root_deduplicates() {
        let a1 = vec![make_artifact("plo", [1u8; 32])];
        let a2 = vec![
            make_artifact("plo", [1u8; 32]),
            make_artifact("plo", [1u8; 32]),
        ];
        assert_eq!(
            compute_root_from_artifacts(&a1),
            compute_root_from_artifacts(&a2),
        );
    }

    #[test]
    fn different_artifacts_different_root() {
        let a1 = vec![make_artifact("plo", [1u8; 32])];
        let a2 = vec![make_artifact("plo", [2u8; 32])];
        assert_ne!(
            compute_root_from_artifacts(&a1),
            compute_root_from_artifacts(&a2),
        );
    }
}
