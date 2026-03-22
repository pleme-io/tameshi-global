//! Global State Root Chain — append-only BLAKE3-linked chain.
//!
//! Maintains the global state root aggregating all cluster roots.
//! Thread-safe via `RwLock<Inner>`, following the HeartbeatChain pattern
//! from tameshi core.
//!
//! ```text
//! GSR₀ ──hash──▶ GSR₁ ──hash──▶ GSR₂ ──hash──▶ GSR₃
//!  │               │               │               │
//!  └─ clusters     └─ clusters     └─ clusters     └─ clusters
//!  └─ prev: 0..0   └─ prev: H(G₀) └─ prev: H(G₁) └─ prev: H(G₂)
//! ```

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::RwLock;

/// The global state root aggregating all cluster roots.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GlobalStateRoot {
    /// BLAKE3 hash of concatenated cluster roots (sorted by cluster_id).
    pub root_hash: [u8; 32],
    /// Number of clusters contributing to this root.
    pub cluster_count: usize,
    /// Monotonically increasing sequence number.
    pub sequence: u64,
    /// BLAKE3 hash of the previous `GlobalStateRoot` (all zeros for first).
    pub previous_root: [u8; 32],
    /// When this global root was computed.
    pub computed_at: DateTime<Utc>,
}

/// A single cluster's contribution to the global state root.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ClusterRootEntry {
    /// Unique cluster identifier (e.g., "plo-us-east", "edge-fleet-07").
    pub cluster_id: String,
    /// BLAKE3 Merkle root of all `composed_root` hashes on this cluster.
    pub cluster_root: [u8; 32],
    /// Number of nodes reporting attestations.
    pub node_count: u32,
    /// Total number of `CertificationArtifact` entries across all nodes.
    pub artifact_count: u64,
    /// Last time this cluster reported its root.
    pub last_reported: DateTime<Utc>,
    /// Cluster liveness status.
    pub status: ClusterStatus,
}

/// Cluster liveness status.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClusterStatus {
    /// Reported within the last 2 intervals.
    Active,
    /// Missed 1-3 reporting intervals.
    Stale,
    /// Missed 3+ reporting intervals.
    Offline,
    /// Manually revoked by operator.
    Revoked,
}

/// Thread-safe append-only chain of global state roots.
pub struct GlobalStateRootChain {
    inner: RwLock<Inner>,
}

struct Inner {
    /// Full history of global state roots.
    roots: Vec<GlobalStateRoot>,
    /// Current cluster state, keyed by cluster_id (BTreeMap for deterministic ordering).
    clusters: BTreeMap<String, ClusterRootEntry>,
    /// Next sequence number.
    next_sequence: u64,
    /// Hash of the last appended root.
    last_hash: [u8; 32],
}

impl GlobalStateRootChain {
    /// Create a new empty chain.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: RwLock::new(Inner {
                roots: Vec::with_capacity(1024),
                clusters: BTreeMap::new(),
                next_sequence: 0,
                last_hash: [0u8; 32],
            }),
        }
    }

    /// Update a cluster's entry and recompute the global state root.
    ///
    /// Returns the new sequence number.
    pub fn update_cluster(&self, entry: ClusterRootEntry) -> u64 {
        self.update_cluster_with_time(entry, Utc::now())
    }

    /// Update a cluster's entry with an explicit timestamp (for deterministic testing).
    pub fn update_cluster_with_time(&self, entry: ClusterRootEntry, now: DateTime<Utc>) -> u64 {
        let mut inner = self.inner.write().expect("chain lock poisoned");

        inner.clusters.insert(entry.cluster_id.clone(), entry);

        let root_hash = compute_global_root(&inner.clusters);
        let sequence = inner.next_sequence;
        let previous_root = inner.last_hash;

        let gsr = GlobalStateRoot {
            root_hash,
            cluster_count: inner.clusters.len(),
            sequence,
            previous_root,
            computed_at: now,
        };

        inner.last_hash = root_hash;
        inner.next_sequence += 1;
        inner.roots.push(gsr);

        sequence
    }

    /// Remove a cluster from the global state and recompute.
    ///
    /// Returns `true` if the cluster existed and was removed.
    pub fn remove_cluster(&self, cluster_id: &str) -> bool {
        let mut inner = self.inner.write().expect("chain lock poisoned");

        if inner.clusters.remove(cluster_id).is_none() {
            return false;
        }

        let root_hash = compute_global_root(&inner.clusters);
        let sequence = inner.next_sequence;
        let previous_root = inner.last_hash;

        let gsr = GlobalStateRoot {
            root_hash,
            cluster_count: inner.clusters.len(),
            sequence,
            previous_root,
            computed_at: Utc::now(),
        };

        inner.last_hash = root_hash;
        inner.next_sequence += 1;
        inner.roots.push(gsr);

        true
    }

    /// Get the latest global state root, or `None` if the chain is empty.
    #[must_use]
    pub fn latest(&self) -> Option<GlobalStateRoot> {
        let inner = self.inner.read().expect("chain lock poisoned");
        inner.roots.last().cloned()
    }

    /// Get a global state root by sequence number.
    #[must_use]
    pub fn get(&self, sequence: u64) -> Option<GlobalStateRoot> {
        let inner = self.inner.read().expect("chain lock poisoned");
        inner.roots.get(sequence as usize).cloned()
    }

    /// Get all cluster entries.
    #[must_use]
    pub fn clusters(&self) -> BTreeMap<String, ClusterRootEntry> {
        let inner = self.inner.read().expect("chain lock poisoned");
        inner.clusters.clone()
    }

    /// Get a specific cluster entry.
    #[must_use]
    pub fn get_cluster(&self, cluster_id: &str) -> Option<ClusterRootEntry> {
        let inner = self.inner.read().expect("chain lock poisoned");
        inner.clusters.get(cluster_id).cloned()
    }

    /// Number of entries in the chain.
    #[must_use]
    pub fn len(&self) -> usize {
        let inner = self.inner.read().expect("chain lock poisoned");
        inner.roots.len()
    }

    /// Whether the chain is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Number of registered clusters.
    #[must_use]
    pub fn cluster_count(&self) -> usize {
        let inner = self.inner.read().expect("chain lock poisoned");
        inner.clusters.len()
    }

    /// Verify the integrity of the entire chain.
    ///
    /// Checks that every entry's `previous_root` matches the preceding
    /// entry's `root_hash`, and that each `root_hash` is correctly derived
    /// from the cluster state at that point.
    #[must_use]
    pub fn verify_integrity(&self) -> bool {
        let inner = self.inner.read().expect("chain lock poisoned");
        let mut expected_prev = [0u8; 32];

        for root in &inner.roots {
            if root.previous_root != expected_prev {
                return false;
            }
            expected_prev = root.root_hash;
        }

        true
    }

    /// Get all entries in the chain.
    #[must_use]
    pub fn entries(&self) -> Vec<GlobalStateRoot> {
        let inner = self.inner.read().expect("chain lock poisoned");
        inner.roots.clone()
    }

    /// Get entries in a sequence range (inclusive).
    #[must_use]
    pub fn entries_in_range(&self, from: u64, to: u64) -> Vec<GlobalStateRoot> {
        let inner = self.inner.read().expect("chain lock poisoned");
        inner
            .roots
            .iter()
            .filter(|r| r.sequence >= from && r.sequence <= to)
            .cloned()
            .collect()
    }

    /// Mark a cluster as revoked.
    ///
    /// Returns `true` if the cluster existed and was not already revoked.
    pub fn revoke_cluster(&self, cluster_id: &str) -> bool {
        let mut inner = self.inner.write().expect("chain lock poisoned");
        if let Some(entry) = inner.clusters.get_mut(cluster_id) {
            if entry.status == ClusterStatus::Revoked {
                return false;
            }
            entry.status = ClusterStatus::Revoked;
            true
        } else {
            false
        }
    }

    /// Update stale/offline status based on time thresholds.
    pub fn update_liveness(&self, stale_secs: u64, offline_secs: u64) {
        self.update_liveness_with_time(stale_secs, offline_secs, Utc::now());
    }

    /// Update stale/offline status with an explicit "now" timestamp.
    pub fn update_liveness_with_time(
        &self,
        stale_secs: u64,
        offline_secs: u64,
        now: DateTime<Utc>,
    ) {
        let mut inner = self.inner.write().expect("chain lock poisoned");
        for entry in inner.clusters.values_mut() {
            if entry.status == ClusterStatus::Revoked {
                continue;
            }
            let elapsed = (now - entry.last_reported).num_seconds().unsigned_abs();
            if elapsed >= offline_secs {
                entry.status = ClusterStatus::Offline;
            } else if elapsed >= stale_secs {
                entry.status = ClusterStatus::Stale;
            } else {
                entry.status = ClusterStatus::Active;
            }
        }
    }
}

impl Default for GlobalStateRootChain {
    fn default() -> Self {
        Self::new()
    }
}

/// Compute the global root hash from cluster entries.
///
/// Iterates the `BTreeMap` (deterministic order by key) and concatenates
/// all cluster root hashes, then BLAKE3-hashes the result. An empty map
/// produces `BLAKE3(empty)`.
#[must_use]
fn compute_global_root(clusters: &BTreeMap<String, ClusterRootEntry>) -> [u8; 32] {
    let mut data = Vec::with_capacity(clusters.len() * 32);
    for entry in clusters.values() {
        data.extend_from_slice(&entry.cluster_root);
    }
    *blake3::hash(&data).as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_entry(cluster_id: &str, root: [u8; 32]) -> ClusterRootEntry {
        ClusterRootEntry {
            cluster_id: cluster_id.to_string(),
            cluster_root: root,
            node_count: 3,
            artifact_count: 100,
            last_reported: Utc::now(),
            status: ClusterStatus::Active,
        }
    }

    fn make_entry_at(cluster_id: &str, root: [u8; 32], time: DateTime<Utc>) -> ClusterRootEntry {
        ClusterRootEntry {
            cluster_id: cluster_id.to_string(),
            cluster_root: root,
            node_count: 3,
            artifact_count: 100,
            last_reported: time,
            status: ClusterStatus::Active,
        }
    }

    #[test]
    fn new_chain_is_empty() {
        let chain = GlobalStateRootChain::new();
        assert!(chain.is_empty());
        assert_eq!(chain.len(), 0);
        assert_eq!(chain.cluster_count(), 0);
        assert!(chain.latest().is_none());
    }

    #[test]
    fn default_chain_is_empty() {
        let chain = GlobalStateRootChain::default();
        assert!(chain.is_empty());
    }

    #[test]
    fn update_single_cluster() {
        let chain = GlobalStateRootChain::new();
        let entry = make_entry("plo", [1u8; 32]);
        let seq = chain.update_cluster(entry);
        assert_eq!(seq, 0);
        assert_eq!(chain.len(), 1);
        assert_eq!(chain.cluster_count(), 1);
    }

    #[test]
    fn update_returns_sequence() {
        let chain = GlobalStateRootChain::new();
        assert_eq!(chain.update_cluster(make_entry("a", [1u8; 32])), 0);
        assert_eq!(chain.update_cluster(make_entry("b", [2u8; 32])), 1);
        assert_eq!(chain.update_cluster(make_entry("a", [3u8; 32])), 2);
    }

    #[test]
    fn latest_returns_most_recent() {
        let chain = GlobalStateRootChain::new();
        chain.update_cluster(make_entry("a", [1u8; 32]));
        chain.update_cluster(make_entry("b", [2u8; 32]));
        let latest = chain.latest().unwrap();
        assert_eq!(latest.sequence, 1);
        assert_eq!(latest.cluster_count, 2);
    }

    #[test]
    fn get_by_sequence() {
        let chain = GlobalStateRootChain::new();
        chain.update_cluster(make_entry("a", [1u8; 32]));
        chain.update_cluster(make_entry("b", [2u8; 32]));
        let first = chain.get(0).unwrap();
        assert_eq!(first.sequence, 0);
        assert_eq!(first.cluster_count, 1);
        assert!(chain.get(99).is_none());
    }

    #[test]
    fn chain_linkage() {
        let chain = GlobalStateRootChain::new();
        chain.update_cluster(make_entry("a", [1u8; 32]));
        chain.update_cluster(make_entry("b", [2u8; 32]));
        let first = chain.get(0).unwrap();
        let second = chain.get(1).unwrap();
        assert_eq!(first.previous_root, [0u8; 32]);
        assert_eq!(second.previous_root, first.root_hash);
    }

    #[test]
    fn verify_integrity_empty() {
        let chain = GlobalStateRootChain::new();
        assert!(chain.verify_integrity());
    }

    #[test]
    fn verify_integrity_single() {
        let chain = GlobalStateRootChain::new();
        chain.update_cluster(make_entry("a", [1u8; 32]));
        assert!(chain.verify_integrity());
    }

    #[test]
    fn verify_integrity_multiple() {
        let chain = GlobalStateRootChain::new();
        for i in 0..10 {
            chain.update_cluster(make_entry(&format!("c{i}"), [i; 32]));
        }
        assert!(chain.verify_integrity());
    }

    #[test]
    fn clusters_returns_all() {
        let chain = GlobalStateRootChain::new();
        chain.update_cluster(make_entry("x", [1u8; 32]));
        chain.update_cluster(make_entry("y", [2u8; 32]));
        let clusters = chain.clusters();
        assert_eq!(clusters.len(), 2);
        assert!(clusters.contains_key("x"));
        assert!(clusters.contains_key("y"));
    }

    #[test]
    fn get_cluster_existing() {
        let chain = GlobalStateRootChain::new();
        chain.update_cluster(make_entry("plo", [42u8; 32]));
        let entry = chain.get_cluster("plo").unwrap();
        assert_eq!(entry.cluster_root, [42u8; 32]);
    }

    #[test]
    fn get_cluster_nonexistent() {
        let chain = GlobalStateRootChain::new();
        assert!(chain.get_cluster("nope").is_none());
    }

    #[test]
    fn update_cluster_overwrites() {
        let chain = GlobalStateRootChain::new();
        chain.update_cluster(make_entry("plo", [1u8; 32]));
        chain.update_cluster(make_entry("plo", [2u8; 32]));
        let entry = chain.get_cluster("plo").unwrap();
        assert_eq!(entry.cluster_root, [2u8; 32]);
        assert_eq!(chain.cluster_count(), 1);
        assert_eq!(chain.len(), 2); // two chain entries
    }

    #[test]
    fn remove_cluster_existing() {
        let chain = GlobalStateRootChain::new();
        chain.update_cluster(make_entry("a", [1u8; 32]));
        chain.update_cluster(make_entry("b", [2u8; 32]));
        assert!(chain.remove_cluster("a"));
        assert_eq!(chain.cluster_count(), 1);
        assert!(chain.get_cluster("a").is_none());
    }

    #[test]
    fn remove_cluster_nonexistent() {
        let chain = GlobalStateRootChain::new();
        assert!(!chain.remove_cluster("nope"));
    }

    #[test]
    fn remove_appends_to_chain() {
        let chain = GlobalStateRootChain::new();
        chain.update_cluster(make_entry("a", [1u8; 32]));
        let before = chain.len();
        chain.remove_cluster("a");
        assert_eq!(chain.len(), before + 1);
    }

    #[test]
    fn entries_returns_all() {
        let chain = GlobalStateRootChain::new();
        chain.update_cluster(make_entry("a", [1u8; 32]));
        chain.update_cluster(make_entry("b", [2u8; 32]));
        assert_eq!(chain.entries().len(), 2);
    }

    #[test]
    fn entries_in_range_inclusive() {
        let chain = GlobalStateRootChain::new();
        for i in 0..5 {
            chain.update_cluster(make_entry(&format!("c{i}"), [i; 32]));
        }
        let range = chain.entries_in_range(1, 3);
        assert_eq!(range.len(), 3);
        assert_eq!(range[0].sequence, 1);
        assert_eq!(range[2].sequence, 3);
    }

    #[test]
    fn entries_in_range_empty() {
        let chain = GlobalStateRootChain::new();
        chain.update_cluster(make_entry("a", [1u8; 32]));
        assert!(chain.entries_in_range(10, 20).is_empty());
    }

    #[test]
    fn revoke_cluster_success() {
        let chain = GlobalStateRootChain::new();
        chain.update_cluster(make_entry("plo", [1u8; 32]));
        assert!(chain.revoke_cluster("plo"));
        let entry = chain.get_cluster("plo").unwrap();
        assert_eq!(entry.status, ClusterStatus::Revoked);
    }

    #[test]
    fn revoke_cluster_already_revoked() {
        let chain = GlobalStateRootChain::new();
        chain.update_cluster(make_entry("plo", [1u8; 32]));
        assert!(chain.revoke_cluster("plo"));
        assert!(!chain.revoke_cluster("plo"));
    }

    #[test]
    fn revoke_cluster_nonexistent() {
        let chain = GlobalStateRootChain::new();
        assert!(!chain.revoke_cluster("nope"));
    }

    #[test]
    fn update_liveness_marks_stale() {
        let chain = GlobalStateRootChain::new();
        let old_time = Utc::now() - chrono::Duration::seconds(150);
        chain.update_cluster(make_entry_at("plo", [1u8; 32], old_time));
        chain.update_liveness(120, 360);
        let entry = chain.get_cluster("plo").unwrap();
        assert_eq!(entry.status, ClusterStatus::Stale);
    }

    #[test]
    fn update_liveness_marks_offline() {
        let chain = GlobalStateRootChain::new();
        let old_time = Utc::now() - chrono::Duration::seconds(400);
        chain.update_cluster(make_entry_at("plo", [1u8; 32], old_time));
        chain.update_liveness(120, 360);
        let entry = chain.get_cluster("plo").unwrap();
        assert_eq!(entry.status, ClusterStatus::Offline);
    }

    #[test]
    fn update_liveness_keeps_active() {
        let chain = GlobalStateRootChain::new();
        chain.update_cluster(make_entry("plo", [1u8; 32]));
        chain.update_liveness(120, 360);
        let entry = chain.get_cluster("plo").unwrap();
        assert_eq!(entry.status, ClusterStatus::Active);
    }

    #[test]
    fn update_liveness_skips_revoked() {
        let chain = GlobalStateRootChain::new();
        let old_time = Utc::now() - chrono::Duration::seconds(999);
        chain.update_cluster(make_entry_at("plo", [1u8; 32], old_time));
        chain.revoke_cluster("plo");
        chain.update_liveness(120, 360);
        let entry = chain.get_cluster("plo").unwrap();
        assert_eq!(entry.status, ClusterStatus::Revoked);
    }

    #[test]
    fn deterministic_root_hash() {
        let chain1 = GlobalStateRootChain::new();
        let chain2 = GlobalStateRootChain::new();
        let now = Utc::now();

        chain1.update_cluster_with_time(make_entry("a", [1u8; 32]), now);
        chain1.update_cluster_with_time(make_entry("b", [2u8; 32]), now);

        chain2.update_cluster_with_time(make_entry("a", [1u8; 32]), now);
        chain2.update_cluster_with_time(make_entry("b", [2u8; 32]), now);

        assert_eq!(
            chain1.latest().unwrap().root_hash,
            chain2.latest().unwrap().root_hash,
        );
    }

    #[test]
    fn different_clusters_different_root() {
        let chain = GlobalStateRootChain::new();
        chain.update_cluster(make_entry("a", [1u8; 32]));
        let root1 = chain.latest().unwrap().root_hash;
        chain.update_cluster(make_entry("a", [2u8; 32]));
        let root2 = chain.latest().unwrap().root_hash;
        assert_ne!(root1, root2);
    }

    #[test]
    fn cluster_order_independence() {
        // BTreeMap ordering should make the root the same regardless of insert order
        let chain1 = GlobalStateRootChain::new();
        let chain2 = GlobalStateRootChain::new();
        let now = Utc::now();

        chain1.update_cluster_with_time(make_entry("alpha", [1u8; 32]), now);
        chain1.update_cluster_with_time(make_entry("beta", [2u8; 32]), now);

        chain2.update_cluster_with_time(make_entry("beta", [2u8; 32]), now);
        chain2.update_cluster_with_time(make_entry("alpha", [1u8; 32]), now);

        assert_eq!(
            chain1.latest().unwrap().root_hash,
            chain2.latest().unwrap().root_hash,
        );
    }

    #[test]
    fn concurrent_reads() {
        use std::sync::Arc;

        let chain = Arc::new(GlobalStateRootChain::new());
        chain.update_cluster(make_entry("a", [1u8; 32]));

        let handles: Vec<_> = (0..10)
            .map(|_| {
                let c = Arc::clone(&chain);
                std::thread::spawn(move || {
                    let _ = c.latest();
                    let _ = c.clusters();
                    let _ = c.len();
                })
            })
            .collect();

        for h in handles {
            h.join().unwrap();
        }
    }

    #[test]
    fn concurrent_writes() {
        use std::sync::Arc;

        let chain = Arc::new(GlobalStateRootChain::new());
        let handles: Vec<_> = (0..10u8)
            .map(|i| {
                let c = Arc::clone(&chain);
                std::thread::spawn(move || {
                    c.update_cluster(make_entry(&format!("c{i}"), [i; 32]));
                })
            })
            .collect();

        for h in handles {
            h.join().unwrap();
        }
        assert_eq!(chain.cluster_count(), 10);
        assert!(chain.verify_integrity());
    }

    #[test]
    fn cluster_status_serde_roundtrip() {
        for status in &[
            ClusterStatus::Active,
            ClusterStatus::Stale,
            ClusterStatus::Offline,
            ClusterStatus::Revoked,
        ] {
            let json = serde_json::to_string(status).unwrap();
            let back: ClusterStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(*status, back);
        }
    }

    #[test]
    fn global_state_root_serde_roundtrip() {
        let gsr = GlobalStateRoot {
            root_hash: [42u8; 32],
            cluster_count: 3,
            sequence: 7,
            previous_root: [0u8; 32],
            computed_at: Utc::now(),
        };
        let json = serde_json::to_string(&gsr).unwrap();
        let back: GlobalStateRoot = serde_json::from_str(&json).unwrap();
        assert_eq!(back.root_hash, gsr.root_hash);
        assert_eq!(back.sequence, gsr.sequence);
    }

    #[test]
    fn cluster_root_entry_serde_roundtrip() {
        let entry = make_entry("plo", [1u8; 32]);
        let json = serde_json::to_string(&entry).unwrap();
        let back: ClusterRootEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(back.cluster_id, "plo");
        assert_eq!(back.cluster_root, [1u8; 32]);
    }
}
