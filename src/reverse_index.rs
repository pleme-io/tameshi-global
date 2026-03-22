//! Reverse index — O(1) hash-to-location lookup.
//!
//! Maps `composed_root` hashes to their physical locations across all
//! clusters, enabling instant blast-radius queries without scanning.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;

/// Location of an artifact in the global fleet.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ArtifactLocation {
    /// Cluster where the artifact resides.
    pub cluster_id: String,
    /// Node within the cluster.
    pub node: String,
    /// Kubernetes namespace.
    pub namespace: String,
    /// Path to the binary on disk.
    pub binary_path: String,
    /// Composed root hash of the certification artifact.
    pub composed_root: [u8; 32],
}

/// Thread-safe reverse index for O(1) hash lookups.
pub struct ReverseIndex {
    index: RwLock<HashMap<[u8; 32], Vec<ArtifactLocation>>>,
}

impl ReverseIndex {
    /// Create a new empty reverse index.
    #[must_use]
    pub fn new() -> Self {
        Self {
            index: RwLock::new(HashMap::new()),
        }
    }

    /// Look up all locations for a given hash.
    #[must_use]
    pub fn lookup(&self, hash: &[u8; 32]) -> Vec<ArtifactLocation> {
        let index = self.index.read().expect("reverse index lock poisoned");
        index.get(hash).cloned().unwrap_or_default()
    }

    /// Check if a hash exists in the index.
    #[must_use]
    pub fn contains(&self, hash: &[u8; 32]) -> bool {
        let index = self.index.read().expect("reverse index lock poisoned");
        index.contains_key(hash)
    }

    /// Count of distinct hashes in the index.
    #[must_use]
    pub fn hash_count(&self) -> usize {
        let index = self.index.read().expect("reverse index lock poisoned");
        index.len()
    }

    /// Total number of artifact locations across all hashes.
    #[must_use]
    pub fn total_locations(&self) -> usize {
        let index = self.index.read().expect("reverse index lock poisoned");
        index.values().map(Vec::len).sum()
    }

    /// Update the index with artifacts from a cluster.
    ///
    /// Removes all existing entries for this cluster, then inserts the new set.
    /// This ensures consistency even if artifacts move between nodes.
    pub fn update_cluster(&self, cluster_id: &str, artifacts: Vec<ArtifactLocation>) {
        let mut index = self.index.write().expect("reverse index lock poisoned");

        // Remove all existing entries for this cluster
        for locations in index.values_mut() {
            locations.retain(|loc| loc.cluster_id != cluster_id);
        }
        // Remove empty entries
        index.retain(|_, v| !v.is_empty());

        // Insert new artifacts
        for artifact in artifacts {
            index
                .entry(artifact.composed_root)
                .or_default()
                .push(artifact);
        }
    }

    /// Remove all entries for a cluster.
    pub fn remove_cluster(&self, cluster_id: &str) {
        let mut index = self.index.write().expect("reverse index lock poisoned");
        for locations in index.values_mut() {
            locations.retain(|loc| loc.cluster_id != cluster_id);
        }
        index.retain(|_, v| !v.is_empty());
    }

    /// Insert a single artifact location.
    pub fn insert(&self, artifact: ArtifactLocation) {
        let mut index = self.index.write().expect("reverse index lock poisoned");
        index
            .entry(artifact.composed_root)
            .or_default()
            .push(artifact);
    }

    /// Remove all entries matching a specific hash.
    ///
    /// Returns the removed locations.
    pub fn remove_hash(&self, hash: &[u8; 32]) -> Vec<ArtifactLocation> {
        let mut index = self.index.write().expect("reverse index lock poisoned");
        index.remove(hash).unwrap_or_default()
    }

    /// Get all unique cluster IDs that contain a given hash.
    #[must_use]
    pub fn clusters_for_hash(&self, hash: &[u8; 32]) -> Vec<String> {
        let locations = self.lookup(hash);
        let mut clusters: Vec<String> = locations.into_iter().map(|l| l.cluster_id).collect();
        clusters.sort();
        clusters.dedup();
        clusters
    }

    /// Clear the entire index.
    pub fn clear(&self) {
        let mut index = self.index.write().expect("reverse index lock poisoned");
        index.clear();
    }
}

impl Default for ReverseIndex {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_loc(cluster: &str, node: &str, hash: [u8; 32]) -> ArtifactLocation {
        ArtifactLocation {
            cluster_id: cluster.to_string(),
            node: node.to_string(),
            namespace: "default".to_string(),
            binary_path: format!("/usr/bin/{cluster}-{node}"),
            composed_root: hash,
        }
    }

    #[test]
    fn new_index_is_empty() {
        let idx = ReverseIndex::new();
        assert_eq!(idx.hash_count(), 0);
        assert_eq!(idx.total_locations(), 0);
    }

    #[test]
    fn default_index_is_empty() {
        let idx = ReverseIndex::default();
        assert_eq!(idx.hash_count(), 0);
    }

    #[test]
    fn lookup_empty() {
        let idx = ReverseIndex::new();
        assert!(idx.lookup(&[0u8; 32]).is_empty());
    }

    #[test]
    fn contains_empty() {
        let idx = ReverseIndex::new();
        assert!(!idx.contains(&[0u8; 32]));
    }

    #[test]
    fn insert_and_lookup() {
        let idx = ReverseIndex::new();
        let loc = make_loc("plo", "node-1", [1u8; 32]);
        idx.insert(loc.clone());
        let result = idx.lookup(&[1u8; 32]);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0], loc);
    }

    #[test]
    fn insert_multiple_same_hash() {
        let idx = ReverseIndex::new();
        idx.insert(make_loc("plo", "node-1", [1u8; 32]));
        idx.insert(make_loc("plo", "node-2", [1u8; 32]));
        idx.insert(make_loc("zek", "node-1", [1u8; 32]));
        let result = idx.lookup(&[1u8; 32]);
        assert_eq!(result.len(), 3);
    }

    #[test]
    fn insert_different_hashes() {
        let idx = ReverseIndex::new();
        idx.insert(make_loc("plo", "node-1", [1u8; 32]));
        idx.insert(make_loc("plo", "node-1", [2u8; 32]));
        assert_eq!(idx.hash_count(), 2);
        assert_eq!(idx.total_locations(), 2);
    }

    #[test]
    fn contains_after_insert() {
        let idx = ReverseIndex::new();
        idx.insert(make_loc("plo", "node-1", [1u8; 32]));
        assert!(idx.contains(&[1u8; 32]));
        assert!(!idx.contains(&[2u8; 32]));
    }

    #[test]
    fn update_cluster_replaces() {
        let idx = ReverseIndex::new();
        idx.insert(make_loc("plo", "node-old", [1u8; 32]));
        idx.update_cluster(
            "plo",
            vec![make_loc("plo", "node-new", [1u8; 32])],
        );
        let result = idx.lookup(&[1u8; 32]);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].node, "node-new");
    }

    #[test]
    fn update_cluster_preserves_others() {
        let idx = ReverseIndex::new();
        idx.insert(make_loc("plo", "node-1", [1u8; 32]));
        idx.insert(make_loc("zek", "node-1", [1u8; 32]));
        idx.update_cluster("plo", vec![make_loc("plo", "node-2", [1u8; 32])]);
        let result = idx.lookup(&[1u8; 32]);
        assert_eq!(result.len(), 2);
        // zek should still be there
        assert!(result.iter().any(|l| l.cluster_id == "zek"));
        // plo should be updated
        assert!(result.iter().any(|l| l.cluster_id == "plo" && l.node == "node-2"));
    }

    #[test]
    fn update_cluster_empty_removes() {
        let idx = ReverseIndex::new();
        idx.insert(make_loc("plo", "node-1", [1u8; 32]));
        idx.update_cluster("plo", vec![]);
        assert_eq!(idx.hash_count(), 0);
        assert_eq!(idx.total_locations(), 0);
    }

    #[test]
    fn update_cluster_removes_old_hashes() {
        let idx = ReverseIndex::new();
        idx.insert(make_loc("plo", "node-1", [1u8; 32]));
        idx.update_cluster("plo", vec![make_loc("plo", "node-1", [2u8; 32])]);
        assert!(!idx.contains(&[1u8; 32]));
        assert!(idx.contains(&[2u8; 32]));
    }

    #[test]
    fn remove_cluster() {
        let idx = ReverseIndex::new();
        idx.insert(make_loc("plo", "node-1", [1u8; 32]));
        idx.insert(make_loc("plo", "node-2", [2u8; 32]));
        idx.insert(make_loc("zek", "node-1", [1u8; 32]));
        idx.remove_cluster("plo");
        assert_eq!(idx.total_locations(), 1);
        let result = idx.lookup(&[1u8; 32]);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].cluster_id, "zek");
    }

    #[test]
    fn remove_cluster_nonexistent_noop() {
        let idx = ReverseIndex::new();
        idx.insert(make_loc("plo", "node-1", [1u8; 32]));
        idx.remove_cluster("nope");
        assert_eq!(idx.total_locations(), 1);
    }

    #[test]
    fn remove_hash() {
        let idx = ReverseIndex::new();
        idx.insert(make_loc("plo", "node-1", [1u8; 32]));
        idx.insert(make_loc("zek", "node-1", [1u8; 32]));
        let removed = idx.remove_hash(&[1u8; 32]);
        assert_eq!(removed.len(), 2);
        assert!(!idx.contains(&[1u8; 32]));
    }

    #[test]
    fn remove_hash_nonexistent() {
        let idx = ReverseIndex::new();
        let removed = idx.remove_hash(&[99u8; 32]);
        assert!(removed.is_empty());
    }

    #[test]
    fn clusters_for_hash() {
        let idx = ReverseIndex::new();
        idx.insert(make_loc("plo", "node-1", [1u8; 32]));
        idx.insert(make_loc("plo", "node-2", [1u8; 32]));
        idx.insert(make_loc("zek", "node-1", [1u8; 32]));
        let clusters = idx.clusters_for_hash(&[1u8; 32]);
        assert_eq!(clusters, vec!["plo", "zek"]);
    }

    #[test]
    fn clusters_for_hash_empty() {
        let idx = ReverseIndex::new();
        assert!(idx.clusters_for_hash(&[1u8; 32]).is_empty());
    }

    #[test]
    fn clear() {
        let idx = ReverseIndex::new();
        idx.insert(make_loc("plo", "n1", [1u8; 32]));
        idx.insert(make_loc("zek", "n1", [2u8; 32]));
        idx.clear();
        assert_eq!(idx.hash_count(), 0);
        assert_eq!(idx.total_locations(), 0);
    }

    #[test]
    fn artifact_location_serde_roundtrip() {
        let loc = make_loc("plo", "node-1", [1u8; 32]);
        let json = serde_json::to_string(&loc).unwrap();
        let back: ArtifactLocation = serde_json::from_str(&json).unwrap();
        assert_eq!(loc, back);
    }

    #[test]
    fn concurrent_reads() {
        use std::sync::Arc;
        let idx = Arc::new(ReverseIndex::new());
        idx.insert(make_loc("plo", "node-1", [1u8; 32]));

        let handles: Vec<_> = (0..10)
            .map(|_| {
                let i = Arc::clone(&idx);
                std::thread::spawn(move || {
                    let _ = i.lookup(&[1u8; 32]);
                    let _ = i.hash_count();
                    let _ = i.total_locations();
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
        let idx = Arc::new(ReverseIndex::new());

        let handles: Vec<_> = (0..10u8)
            .map(|i| {
                let idx = Arc::clone(&idx);
                std::thread::spawn(move || {
                    idx.insert(make_loc(&format!("c{i}"), "n1", [i; 32]));
                })
            })
            .collect();

        for h in handles {
            h.join().unwrap();
        }
        assert_eq!(idx.hash_count(), 10);
    }

    #[test]
    fn total_locations_multi_hash() {
        let idx = ReverseIndex::new();
        idx.insert(make_loc("a", "n1", [1u8; 32]));
        idx.insert(make_loc("b", "n1", [1u8; 32]));
        idx.insert(make_loc("c", "n1", [2u8; 32]));
        assert_eq!(idx.total_locations(), 3);
        assert_eq!(idx.hash_count(), 2);
    }

    #[test]
    fn update_cluster_with_multiple_artifacts() {
        let idx = ReverseIndex::new();
        idx.update_cluster(
            "plo",
            vec![
                make_loc("plo", "n1", [1u8; 32]),
                make_loc("plo", "n2", [2u8; 32]),
                make_loc("plo", "n1", [3u8; 32]),
            ],
        );
        assert_eq!(idx.hash_count(), 3);
        assert_eq!(idx.total_locations(), 3);
    }
}
