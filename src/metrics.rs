//! Prometheus metrics for tameshi-global.

use prometheus::{IntCounter, IntGauge, Registry};

/// Metrics for the global state root server.
pub struct Metrics {
    /// Total reports accepted.
    pub reports_accepted: IntCounter,
    /// Total reports rejected.
    pub reports_rejected: IntCounter,
    /// Total revocations initiated.
    pub revocations_initiated: IntCounter,
    /// Total revocations succeeded.
    pub revocations_succeeded: IntCounter,
    /// Total revocations failed.
    pub revocations_failed: IntCounter,
    /// Current number of registered clusters.
    pub cluster_count: IntGauge,
    /// Current chain length.
    pub chain_length: IntGauge,
    /// Total hash lookups.
    pub hash_lookups: IntCounter,
    /// The Prometheus registry.
    pub registry: Registry,
}

impl Metrics {
    /// Create and register all metrics.
    ///
    /// # Panics
    ///
    /// Panics if metric registration fails (should never happen with unique names).
    #[must_use]
    pub fn new() -> Self {
        let registry = Registry::new();

        let reports_accepted = IntCounter::new(
            "tameshi_global_reports_accepted_total",
            "Total cluster reports accepted",
        )
        .unwrap();

        let reports_rejected = IntCounter::new(
            "tameshi_global_reports_rejected_total",
            "Total cluster reports rejected",
        )
        .unwrap();

        let revocations_initiated = IntCounter::new(
            "tameshi_global_revocations_initiated_total",
            "Total revocation fan-outs initiated",
        )
        .unwrap();

        let revocations_succeeded = IntCounter::new(
            "tameshi_global_revocations_succeeded_total",
            "Total individual cluster revocations succeeded",
        )
        .unwrap();

        let revocations_failed = IntCounter::new(
            "tameshi_global_revocations_failed_total",
            "Total individual cluster revocations failed",
        )
        .unwrap();

        let cluster_count = IntGauge::new(
            "tameshi_global_cluster_count",
            "Current number of registered clusters",
        )
        .unwrap();

        let chain_length = IntGauge::new(
            "tameshi_global_chain_length",
            "Current global state root chain length",
        )
        .unwrap();

        let hash_lookups = IntCounter::new(
            "tameshi_global_hash_lookups_total",
            "Total reverse index hash lookups",
        )
        .unwrap();

        registry.register(Box::new(reports_accepted.clone())).unwrap();
        registry.register(Box::new(reports_rejected.clone())).unwrap();
        registry.register(Box::new(revocations_initiated.clone())).unwrap();
        registry.register(Box::new(revocations_succeeded.clone())).unwrap();
        registry.register(Box::new(revocations_failed.clone())).unwrap();
        registry.register(Box::new(cluster_count.clone())).unwrap();
        registry.register(Box::new(chain_length.clone())).unwrap();
        registry.register(Box::new(hash_lookups.clone())).unwrap();

        Self {
            reports_accepted,
            reports_rejected,
            revocations_initiated,
            revocations_succeeded,
            revocations_failed,
            cluster_count,
            chain_length,
            hash_lookups,
            registry,
        }
    }

    /// Encode all metrics as Prometheus text format.
    #[must_use]
    pub fn encode(&self) -> String {
        use prometheus::Encoder;
        let encoder = prometheus::TextEncoder::new();
        let metric_families = self.registry.gather();
        let mut buffer = Vec::new();
        encoder.encode(&metric_families, &mut buffer).unwrap();
        String::from_utf8(buffer).unwrap()
    }
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metrics_new() {
        let m = Metrics::new();
        assert_eq!(m.reports_accepted.get(), 0);
        assert_eq!(m.cluster_count.get(), 0);
    }

    #[test]
    fn metrics_default() {
        let m = Metrics::default();
        assert_eq!(m.chain_length.get(), 0);
    }

    #[test]
    fn increment_counters() {
        let m = Metrics::new();
        m.reports_accepted.inc();
        m.reports_accepted.inc();
        assert_eq!(m.reports_accepted.get(), 2);
    }

    #[test]
    fn set_gauge() {
        let m = Metrics::new();
        m.cluster_count.set(5);
        assert_eq!(m.cluster_count.get(), 5);
    }

    #[test]
    fn encode_contains_metric_names() {
        let m = Metrics::new();
        m.reports_accepted.inc();
        let text = m.encode();
        assert!(text.contains("tameshi_global_reports_accepted_total"));
        assert!(text.contains("tameshi_global_cluster_count"));
    }

    #[test]
    fn all_counters_zero_initially() {
        let m = Metrics::new();
        assert_eq!(m.reports_rejected.get(), 0);
        assert_eq!(m.revocations_initiated.get(), 0);
        assert_eq!(m.revocations_succeeded.get(), 0);
        assert_eq!(m.revocations_failed.get(), 0);
        assert_eq!(m.hash_lookups.get(), 0);
    }

    #[test]
    fn encode_empty_metrics() {
        let m = Metrics::new();
        let text = m.encode();
        // Should still produce valid output
        assert!(!text.is_empty());
    }
}
