//! Error types for tameshi-global.

/// Crate-level result alias.
pub type Result<T> = std::result::Result<T, Error>;

/// All errors that tameshi-global can produce.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Hash verification failed.
    #[error("hash verification failed: {0}")]
    HashVerification(String),

    /// Chain integrity violation.
    #[error("chain integrity violation: {0}")]
    ChainIntegrity(String),

    /// Unknown cluster.
    #[error("unknown cluster: {0}")]
    UnknownCluster(String),

    /// Cluster already revoked.
    #[error("cluster is revoked: {0}")]
    ClusterRevoked(String),

    /// Invalid report payload.
    #[error("invalid report: {0}")]
    InvalidReport(String),

    /// Configuration error.
    #[error("configuration error: {0}")]
    Config(String),

    /// HTTP client error.
    #[error("http error: {0}")]
    Http(#[from] reqwest::Error),

    /// Serialization error.
    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    /// Internal error.
    #[error("internal error: {0}")]
    Internal(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_display_hash_verification() {
        let e = Error::HashVerification("mismatch".into());
        assert!(e.to_string().contains("mismatch"));
    }

    #[test]
    fn error_display_chain_integrity() {
        let e = Error::ChainIntegrity("gap at seq 5".into());
        assert!(e.to_string().contains("gap at seq 5"));
    }

    #[test]
    fn error_display_unknown_cluster() {
        let e = Error::UnknownCluster("cluster-x".into());
        assert!(e.to_string().contains("cluster-x"));
    }

    #[test]
    fn error_display_cluster_revoked() {
        let e = Error::ClusterRevoked("cluster-y".into());
        assert!(e.to_string().contains("cluster-y"));
    }

    #[test]
    fn error_display_invalid_report() {
        let e = Error::InvalidReport("empty".into());
        assert!(e.to_string().contains("empty"));
    }

    #[test]
    fn error_display_config() {
        let e = Error::Config("missing field".into());
        assert!(e.to_string().contains("missing field"));
    }

    #[test]
    fn error_display_internal() {
        let e = Error::Internal("lock poisoned".into());
        assert!(e.to_string().contains("lock poisoned"));
    }

    #[test]
    fn error_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<Error>();
    }
}
