//! Tameshi Global State Root — master server for planetary-scale attestation.
//!
//! Accepts `ClusterRootReport` messages from all clusters and maintains the
//! `GlobalStateRootChain`, a BLAKE3-linked append-only chain of global state
//! roots. Provides reverse-index lookups for O(1) hash-to-location queries
//! and cross-cluster revocation fan-out.

pub mod api;
pub mod config;
pub mod error;
pub mod health;
pub mod metrics;
pub mod remediation;
pub mod reporter;
pub mod reverse_index;
pub mod state;

/// Re-export key types for convenience.
pub mod prelude {
    pub use crate::config::Config;
    pub use crate::error::{Error, Result};
    pub use crate::reporter::{ClusterReporter, ClusterRootReport};
    pub use crate::reverse_index::{ArtifactLocation, ReverseIndex};
    pub use crate::state::{
        ClusterRootEntry, ClusterStatus, GlobalStateRoot, GlobalStateRootChain,
    };
}
