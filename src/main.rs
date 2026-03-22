//! tameshi-global CLI: daemon and status commands.

use std::collections::BTreeMap;
use std::sync::Arc;

use tameshi_global::api::{self, AppState};
use tameshi_global::config::load_config;
use tameshi_global::health;
use tameshi_global::metrics::Metrics;
use tameshi_global::remediation::{MockRevocationClient, Remediator};
use tameshi_global::reporter::ClusterReporter;
use tameshi_global::reverse_index::ReverseIndex;
use tameshi_global::state::GlobalStateRootChain;

#[tokio::main]
async fn main() {
    // Load configuration
    let config = load_config(Some("tameshi-global.yaml")).unwrap_or_else(|e| {
        eprintln!("Warning: config load failed ({e}), using defaults");
        tameshi_global::config::Config::default()
    });

    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| config.log_level.parse().unwrap_or_default()),
        )
        .json()
        .init();

    tracing::info!(
        bind = %config.bind_address,
        port = config.port,
        "starting tameshi-global server"
    );

    // Build shared state
    let chain = Arc::new(GlobalStateRootChain::new());
    let index = Arc::new(ReverseIndex::new());
    let reporter = ClusterReporter::new(Arc::clone(&chain), Arc::clone(&index));
    let remediator = Remediator::new(BTreeMap::new(), MockRevocationClient::new());
    let metrics = Arc::new(Metrics::new());

    let app_state = Arc::new(AppState {
        reporter,
        chain: Arc::clone(&chain),
        index,
        remediator: Arc::new(tokio::sync::RwLock::new(remediator)),
        metrics,
    });

    // Build router: API routes use AppState, health routes use the chain directly
    let health_router = axum::Router::new()
        .route("/healthz", axum::routing::get(health::healthz))
        .route("/readyz", axum::routing::get(health::readyz))
        .with_state(chain);

    let app = api::router(app_state).merge(health_router);

    let addr = format!("{}:{}", config.bind_address, config.port);
    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    tracing::info!(%addr, "listening");

    axum::serve(listener, app).await.unwrap();
}
