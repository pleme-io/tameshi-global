//! Configuration loading via shikumi's ProviderChain (defaults -> YAML -> env).

use serde::{Deserialize, Serialize};

/// Server configuration.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Config {
    /// Address to bind the HTTP server to.
    pub bind_address: String,
    /// Port to listen on.
    pub port: u16,
    /// Log level (e.g., "info", "debug", "trace").
    pub log_level: String,
    /// Stale threshold in seconds — cluster is stale after this many seconds without a report.
    pub stale_threshold_secs: u64,
    /// Offline threshold in seconds — cluster is offline after this many seconds without a report.
    pub offline_threshold_secs: u64,
    /// Whether to enable Prometheus metrics endpoint.
    pub metrics_enabled: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            bind_address: "0.0.0.0".to_string(),
            port: 8090,
            log_level: "info".to_string(),
            stale_threshold_secs: 120,
            offline_threshold_secs: 360,
            metrics_enabled: true,
        }
    }
}

/// Load configuration from defaults, YAML file, and environment variables.
///
/// Environment variables are prefixed with `TAMESHI_GLOBAL_` and use `__` as
/// separator for nested keys. For example, `TAMESHI_GLOBAL_PORT=9090`.
///
/// # Errors
///
/// Returns an error if the configuration cannot be loaded or parsed.
pub fn load_config(yaml_path: Option<&str>) -> crate::error::Result<Config> {
    let mut chain = shikumi::ProviderChain::new().with_defaults(&Config::default());

    if let Some(path) = yaml_path {
        chain = chain.with_file(std::path::Path::new(path));
    }

    chain
        .with_env("TAMESHI_GLOBAL_")
        .extract()
        .map_err(|e| crate::error::Error::Config(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_values() {
        let config = Config::default();
        assert_eq!(config.bind_address, "0.0.0.0");
        assert_eq!(config.port, 8090);
        assert_eq!(config.log_level, "info");
        assert_eq!(config.stale_threshold_secs, 120);
        assert_eq!(config.offline_threshold_secs, 360);
        assert!(config.metrics_enabled);
    }

    #[test]
    fn load_config_defaults() {
        let config = load_config(None).unwrap();
        assert_eq!(config.port, 8090);
        assert_eq!(config.bind_address, "0.0.0.0");
    }

    #[test]
    fn load_config_nonexistent_yaml_uses_defaults() {
        let config = load_config(Some("/nonexistent/config.yaml")).unwrap();
        assert_eq!(config.port, 8090);
    }

    #[test]
    fn config_serde_roundtrip() {
        let config = Config::default();
        let json = serde_json::to_string(&config).unwrap();
        let deserialized: Config = serde_json::from_str(&json).unwrap();
        assert_eq!(config, deserialized);
    }

    #[test]
    fn config_clone() {
        let config = Config::default();
        let cloned = config.clone();
        assert_eq!(config, cloned);
    }
}
