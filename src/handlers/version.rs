
use axum::{
    extract::State,
    response::Json,
};
use serde::{Deserialize, Serialize};
use crate::handlers::AppState;

/// Service version information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceVersion {
    /// Service name
    pub service: String,

    /// Version
    pub version: String,

    /// Build date
    #[serde(skip_serializing_if = "Option::is_none")]
    pub build_date: Option<String>,

    /// Git commit hash
    #[serde(skip_serializing_if = "Option::is_none")]
    pub commit_hash: Option<String>,
}

impl ServiceVersion {
    /// Create a new service version.
    pub fn new() -> Self {
        Self {
            service: "gta-kbs".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            build_date: option_env!("BUILD_DATE").map(|s| s.to_string()),
            commit_hash: option_env!("COMMIT_HASH").map(|s| s.to_string()),
        }
    }
}

impl Default for ServiceVersion {
    fn default() -> Self {
        Self::new()
    }
}

/// GET /version - Get the service version.
pub async fn get_version(State(_state): State<AppState>) -> Json<ServiceVersion> {
    Json(ServiceVersion::new())
}
