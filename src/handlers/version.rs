// Copyright (c) 2025 Jamie Cui
//
// MIT License
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.


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
