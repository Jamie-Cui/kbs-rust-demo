/*
 *   Copyright (c) 2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

//! ITA API request types.

use crate::models::attestation::VerifierNonceRequest;
use serde::{Deserialize, Serialize};

/// Request to get a verifier nonce from ITA.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetNonceRequest {
    /// Unique identifier for this request
    pub request_id: String,
}

/// Request to get an attestation token from ITA.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetTokenRequest {
    /// Verifier nonce (from GetNonce response)
    pub nonce: VerifierNonceRequest,

    /// Evidence containing quote and runtime data
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence: Option<Evidence>,

    /// Optional list of policy IDs to match
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub policy_ids: Vec<String>,

    /// Unique identifier for this request
    pub request_id: String,
}

/// Evidence payload for attestation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    /// Base64-encoded SGX/TDX quote
    pub evidence: String,

    /// Base64-encoded runtime data (public key)
    pub user_data: String,

    /// Base64-encoded event log (for TDX)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event_log: Option<String>,
}
