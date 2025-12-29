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
