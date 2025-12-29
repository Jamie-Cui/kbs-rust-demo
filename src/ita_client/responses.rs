
use crate::models::attestation::VerifierNonceData;
use serde::{Deserialize, Serialize};

/// Response from GetNonce API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetNonceResponse {
    /// Signed verifier nonce
    pub nonce: VerifierNonceData,
}

/// Response from GetToken API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetTokenResponse {
    /// Attestation token (JWT)
    pub token: String,
}

/// Response from VerifyToken API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyTokenResponse {
    /// Decoded token claims
    pub claims: serde_json::Value,
}
