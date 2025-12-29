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


use crate::models::attestation::VerifierNonce;
use serde::{Deserialize, Serialize};

/// Key transfer request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyTransferRequest {
    /// Attestation token (for passport mode)
    #[serde(rename = "attestation_token")]
    pub attestation_token: Option<String>,

    /// Quote (for background verification mode)
    pub quote: Option<Vec<u8>>,

    /// Verifier nonce (for background verification mode)
    pub nonce: Option<VerifierNonce>,

    /// Runtime data / user data (public key from workload)
    #[serde(rename = "user_data")]
    pub user_data: Option<Vec<u8>>,

    /// Event log (for TDX)
    #[serde(rename = "event_log")]
    pub event_log: Option<Vec<u8>>,
}

/// Key transfer response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyTransferResponse {
    /// Wrapped key (key wrapped with SWK using AES-GCM)
    #[serde(rename = "wrapped_key")]
    pub wrapped_key: Vec<u8>,

    /// Wrapped SWK (SWK wrapped with public key using RSA-OAEP)
    #[serde(rename = "wrapped_swk")]
    pub wrapped_swk: Vec<u8>,
}

/// Internal key transfer request (with additional metadata).
#[derive(Debug, Clone)]
pub struct TransferKeyRequest {
    /// Key ID
    pub key_id: uuid::Uuid,

    /// Public key from the attested workload (RSA)
    pub public_key: Option<rsa::RsaPublicKey>,

    /// Attestation type
    pub attestation_type: Option<String>,

    /// Key transfer request
    pub request: KeyTransferRequest,
}

/// RSA public key representation.
#[derive(Debug, Clone)]
pub struct RsaPublicKey {
    /// Modulus
    pub n: Vec<u8>,

    /// Exponent
    pub e: u32,
}

impl RsaPublicKey {
    /// Create a new RSA public key from modulus and exponent.
    pub fn new(n: Vec<u8>, e: u32) -> Self {
        Self { n, e }
    }

    /// Get the modulus as bytes.
    pub fn modulus(&self) -> &[u8] {
        &self.n
    }

    /// Get the exponent.
    pub fn exponent(&self) -> u32 {
        self.e
    }

    /// Get the key size in bits.
    pub fn key_size(&self) -> usize {
        self.n.len() * 8
    }
}
