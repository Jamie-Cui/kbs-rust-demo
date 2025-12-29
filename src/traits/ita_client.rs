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

//!
//! This trait defines the interface for communicating with the Intel Trust Authority service.
//! You need to implement this to interact with the ITA API.
//!
//! # Example Implementation
//!
//! ```rust
//! use gta_kbs::traits::ItaClient;
//! use gta_kbs::models::attestation::VerifierNonce;
//! use gta_kbs::error::{KbsResult, KbsError};
//!
//! struct MyItaClient {
//!     api_url: String,
//!     api_key: String,
//! }
//!
//! #[async_trait::async_trait]
//! impl ItaClient for MyItaClient {
//!     async fn get_nonce(&self, request_id: &str) -> KbsResult<VerifierNonce> {
//!         // Implement nonce retrieval from ITA
//!         // This should call ITA's GetNonce API
//!         todo!("Implement get_nonce")
//!     }
//!
//!     async fn get_token(
//!         &self,
//!         quote: Vec<u8>,
//!         user_data: Vec<u8>,
//!         event_log: Option<Vec<u8>>,
//!         nonce: &VerifierNonce,
//!         policy_ids: Vec<String>,
//!         request_id: &str,
//!     ) -> KbsResult<String> {
//!         // Implement token retrieval from ITA
//!         // This should call ITA's GetToken API with the quote
//!         // Returns the attestation token (JWT)
//!         todo!("Implement get_token")
//!     }
//!
//!     async fn verify_token(&self, token: &str) -> KbsResult<serde_json::Value> {
//!         // Implement token verification
//!         // This should verify the token's signature and extract claims
//!         // Returns the decoded token claims
//!         todo!("Implement token verification")
//!     }
//! }
//! ```

use async_trait::async_trait;
use crate::error::KbsResult;
use crate::models::attestation::VerifierNonce;
use serde_json::Value;

/// Intel Trust Authority Client trait.
///
/// This trait abstracts the communication with the Intel Trust Authority service
/// for remote attestation operations.
#[async_trait]
pub trait ItaClient: Send + Sync {
    /// Get a verifier nonce from Intel Trust Authority.
    ///
    /// This is the first step in the background verification mode.
    /// The nonce is sent to the workload to be included in the quote.
    ///
    /// # Arguments
    /// * `request_id` - Unique identifier for this request (typically the key ID)
    ///
    /// # Returns
    /// A signed verifier nonce from ITA.
    async fn get_nonce(&self, request_id: &str) -> KbsResult<VerifierNonce>;

    /// Get an attestation token from Intel Trust Authority.
    ///
    /// This is called after receiving a quote from the workload.
    /// ITA verifies the quote and returns an attestation token.
    ///
    /// # Arguments
    /// * `quote` - The SGX or TDX quote from the workload
    /// * `user_data` - Runtime data (public key) from the workload
    /// * `event_log` - Optional event log (for TDX)
    /// * `nonce` - The verifier nonce (from get_nonce)
    /// * `policy_ids` - Optional list of policy IDs to match
    /// * `request_id` - Unique identifier for this request
    ///
    /// # Returns
    /// The attestation token as a JWT string.
    async fn get_token(
        &self,
        quote: Vec<u8>,
        user_data: Vec<u8>,
        event_log: Option<Vec<u8>>,
        nonce: &VerifierNonce,
        policy_ids: Vec<String>,
        request_id: &str,
    ) -> KbsResult<String>;

    /// Verify an attestation token.
    ///
    /// This verifies the token's signature and extracts the claims.
    /// Used in passport mode where the client provides a pre-obtained token.
    ///
    /// # Arguments
    /// * `token` - The attestation token (JWT) to verify
    ///
    /// # Returns
    /// The decoded token claims as a JSON value.
    async fn verify_token(&self, token: &str) -> KbsResult<Value>;
}
