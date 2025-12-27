/*
 *   Copyright (c) 2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

//! Intel Trust Authority Client implementation.
//!
//! This module provides a Rust implementation of the Intel Trust Authority API client.

use async_trait::async_trait;
use reqwest::{Client, header};
use serde::{Deserialize, Serialize};
use base64::{Engine as _, engine::general_purpose};
use crate::{
    config::Configuration,
    error::{KbsError, KbsResult},
    models::attestation::VerifierNonce,
    traits::ItaClient,
};

pub mod requests;
pub mod responses;

use requests::{GetNonceRequest, GetTokenRequest};
use responses::{GetNonceResponse, GetTokenResponse, VerifyTokenResponse};

/// ITA Client implementation.
#[derive(Clone)]
pub struct IntelItaClient {
    /// HTTP client
    client: Client,

    /// Base URL for ITA portal
    base_url: String,

    /// API URL for ITA API
    api_url: String,

    /// API key (base64 encoded)
    api_key: String,
}

impl IntelItaClient {
    /// Create a new ITA client.
    pub fn new(config: &Configuration) -> KbsResult<Self> {
        // Decode the API key from base64
        let _decoded = general_purpose::STANDARD
            .decode(&config.trust_authority_api_key)
            .map_err(|e| KbsError::Config(format!("Invalid API key encoding: {}", e)))?;

        // Parse server name from API URL for TLS
        let server_name = url::Url::parse(&config.trust_authority_api_url)
            .map_err(|e| KbsError::Config(format!("Invalid API URL: {}", e)))?
            .host_str()
            .ok_or_else(|| KbsError::Config("Invalid API URL: no host".into()))?
            .to_string();

        // Build HTTP client with TLS configuration
        let client = Client::builder()
            .min_tls_version(reqwest::tls::Version::TLS_1_2)
            .build()
            .map_err(|e| KbsError::Internal(format!("Failed to create HTTP client: {}", e)))?;

        Ok(Self {
            client,
            base_url: config.trust_authority_base_url.clone(),
            api_url: config.trust_authority_api_url.clone(),
            api_key: config.trust_authority_api_key.clone(),
        })
    }

    /// Get the full URL for an API endpoint.
    fn api_endpoint(&self, path: &str) -> String {
        format!("{}{}", self.api_url, path)
    }

    /// Get authorization headers.
    fn auth_headers(&self) -> header::HeaderMap {
        let mut headers = header::HeaderMap::new();
        headers.insert(
            header::CONTENT_TYPE,
            header::HeaderValue::from_static("application/json"),
        );
        headers.insert(
            "x-api-key",
            header::HeaderValue::from_str(&self.api_key)
                .expect("API key contains invalid header characters"),
        );
        headers
    }
}

#[async_trait]
impl ItaClient for IntelItaClient {
    async fn get_nonce(&self, request_id: &str) -> KbsResult<VerifierNonce> {
        let request = GetNonceRequest {
            request_id: request_id.to_string(),
        };

        let response = self
            .client
            .post(&self.api_endpoint("/nonce"))
            .headers(self.auth_headers())
            .json(&request)
            .send()
            .await
            .map_err(|e| KbsError::ItaClient(format!("ITA API request failed: {}", e)))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response
                .text()
                .await
                .unwrap_or_else(|_| "Unable to read error body".into());
            return Err(KbsError::ItaClient(format!(
                "ITA API returned error {}: {}",
                status, body
            )));
        }

        let nonce_response: GetNonceResponse = response
            .json()
            .await
            .map_err(|e| KbsError::ItaClient(format!("Failed to parse nonce response: {}", e)))?;

        Ok(VerifierNonce {
            val: nonce_response.nonce.val,
            iat: nonce_response.nonce.iat,
            signature: nonce_response.nonce.signature,
        })
    }

    async fn get_token(
        &self,
        quote: Vec<u8>,
        user_data: Vec<u8>,
        event_log: Option<Vec<u8>>,
        nonce: &VerifierNonce,
        policy_ids: Vec<String>,
        request_id: &str,
    ) -> KbsResult<String> {
        let request = GetTokenRequest {
            nonce: crate::models::attestation::VerifierNonceRequest {
                val: nonce.val.clone(),
                iat: nonce.iat.clone(),
                signature: nonce.signature.clone(),
            },
            evidence: Some(requests::Evidence {
                evidence: general_purpose::STANDARD.encode(&quote),
                user_data: general_purpose::STANDARD.encode(&user_data),
                event_log: event_log
                    .as_ref()
                    .map(|log| general_purpose::STANDARD.encode(log)),
            }),
            policy_ids,
            request_id: request_id.to_string(),
        };

        let response = self
            .client
            .post(&self.api_endpoint("/token"))
            .headers(self.auth_headers())
            .json(&request)
            .send()
            .await
            .map_err(|e| KbsError::ItaClient(format!("ITA API request failed: {}", e)))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response
                .text()
                .await
                .unwrap_or_else(|_| "Unable to read error body".into());
            return Err(KbsError::ItaClient(format!(
                "ITA API returned error {}: {}",
                status, body
            )));
        }

        let token_response: GetTokenResponse = response
            .json()
            .await
            .map_err(|e| KbsError::ItaClient(format!("Failed to parse token response: {}", e)))?;

        Ok(token_response.token)
    }

    async fn verify_token(&self, token: &str) -> KbsResult<serde_json::Value> {
        let response = self
            .client
            .post(&self.api_endpoint("/verify"))
            .headers(self.auth_headers())
            .json(&serde_json::json!({ "token": token }))
            .send()
            .await
            .map_err(|e| KbsError::ItaClient(format!("ITA API request failed: {}", e)))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response
                .text()
                .await
                .unwrap_or_else(|_| "Unable to read error body".into());
            return Err(KbsError::ItaClient(format!(
                "ITA API returned error {}: {}",
                status, body
            )));
        }

        let verify_response: VerifyTokenResponse = response
            .json()
            .await
            .map_err(|e| KbsError::ItaClient(format!("Failed to parse verify response: {}", e)))?;

        Ok(verify_response.claims)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_client() {
        // This test requires valid configuration
        // Skip in CI unless credentials are available
    }
}
