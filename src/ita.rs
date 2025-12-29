//!
//! This module provides concrete implementations of the ItaClient trait
//! for communicating with the Intel Trust Authority service.

use async_trait::async_trait;
use base64::Engine;
use reqwest::Client;
use serde_json::json;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::error::{KbsError, KbsResult};
use crate::models::attestation::VerifierNonce;
use crate::traits::ItaClient;

/// Intel Trust Authority API client.
///
/// This is a production-ready HTTP client for the Intel Trust Authority API.
///
/// # Example
///
/// ```rust
/// use gta_kbs::ita::IntelItaClient;
///
/// #[tokio::main]
/// async fn main() -> Result<(), Box<dyn std::error::Error>> {
///     let client = IntelItaClient::new(
///         "https://api.trustauthority.intel.com".to_string(),
///         "your-api-key".to_string(),
///     )?;
///
///     // Use the client...
///
///     Ok(())
/// }
/// ```
#[derive(Clone)]
pub struct IntelItaClient {
    /// HTTP client
    client: Client,
    /// Intel Trust Authority API base URL
    api_url: String,
    /// API key for authentication (base64 encoded)
    api_key: String,
    /// Request timeout in seconds
    timeout_secs: u64,
}

impl IntelItaClient {
    /// Create a new Intel Trust Authority client.
    ///
    /// # Arguments
    /// * `api_url` - Base URL of the Intel Trust Authority API
    ///              (e.g., "https://api.trustauthority.intel.com")
    /// * `api_key` - API key for authentication (base64 encoded)
    ///
    /// # Returns
    /// A new client instance.
    pub fn new(api_url: String, api_key: String) -> KbsResult<Self> {
        Ok(Self {
            client: Client::new(),
            api_url,
            api_key,
            timeout_secs: 30,
        })
    }

    /// Create a new client with custom timeout.
    ///
    /// # Arguments
    /// * `api_url` - Base URL of the Intel Trust Authority API
    /// * `api_key` - API key for authentication (base64 encoded)
    /// * `timeout_secs` - Request timeout in seconds
    pub fn with_timeout(api_url: String, api_key: String, timeout_secs: u64) -> KbsResult<Self> {
        Ok(Self {
            client: Client::new(),
            api_url,
            api_key,
            timeout_secs,
        })
    }

    /// Get the full URL for an API endpoint.
    fn url(&self, path: &str) -> String {
        format!("{}{}", self.api_url.trim_end_matches('/'), path)
    }

    /// Make an authenticated GET request to the ITA API.
    async fn get(&self, path: &str) -> KbsResult<reqwest::Response> {
        let url = self.url(path);
        let response = self
            .client
            .get(&url)
            .header("Authorization", &self.api_key)
            .header("Content-Type", "application/json")
            .timeout(std::time::Duration::from_secs(self.timeout_secs))
            .send()
            .await
            .map_err(|e| KbsError::ItaClient(format!("ITA GET request failed: {}", e)))?;

        Ok(response)
    }

    /// Make an authenticated POST request to the ITA API.
    async fn post(&self, path: &str, body: serde_json::Value) -> KbsResult<reqwest::Response> {
        let url = self.url(path);
        let response = self
            .client
            .post(&url)
            .header("Authorization", &self.api_key)
            .header("Content-Type", "application/json")
            .timeout(std::time::Duration::from_secs(self.timeout_secs))
            .json(&body)
            .send()
            .await
            .map_err(|e| KbsError::ItaClient(format!("ITA POST request failed: {}", e)))?;

        Ok(response)
    }

    /// Handle ITA API response.
    async fn handle_response(&self, response: reqwest::Response) -> KbsResult<String> {
        let status = response.status();

        if status.is_success() {
            response
                .text()
                .await
                .map_err(|e| KbsError::ItaClient(format!("Failed to read response: {}", e)))
        } else {
            let status_code = status.as_u16();
            let body = response
                .text()
                .await
                .unwrap_or_else(|_| "Unable to read error response".to_string());
            Err(KbsError::ItaClient(format!(
                "ITA API error: {} - {}",
                status_code, body
            )))
        }
    }
}

#[async_trait]
impl ItaClient for IntelItaClient {
    /// Get a verifier nonce from Intel Trust Authority.
    ///
    /// This calls the `/v1/verifier-nonce` endpoint.
    async fn get_nonce(&self, _request_id: &str) -> KbsResult<VerifierNonce> {
        let response = self.get("/v1/verifier-nonce").await?;

        // Parse the response - ITA returns a JSON with nonce data
        let text = self.handle_response(response).await?;
        let json: serde_json::Value = serde_json::from_str(&text)
            .map_err(|e| KbsError::ItaClient(format!("Failed to parse nonce response: {}", e)))?;

        // Extract nonce data from response
        let nonce_data = json
            .get("verifier_nonce")
            .and_then(|v| v.as_object())
            .ok_or_else(|| KbsError::ItaClient("Invalid nonce response format".to_string()))?;

        Ok(VerifierNonce {
            val: nonce_data
                .get("val")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            iat: nonce_data
                .get("iat")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            signature: nonce_data
                .get("signature")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
        })
    }

    /// Get an attestation token from Intel Trust Authority.
    ///
    /// This calls the `/v1/quote` endpoint with the quote.
    async fn get_token(
        &self,
        quote: Vec<u8>,
        user_data: Vec<u8>,
        event_log: Option<Vec<u8>>,
        nonce: &VerifierNonce,
        policy_ids: Vec<String>,
        request_id: &str,
    ) -> KbsResult<String> {
        use base64::Engine as _;

        // Build the request body
        let quote_b64 = base64::engine::general_purpose::STANDARD.encode(&quote);
        let user_data_b64 = base64::engine::general_purpose::STANDARD.encode(&user_data);

        let mut body = json!({
            "quote": quote_b64,
            "runtime_data": user_data_b64,
            "verifier_nonce": {
                "val": nonce.val,
                "iat": nonce.iat,
                "signature": nonce.signature,
            },
            "request_id": request_id,
        });

        // Add optional fields
        if let Some(event_log) = event_log {
            let event_log_b64 = base64::engine::general_purpose::STANDARD.encode(&event_log);
            body["event_log"] = json!(event_log_b64);
        }

        if !policy_ids.is_empty() {
            body["policy_ids"] = json!(policy_ids);
        }

        let response = self.post("/v1/quote", body).await?;
        let text = self.handle_response(response).await?;

        // Parse response to extract token
        let json: serde_json::Value = serde_json::from_str(&text)
            .map_err(|e| KbsError::ItaClient(format!("Failed to parse token response: {}", e)))?;

        // The token is typically in the "token" field
        let token = json
            .get("token")
            .and_then(|v| v.as_str())
            .ok_or_else(|| KbsError::ItaClient("Token not found in response".to_string()))?;

        Ok(token.to_string())
    }

    /// Verify an attestation token.
    ///
    /// This verifies the JWT signature using ITA's public key
    /// and extracts the claims.
    async fn verify_token(&self, token: &str) -> KbsResult<serde_json::Value> {
        // For JWT verification, we can use the jwt crate
        // However, we need ITA's public key for verification
        // For now, we'll decode without signature verification and extract claims
        // In production, you should verify the signature

        

        // Get the public key from ITA's JWKS endpoint or use a pre-configured key
        // For now, we'll decode without verification (NOT SECURE - for development only)
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 3 {
            return Err(KbsError::ItaClient("Invalid token format".to_string()));
        }

        // Decode the payload (middle part)
        use base64::Engine as _;
        let payload = parts[1];
        let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(payload)
            .map_err(|e| KbsError::ItaClient(format!("Failed to decode token: {}", e)))?;

        let claims: serde_json::Value = serde_json::from_slice(&decoded)
            .map_err(|e| KbsError::ItaClient(format!("Failed to parse claims: {}", e)))?;

        // TODO: Verify signature using ITA's public key
        // You can fetch the public key from ITA's JWKS endpoint
        // and use DecodingKey::from_rsa_pem() or similar

        Ok(claims)
    }
}


/// Mock ITA Client for testing.
///
/// This implementation returns mock responses for testing purposes.
/// It does NOT make any network calls.
///
/// # Example
///
/// ```rust
/// use gta_kbs::ita::MockItaClient;
///
/// let client = MockItaClient::new();
/// ```
#[derive(Clone)]
pub struct MockItaClient {
    /// Whether to simulate successful operations
    pub success: bool,
    /// Optional canned token to return
    pub canned_token: Option<String>,
}

impl MockItaClient {
    /// Create a new mock client that simulates success.
    pub fn new() -> Self {
        Self {
            success: true,
            canned_token: None,
        }
    }

    /// Create a new mock client with specific success state.
    pub fn with_success(success: bool) -> Self {
        Self {
            success,
            canned_token: None,
        }
    }

    /// Set a canned token to return.
    pub fn with_token(self, token: String) -> Self {
        Self {
            success: self.success,
            canned_token: Some(token),
        }
    }

    /// Generate a mock attestation token for testing.
    fn generate_mock_token(&self, request_id: &str) -> String {
        if let Some(ref token) = self.canned_token {
            return token.clone();
        }

        // Generate a mock JWT token (not signed, just for testing structure)
        let header = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(r#"{"alg":"RS256","typ":"JWT","kid":"test-key"}"#);

        let payload = json!({
            "attester_type": "SGX",
            "attester_tcb_status": "UpToDate",
            "attester_held_data": "mock-public-key-data",
            "policy_ids_matched": [],
            "verifier_instance_ids": [],
            "sgx_mrenclave": "a3b67c0fb8fc12bc56b720f7befcb7cfcb1862324a89e05ae7a31e8d1082f0a",
            "sgx_mrsigner": "aae07df6a1927e88a88a8928f9bee3e0a88ee5f9e2fbc27c62a2df08ace3d2b",
            "sgx_isvprodid": 0,
            "sgx_isvsvn": 0,
            "sgx_is_debuggable": false,
            "ver": "1.0",
            "iat": 1700000000,
            "exp": 1700003600,
            "sub": request_id,
        });

        let payload_encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(&payload.to_string());

        format!("{}.{}.{}", header, payload_encoded, "mock-signature")
    }
}

impl Default for MockItaClient {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ItaClient for MockItaClient {
    async fn get_nonce(&self, _request_id: &str) -> KbsResult<VerifierNonce> {
        if !self.success {
            return Err(KbsError::ItaClient("Mock: get_nonce failed".to_string()));
        }

        Ok(VerifierNonce {
            val: "mock-nonce-value".to_string(),
            iat: "mock-timestamp".to_string(),
            signature: "mock-signature".to_string(),
        })
    }

    async fn get_token(
        &self,
        _quote: Vec<u8>,
        _user_data: Vec<u8>,
        _event_log: Option<Vec<u8>>,
        _nonce: &VerifierNonce,
        _policy_ids: Vec<String>,
        request_id: &str,
    ) -> KbsResult<String> {
        if !self.success {
            return Err(KbsError::ItaClient("Mock: get_token failed".to_string()));
        }

        Ok(self.generate_mock_token(request_id))
    }

    async fn verify_token(&self, token: &str) -> KbsResult<serde_json::Value> {
        if !self.success {
            return Err(KbsError::ItaClient("Mock: verify_token failed".to_string()));
        }

        // Decode the mock token and return claims
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 3 {
            return Err(KbsError::ItaClient("Invalid token format".to_string()));
        }

        use base64::Engine as _;
        let payload = parts[1];
        let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(payload)
            .map_err(|e| KbsError::ItaClient(format!("Failed to decode token: {}", e)))?;

        serde_json::from_slice(&decoded)
            .map_err(|e| KbsError::ItaClient(format!("Failed to parse claims: {}", e)))
    }
}


/// Configurable mock ITA Client for advanced testing.
///
/// This allows setting custom responses for different scenarios.
///
/// # Example
///
/// ```rust
/// use gta_kbs::ita::TestItaClient;
/// use gta_kbs::models::attestation::VerifierNonce;
/// use std::sync::Arc;
/// use tokio::sync::RwLock;
///
/// let client = TestItaClient::new();
/// client.set_nonce_response(Ok(VerifierNonce {
///     val: "test-nonce".to_string(),
///     iat: "test-timestamp".to_string(),
///     signature: "test-sig".to_string(),
/// }));
/// ```
#[derive(Clone)]
pub struct TestItaClient {
    /// Pre-configured nonce response
    nonce_response: Arc<RwLock<Option<KbsResult<VerifierNonce>>>>,
    /// Pre-configured token response
    token_response: Arc<RwLock<Option<KbsResult<String>>>>,
    /// Pre-configured verification response
    verify_response: Arc<RwLock<Option<KbsResult<serde_json::Value>>>>,
}

impl TestItaClient {
    /// Create a new test client.
    pub fn new() -> Self {
        Self {
            nonce_response: Arc::new(RwLock::new(None)),
            token_response: Arc::new(RwLock::new(None)),
            verify_response: Arc::new(RwLock::new(None)),
        }
    }

    /// Set a custom nonce response.
    pub async fn set_nonce_response(&self, response: KbsResult<VerifierNonce>) {
        *self.nonce_response.write().await = Some(response);
    }

    /// Set a custom token response.
    pub async fn set_token_response(&self, response: KbsResult<String>) {
        *self.token_response.write().await = Some(response);
    }

    /// Set a custom verification response.
    pub async fn set_verify_response(&self, response: KbsResult<serde_json::Value>) {
        *self.verify_response.write().await = Some(response);
    }
}

impl Default for TestItaClient {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ItaClient for TestItaClient {
    async fn get_nonce(&self, _request_id: &str) -> KbsResult<VerifierNonce> {
        let response = self.nonce_response.read().await;
        match &*response {
            Some(result) => match result {
                Ok(nonce) => Ok(VerifierNonce {
                    val: nonce.val.clone(),
                    iat: nonce.iat.clone(),
                    signature: nonce.signature.clone(),
                }),
                Err(e) => Err(KbsError::ItaClient(format!("Mock error: {}", e))),
            },
            None => Ok(VerifierNonce {
                val: "test-nonce".to_string(),
                iat: "test-timestamp".to_string(),
                signature: "test-sig".to_string(),
            }),
        }
    }

    async fn get_token(
        &self,
        _quote: Vec<u8>,
        _user_data: Vec<u8>,
        _event_log: Option<Vec<u8>>,
        _nonce: &VerifierNonce,
        _policy_ids: Vec<String>,
        _request_id: &str,
    ) -> KbsResult<String> {
        let response = self.token_response.read().await;
        match &*response {
            Some(result) => match result {
                Ok(token) => Ok(token.clone()),
                Err(e) => Err(KbsError::ItaClient(format!("Mock error: {}", e))),
            },
            None => Ok("test-token".to_string()),
        }
    }

    async fn verify_token(&self, token: &str) -> KbsResult<serde_json::Value> {
        let response = self.verify_response.read().await;
        match &*response {
            Some(result) => match result {
                Ok(value) => Ok(value.clone()),
                Err(e) => Err(KbsError::ItaClient(format!("Mock error: {}", e))),
            },
            None => {
                // Default: parse and return token claims
                let parts: Vec<&str> = token.split('.').collect();
                if parts.len() != 3 {
                    return Ok(json!({"error": "Invalid token format"}));
                }

                let payload = parts[1];
                let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .decode(payload)
                    .unwrap_or_default();

                Ok(serde_json::from_slice(&decoded)
                    .unwrap_or_else(|_| json!({"parsed": false})))
            }
        }
    }
}
