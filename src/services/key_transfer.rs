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


use async_trait::async_trait;
use std::sync::Arc;

use crate::crypto::{aes, rsa};
use crate::error::{KbsError, KbsResult};
use crate::models::{
    AttestationTokenClaim, AttesterType, KeyTransferRequest,
    KeyTransferResponse, VerifierNonce,
};
use crate::repositories::{KeyStore, KeyTransferPolicyStore};
use crate::services::validation::validate_attestation_claims;
use crate::traits::{ItaClient, KeyManager};

/// Key transfer service trait.
#[async_trait]
pub trait KeyTransferService: Send + Sync {
    /// Transfer a key with evidence (quote/attestation token).
    async fn transfer_key_with_evidence(
        &self,
        key_id: uuid::Uuid,
        attestation_type: Option<String>,
        request: KeyTransferRequest,
    ) -> KbsResult<KeyTransferResponse>;

    /// Transfer a key with just a public key (no attestation).
    async fn transfer_key_without_attestation(
        &self,
        key_id: uuid::Uuid,
        public_key_pem: &str,
    ) -> KbsResult<KeyTransferResponse>;

    /// Get a nonce for background verification.
    async fn get_nonce(&self, key_id: uuid::Uuid) -> KbsResult<VerifierNonce>;
}

/// Implementation of the key transfer service.
pub struct KeyTransferServiceImpl<K, P, M, I>
where
    K: KeyStore,
    P: KeyTransferPolicyStore,
    M: KeyManager,
    I: ItaClient,
{
    key_store: Arc<K>,
    policy_store: Arc<P>,
    key_manager: Arc<M>,
    ita_client: Arc<I>,
    is_sgx: bool,
}

impl<K, P, M, I> KeyTransferServiceImpl<K, P, M, I>
where
    K: KeyStore,
    P: KeyTransferPolicyStore,
    M: KeyManager,
    I: ItaClient,
{
    /// Create a new key transfer service.
    pub fn new(
        key_store: Arc<K>,
        policy_store: Arc<P>,
        key_manager: Arc<M>,
        ita_client: Arc<I>,
        is_sgx: bool,
    ) -> Self {
        Self {
            key_store,
            policy_store,
            key_manager,
            ita_client,
            is_sgx,
        }
    }

    /// Get the wrapped key response.
    async fn get_wrapped_key(
        &self,
        key_id: uuid::Uuid,
        algorithm: &str,
        attester_held_data: &str,
        attester_type: AttesterType,
    ) -> KbsResult<KeyTransferResponse> {
        // Parse the public key from attester held data
        let public_key = rsa::parse_public_key_from_attester_data(
            attester_held_data,
            attester_type == AttesterType::Sgx,
        )?;

        // Get the secret key from KMS
        let secret_key = self
            .key_manager
            .transfer_key(&key_id.to_string())
            .await
            .map_err(|e| KbsError::KeyManager(e.to_string()))?;

        // Create SWK (Symmetric Wrapping Key)
        let swk = aes::generate_aes_key()?;

        // Wrap the secret key with SWK using AES-GCM
        let (nonce, wrapped_key) = aes::aes_gcm_encrypt(&secret_key, &swk)?;

        // Build the wrapped key metadata format
        // Format: [iv_len(4)][tag_len(4)][data_len(4)][iv][tag][data]
        let iv_len = nonce.len() as u32;
        let tag_len = 16u32; // GCM tag size
        let data_len = wrapped_key.len() as u32;

        let mut wrapped_key_with_metadata = Vec::new();
        wrapped_key_with_metadata.extend_from_slice(&iv_len.to_le_bytes());
        wrapped_key_with_metadata.extend_from_slice(&tag_len.to_le_bytes());
        wrapped_key_with_metadata.extend_from_slice(&data_len.to_le_bytes());
        wrapped_key_with_metadata.extend_from_slice(&nonce);
        wrapped_key_with_metadata.extend_from_slice(&wrapped_key);

        // Wrap the SWK with the public key using RSA-OAEP
        let wrapped_swk = rsa::rsa_oaep_wrap(&swk, &public_key)?;

        Ok(KeyTransferResponse {
            wrapped_key: wrapped_key_with_metadata,
            wrapped_swk,
        })
    }
}

#[async_trait]
impl<K, P, M, I> KeyTransferService for KeyTransferServiceImpl<K, P, M, I>
where
    K: KeyStore,
    P: KeyTransferPolicyStore,
    M: KeyManager,
    I: ItaClient,
{
    async fn transfer_key_with_evidence(
        &self,
        key_id: uuid::Uuid,
        attestation_type: Option<String>,
        request: KeyTransferRequest,
    ) -> KbsResult<KeyTransferResponse> {
        // Get the key
        let key = self.key_store.retrieve(key_id).await?;

        // Get the transfer policy
        let policy = self.policy_store.retrieve(key.transfer_policy_id).await?;

        let mut token = String::new();

        // Passport mode: client provides attestation token
        if let Some(ref attestation_token) = request.attestation_token {
            token = attestation_token.clone();
        }
        // Background verification mode
        else if request.quote.is_some() && request.nonce.is_some() {
            let att_type = if let Some(at) = attestation_type {
                at
            } else {
                policy.attestation_type.to_string()
            };

            // Verify attestation type matches policy
            if AttesterType::from_str(&att_type) != Some(policy.attestation_type) {
                return Err(KbsError::Validation(
                    "Attestation type does not match policy".into(),
                ));
            }

            // Get policy IDs for ITA matching
            let policy_ids = match policy.attestation_type {
                AttesterType::Sgx => policy
                    .sgx
                    .as_ref()
                    .and_then(|s| s.policy_ids.as_ref())
                    .map(|ids| ids.iter().map(|id| id.to_string()).collect())
                    .unwrap_or_default(),
                AttesterType::Tdx => policy
                    .tdx
                    .as_ref()
                    .and_then(|t| t.policy_ids.as_ref())
                    .map(|ids| ids.iter().map(|id| id.to_string()).collect())
                    .unwrap_or_default(),
            };

            // Get token from ITA
            token = self
                .ita_client
                .get_token(
                    request.quote.unwrap(),
                    request.user_data.unwrap_or_default(),
                    request.event_log,
                    request.nonce.as_ref().unwrap(),
                    policy_ids,
                    &key_id.to_string(),
                )
                .await
                .map_err(|e| KbsError::ItaClient(e.to_string()))?;
        } else {
            // Need to request a nonce first
            return Err(KbsError::Validation(
                "Either attestation_token or quote+nonce must be provided".into(),
            ));
        }

        // Verify the token
        let claims_json = self
            .ita_client
            .verify_token(&token)
            .await
            .map_err(|e| KbsError::ItaClient(e.to_string()))?;

        let claims: AttestationTokenClaim = serde_json::from_value(claims_json)
            .map_err(|e| KbsError::Validation(format!("Invalid token claims: {}", e)))?;

        // Verify attestation type matches
        if claims.attester_type != policy.attestation_type {
            return Err(KbsError::Authorization(
                "Token attestation type does not match policy".into(),
            ));
        }

        // Validate claims against policy
        validate_attestation_claims(&claims, &policy)?;

        // Get attester held data (public key)
        let attester_held_data = claims
            .attester_held_data
            .ok_or_else(|| KbsError::Validation("Missing attester_held_data in token".into()))?;

        // Get the wrapped key
        self.get_wrapped_key(key_id, &key.key_info.algorithm, &attester_held_data, claims.attester_type)
            .await
    }

    async fn transfer_key_without_attestation(
        &self,
        key_id: uuid::Uuid,
        public_key_pem: &str,
    ) -> KbsResult<KeyTransferResponse> {
        // Get the key
        let key = self.key_store.retrieve(key_id).await?;

        // Parse the public key from PEM using rsa crate
        let public_key = parse_rsa_public_key_from_pem(public_key_pem)?;

        // Get the secret key from KMS
        let secret_key = self
            .key_manager
            .transfer_key(&key_id.to_string())
            .await
            .map_err(|e| KbsError::KeyManager(e.to_string()))?;

        // Create SWK (Symmetric Wrapping Key)
        let swk = aes::generate_aes_key()?;

        // Wrap the secret key with SWK using AES-GCM
        let (nonce, wrapped_key) = aes::aes_gcm_encrypt(&secret_key, &swk)?;

        // Build the wrapped key metadata format
        let iv_len = nonce.len() as u32;
        let tag_len = 16u32; // GCM tag size
        let data_len = wrapped_key.len() as u32;

        let mut wrapped_key_with_metadata = Vec::new();
        wrapped_key_with_metadata.extend_from_slice(&iv_len.to_le_bytes());
        wrapped_key_with_metadata.extend_from_slice(&tag_len.to_le_bytes());
        wrapped_key_with_metadata.extend_from_slice(&data_len.to_le_bytes());
        wrapped_key_with_metadata.extend_from_slice(&nonce);
        wrapped_key_with_metadata.extend_from_slice(&wrapped_key);

        // Wrap the SWK with the public key using RSA-OAEP
        let wrapped_swk = rsa::rsa_oaep_wrap(&swk, &public_key)?;

        Ok(KeyTransferResponse {
            wrapped_key: wrapped_key_with_metadata,
            wrapped_swk,
        })
    }

    async fn get_nonce(&self, key_id: uuid::Uuid) -> KbsResult<VerifierNonce> {
        // Get the key to verify it exists
        self.key_store.retrieve(key_id).await?;

        // Get nonce from ITA
        self.ita_client
            .get_nonce(&key_id.to_string())
            .await
            .map_err(|e| KbsError::ItaClient(e.to_string()))
    }
}

/// Parse RSA public key from PEM format.
fn parse_rsa_public_key_from_pem(pem: &str) -> KbsResult<rsa::RsaPublicKey> {
    use pkcs8::DecodePublicKey;

    // Use the rsa crate's public key parsing with pkcs8 trait
    let public_key = rsa::RsaPublicKey::from_public_key_pem(pem)
        .map_err(|e| KbsError::Crypto(format!("Failed to parse RSA public key from PEM: {}", e)))?;

    Ok(public_key)
}
