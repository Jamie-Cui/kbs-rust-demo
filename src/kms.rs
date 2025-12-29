//!
//! This module provides concrete implementations of the KeyManager trait
//! for various KMS backends.

use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::crypto::aes;
use crate::error::{KbsError, KbsResult};
use crate::models::{KeyInfo, KeyRequest};
use crate::traits::KeyManager;

/// In-memory Key Manager for development and testing.
///
/// This implementation stores keys in memory and should NOT be used in production.
/// It's useful for development, testing, and as a reference for implementing
/// production KeyManagers for real KMS backends (Vault, KMIP, etc.).
///
/// # Example
///
/// ```rust
/// use gta_kbs::kms::MemoryKeyManager;
/// use gta_kbs::models::{KeyRequest, KeyInfo};
/// use gta_kbs::traits::KeyManager;
/// use uuid::Uuid;
///
/// #[tokio::main]
/// async fn main() -> Result<(), Box<dyn std::error::Error>> {
///     let key_manager = MemoryKeyManager::new();
///
///     let request = KeyRequest {
///         key_information: KeyInfo {
///             algorithm: "AES".to_string(),
///             key_length: Some(256),
///             curve_type: None,
///             key_data: None,
///             kmip_key_id: None,
///         },
///         transfer_policy_id: Uuid::new_v4(),
///     };
///
///     let key_info = key_manager.create_key(&request).await?;
///     println!("Created key: {:?}", key_info);
///
///     Ok(())
/// }
/// ```
#[derive(Clone)]
pub struct MemoryKeyManager {
    /// In-memory key storage (key_id -> key_material)
    keys: Arc<RwLock<HashMap<String, StoredKey>>>,
}

/// Stored key information.
struct StoredKey {
    /// Key information
    key_info: KeyInfo,
    /// Raw key material (bytes)
    key_material: Vec<u8>,
}

impl MemoryKeyManager {
    /// Create a new in-memory key manager.
    pub fn new() -> Self {
        Self {
            keys: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Generate a unique key ID.
    fn generate_key_id() -> String {
        format!("kms-{}", Uuid::new_v4())
    }

    /// Create a key ID from the key info.
    fn key_id_from_info(key_info: &KeyInfo) -> String {
        if let Some(ref kmip_id) = key_info.kmip_key_id {
            return kmip_id.clone();
        }
        Self::generate_key_id()
    }
}

impl Default for MemoryKeyManager {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl KeyManager for MemoryKeyManager {
    async fn create_key(&self, request: &KeyRequest) -> KbsResult<KeyInfo> {
        let key_info = &request.key_information;

        // Validate the key info
        key_info.validate()?;

        let key_material = match key_info.algorithm.to_uppercase().as_str() {
            "AES" => {
                // Generate AES key
                let key_bytes = key_info.key_length.unwrap_or(256) / 8;
                aes::generate_aes_key_with_size(key_bytes as usize)?
            }
            "RSA" => {
                // For RSA, generate a key pair and return the private key in DER format
                let key_bits = key_info.key_length.unwrap_or(2048);
                rsa_generate_private_key(key_bits as usize).await?
            }
            "EC" => {
                // For EC, generate a key pair
                let curve = key_info.curve_type.as_ref()
                    .map(|s| s.as_str())
                    .unwrap_or("prime256v1");
                ec_generate_private_key(curve).await?
            }
            _ => {
                return Err(KbsError::KeyManager(format!(
                    "Unsupported algorithm: {}",
                    key_info.algorithm
                )));
            }
        };

        // Generate a key ID
        let key_id = Self::key_id_from_info(key_info);

        // Store the key
        let stored_key = StoredKey {
            key_info: key_info.clone(),
            key_material,
        };

        self.keys.write().await.insert(key_id.clone(), stored_key);

        // Return the key info with the generated key ID
        Ok(KeyInfo {
            algorithm: key_info.algorithm.clone(),
            key_length: key_info.key_length,
            curve_type: key_info.curve_type.clone(),
            key_data: key_info.key_data.clone(),
            kmip_key_id: Some(key_id),
        })
    }

    async fn delete_key(&self, key_id: &str) -> KbsResult<()> {
        self.keys
            .write()
            .await
            .remove(key_id)
            .ok_or_else(|| KbsError::NotFound(format!("Key not found: {}", key_id)))?;
        Ok(())
    }

    async fn register_key(&self, request: &KeyRequest) -> KbsResult<KeyInfo> {
        let key_info = &request.key_information;

        // Validate that this is a registration request
        if key_info.is_create() {
            return Err(KbsError::Validation(
                "Cannot register a key without key_data or kmip_key_id".to_string(),
            ));
        }

        // Generate a key ID if not provided
        let key_id = if let Some(ref kmip_id) = key_info.kmip_key_id {
            kmip_id.clone()
        } else {
            Self::generate_key_id()
        };

        // If key_data is provided, decode it and store
        if let Some(ref key_data) = key_info.key_data {
            use base64::Engine as _;
            let key_material = base64::engine::general_purpose::STANDARD
                .decode(key_data)
                .map_err(|e| KbsError::Validation(format!("Invalid base64 key_data: {}", e)))?;

            let stored_key = StoredKey {
                key_info: key_info.clone(),
                key_material,
            };

            self.keys.write().await.insert(key_id.clone(), stored_key);
        }

        Ok(KeyInfo {
            algorithm: key_info.algorithm.clone(),
            key_length: key_info.key_length,
            curve_type: key_info.curve_type.clone(),
            key_data: key_info.key_data.clone(),
            kmip_key_id: Some(key_id),
        })
    }

    async fn transfer_key(&self, key_id: &str) -> KbsResult<Vec<u8>> {
        let keys = self.keys.read().await;
        let stored_key = keys
            .get(key_id)
            .ok_or_else(|| KbsError::NotFound(format!("Key not found: {}", key_id)))?;

        Ok(stored_key.key_material.clone())
    }
}

/// Generate an RSA private key and return it as DER bytes.
async fn rsa_generate_private_key(bits: usize) -> KbsResult<Vec<u8>> {
    use pkcs8::EncodePrivateKey;
    use rand::rngs::OsRng;
    use rsa::RsaPrivateKey;

    let mut rng = OsRng;
    let private_key = RsaPrivateKey::new(&mut rng, bits)
        .map_err(|e| KbsError::Crypto(format!("Failed to generate RSA key: {}", e)))?;

    // Serialize to DER (PKCS#8)
    let der_bytes = private_key.to_pkcs8_der()
        .map_err(|e| KbsError::Crypto(format!("Failed to serialize RSA key: {}", e)))?;

    Ok(der_bytes.to_bytes().to_vec())
}

/// Generate an EC private key and return it as DER bytes.
async fn ec_ec_generate_private_key(_curve: &str) -> KbsResult<Vec<u8>> {
    // For EC keys, we would use p256 or similar crate
    // For now, return a placeholder
    Err(KbsError::KeyManager(
        "EC key generation not yet implemented - please use a real KMS".to_string(),
    ))
}

/// Placeholder function - renamed to avoid conflict
async fn ec_generate_private_key(curve: &str) -> KbsResult<Vec<u8>> {
    // For EC keys, we would use p256 or k256 crate
    // For now, return an error
    Err(KbsError::KeyManager(
        format!("EC key generation not yet implemented for curve: {} - please use a real KMS or implement using p256/k256 crate", curve)
    ))
}


/// HashiCorp Vault Key Manager.
///
/// This implementation connects to HashiCorp Vault's KV secrets engine
/// for key storage. This is a production-ready implementation for Vault.
///
/// # Example
///
/// ```rust
/// use gta_kbs::kms::VaultKeyManager;
///
/// #[tokio::main]
/// async fn main() -> Result<(), Box<dyn std::error::Error>> {
///     let key_manager = VaultKeyManager::new(
///         "http://localhost:8200".to_string(),
///         "my-token".to_string(),
///         "secret".to_string(), // KV secrets engine mount
///     )?;
///
///     // Use the key manager...
///
///     Ok(())
/// }
/// ```
#[cfg(feature = "vault")]
#[derive(Clone)]
pub struct VaultKeyManager {
    /// Vault client
    client: reqwest::Client,
    /// Vault address
    vault_addr: String,
    /// Vault token
    vault_token: String,
    /// KV secrets engine path
    kv_mount: String,
}

#[cfg(feature = "vault")]
impl VaultKeyManager {
    /// Create a new Vault key manager.
    ///
    /// # Arguments
    /// * `vault_addr` - Vault address (e.g., "http://localhost:8200")
    /// * `vault_token` - Vault token for authentication
    /// * `kv_mount` - KV secrets engine mount path (e.g., "secret")
    pub fn new(vault_addr: String, vault_token: String, kv_mount: String) -> KbsResult<Self> {
        Ok(Self {
            client: reqwest::Client::new(),
            vault_addr,
            vault_token,
            kv_mount,
        })
    }

    /// Get the full path for a key in Vault.
    fn vault_path(&self, key_id: &str) -> String {
        format!("{}/v1/{}/data/{}", self.vault_addr, self.kv_mount, key_id)
    }

    /// Write a key to Vault.
    async fn vault_write(&self, key_id: &str, data: serde_json::Value) -> KbsResult<()> {
        let url = self.vault_path(key_id);
        let response = self
            .client
            .post(&url)
            .header("X-Vault-Token", &self.vault_token)
            .json(&data)
            .send()
            .await
            .map_err(|e| KbsError::KeyManager(format!("Vault request failed: {}", e)))?;

        if response.status().is_success() {
            Ok(())
        } else {
            let status = response.status();
            let body = response
                .text()
                .await
                .unwrap_or_else(|_| "Unable to read response".to_string());
            Err(KbsError::KeyManager(format!(
                "Vault write failed: {} - {}",
                status, body
            )))
        }
    }

    /// Read a key from Vault.
    async fn vault_read(&self, key_id: &str) -> KbsResult<serde_json::Value> {
        let url = self.vault_path(key_id);
        let response = self
            .client
            .get(&url)
            .header("X-Vault-Token", &self.vault_token)
            .send()
            .await
            .map_err(|e| KbsError::KeyManager(format!("Vault request failed: {}", e)))?;

        if response.status().is_success() {
            response
                .json()
                .await
                .map_err(|e| KbsError::KeyManager(format!("Failed to parse Vault response: {}", e)))
        } else {
            let status = response.status();
            let body = response
                .text()
                .await
                .unwrap_or_else(|_| "Unable to read response".to_string());
            Err(KbsError::KeyManager(format!(
                "Vault read failed: {} - {}",
                status, body
            )))
        }
    }

    /// Delete a key from Vault.
    async fn vault_delete(&self, key_id: &str) -> KbsResult<()> {
        let url = self.vault_path(key_id);
        let response = self
            .client
            .delete(&url)
            .header("X-Vault-Token", &self.vault_token)
            .send()
            .await
            .map_err(|e| KbsError::KeyManager(format!("Vault request failed: {}", e)))?;

        if response.status().is_success() {
            Ok(())
        } else {
            let status = response.status();
            let body = response
                .text()
                .await
                .unwrap_or_else(|_| "Unable to read response".to_string());
            Err(KbsError::KeyManager(format!(
                "Vault delete failed: {} - {}",
                status, body
            )))
        }
    }
}

#[cfg(feature = "vault")]
#[async_trait]
impl KeyManager for VaultKeyManager {
    async fn create_key(&self, request: &KeyRequest) -> KbsResult<KeyInfo> {
        let key_info = &request.key_information;
        key_info.validate()?;

        let key_material = match key_info.algorithm.to_uppercase().as_str() {
            "AES" => {
                let key_bytes = key_info.key_length.unwrap_or(256) / 8;
                aes::generate_aes_key_with_size(key_bytes as usize)?
            }
            "RSA" => {
                let key_bits = key_info.key_length.unwrap_or(2048);
                rsa_generate_private_key(key_bits as usize).await?
            }
            "EC" => {
                let curve = key_info.curve_type.as_ref()
                    .map(|s| s.as_str())
                    .unwrap_or("prime256v1");
                ec_generate_private_key(curve).await?
            }
            _ => {
                return Err(KbsError::KeyManager(format!(
                    "Unsupported algorithm: {}",
                    key_info.algorithm
                )));
            }
        };

        // Encode key material as base64 for storage
        use base64::Engine as _;
        let key_data_b64 = base64::engine::general_purpose::STANDARD.encode(&key_material);

        // Generate a key ID
        let key_id = format!("kms-{}", Uuid::new_v4());

        // Store in Vault
        let vault_data = serde_json::json!({
            "algorithm": key_info.algorithm,
            "key_length": key_info.key_length,
            "curve_type": key_info.curve_type,
            "key_material": key_data_b64,
        });

        self.vault_write(&key_id, vault_data).await?;

        Ok(KeyInfo {
            algorithm: key_info.algorithm.clone(),
            key_length: key_info.key_length,
            curve_type: key_info.curve_type.clone(),
            key_data: None,
            kmip_key_id: Some(key_id),
        })
    }

    async fn delete_key(&self, key_id: &str) -> KbsResult<()> {
        self.vault_delete(key_id).await
    }

    async fn register_key(&self, request: &KeyRequest) -> KbsResult<KeyInfo> {
        let key_info = &request.key_information;

        if key_info.is_create() {
            return Err(KbsError::Validation(
                "Cannot register a key without key_data or kmip_key_id".to_string(),
            ));
        }

        let key_id = if let Some(ref kmip_id) = key_info.kmip_key_id {
            kmip_id.clone()
        } else {
            format!("kms-{}", Uuid::new_v4())
        };

        // If key_data is provided, store it in Vault
        if let Some(ref key_data) = key_info.key_data {
            let vault_data = serde_json::json!({
                "algorithm": key_info.algorithm,
                "key_length": key_info.key_length,
                "curve_type": key_info.curve_type,
                "key_material": key_data,
            });

            self.vault_write(&key_id, vault_data).await?;
        }

        Ok(KeyInfo {
            algorithm: key_info.algorithm.clone(),
            key_length: key_info.key_length,
            curve_type: key_info.curve_type.clone(),
            key_data: key_info.key_data.clone(),
            kmip_key_id: Some(key_id),
        })
    }

    async fn transfer_key(&self, key_id: &str) -> KbsResult<Vec<u8>> {
        let response = self.vault_read(key_id).await?;

        // Parse the Vault response
        let data = response["data"]["data"]
            .as_object()
            .ok_or_else(|| KbsError::KeyManager("Invalid Vault response format".to_string()))?;

        let key_material_b64 = data
            .get("key_material")
            .and_then(|v| v.as_str())
            .ok_or_else(|| KbsError::KeyManager("key_material not found in Vault".to_string()))?;

        // Decode base64
        use base64::Engine as _;
        let key_material = base64::engine::general_purpose::STANDARD
            .decode(key_material_b64)
            .map_err(|e| KbsError::KeyManager(format!("Failed to decode key material: {}", e)))?;

        Ok(key_material)
    }
}
