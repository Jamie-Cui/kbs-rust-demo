
use crate::constant;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Key request for creating or registering a key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyRequest {
    /// Key information
    pub key_information: KeyInfo,

    /// Transfer policy ID
    #[serde(rename = "transfer_policy_id")]
    pub transfer_policy_id: Uuid,
}

/// Key update request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyUpdateRequest {
    /// Transfer policy ID
    #[serde(rename = "transfer_policy_id")]
    pub transfer_policy_id: Uuid,
}

/// Key response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyResponse {
    /// Key ID
    pub id: Uuid,

    /// Key information
    pub key_info: KeyInfo,

    /// Transfer policy ID
    #[serde(rename = "transfer_policy_id")]
    pub transfer_policy_id: Uuid,

    /// Transfer link
    #[serde(rename = "transfer_link")]
    pub transfer_link: String,

    /// Creation timestamp
    #[serde(rename = "created_at")]
    pub created_at: time::OffsetDateTime,
}

/// Key information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyInfo {
    /// Encryption algorithm (AES, RSA, EC)
    pub algorithm: String,

    /// Key length in bits
    #[serde(rename = "key_length")]
    pub key_length: Option<i32>,

    /// Curve type (for EC keys)
    #[serde(rename = "curve_type")]
    pub curve_type: Option<String>,

    /// Key data (base64 encoded private key)
    #[serde(rename = "key_data")]
    pub key_data: Option<String>,

    /// KMIP key ID (if key is stored in KMIP)
    #[serde(rename = "kmip_key_id")]
    pub kmip_key_id: Option<String>,
}

/// Internal key attributes (stored in repository).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyAttributes {
    /// Key ID
    pub id: Uuid,

    /// Key information
    pub key_info: KeyInfo,

    /// Transfer policy ID
    #[serde(rename = "transfer_policy_id")]
    pub transfer_policy_id: Uuid,

    /// Creation timestamp
    #[serde(rename = "created_at")]
    pub created_at: time::OffsetDateTime,
}

/// Key filter criteria for searching.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct KeyFilterCriteria {
    /// Encryption algorithm
    pub algorithm: Option<String>,

    /// Key length
    #[serde(rename = "keyLength")]
    pub key_length: Option<i32>,

    /// Curve type
    #[serde(rename = "curveType")]
    pub curve_type: Option<String>,

    /// Transfer policy ID
    #[serde(rename = "transferPolicyId")]
    pub transfer_policy_id: Option<Uuid>,
}

impl KeyInfo {
    /// Validate the key information.
    pub fn validate(&self) -> Result<(), String> {
        match self.algorithm.to_uppercase().as_str() {
            constant::CRYPTO_ALG_AES => {
                if self.key_length.is_none() {
                    return Err("key_length is required for AES keys".to_string());
                }
                let length = self.key_length.unwrap();
                if ![128, 192, 256].contains(&length) {
                    return Err(format!(
                        "Invalid AES key length: {}. Must be 128, 192, or 256",
                        length
                    ));
                }
            }
            constant::CRYPTO_ALG_RSA => {
                if self.key_length.is_none() {
                    return Err("key_length is required for RSA keys".to_string());
                }
                let length = self.key_length.unwrap();
                if ![2048, 3072, 4096, 7680].contains(&length) {
                    return Err(format!(
                        "Invalid RSA key length: {}. Must be 2048, 3072, 4096, or 7680",
                        length
                    ));
                }
            }
            constant::CRYPTO_ALG_EC => {
                if self.curve_type.is_none() {
                    return Err("curve_type is required for EC keys".to_string());
                }
                let curve = self.curve_type.as_ref().unwrap().to_lowercase();
                if !["secp256r1", "secp384r1", "secp521r1", "prime256v1"].contains(&curve.as_str())
                {
                    return Err(format!("Invalid EC curve: {}. Must be secp256r1, secp384r1, secp521r1, or prime256v1", curve));
                }
            }
            _ => {
                return Err(format!(
                    "Invalid algorithm: {}. Must be AES, RSA, or EC",
                    self.algorithm
                ));
            }
        }

        Ok(())
    }

    /// Check if this is a key creation request (no pre-existing key data).
    pub fn is_create(&self) -> bool {
        self.key_data.is_none() && self.kmip_key_id.is_none()
    }

    /// Check if this is a key registration request (pre-existing key data).
    pub fn is_register(&self) -> bool {
        !self.is_create()
    }
}
