/*
 *   Copyright (c) 2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

//! Key Manager trait.
//!
//! This trait defines the interface for key management operations.
//! You need to implement this for your KMS backend (Vault, KMIP, etc.).
//!
//! # Example Implementation
//!
//! ```rust
//! use gta_kbs::traits::KeyManager;
//! use gta_kbs::models::{KeyRequest, KeyInfo};
//! use gta_kbs::error::{KbsResult, KbsError};
//!
//! struct MyKeyManager;
//!
//! #[async_trait::async_trait]
//! impl KeyManager for MyKeyManager {
//!     async fn create_key(&self, request: &KeyRequest) -> KbsResult<KeyInfo> {
//!         // Implement key creation in your KMS
//!         // Return the created key information
//!         todo!("Implement key creation")
//!     }
//!
//!     async fn delete_key(&self, key_id: &str) -> KbsResult<()> {
//!         // Implement key deletion in your KMS
//!         todo!("Implement key deletion")
//!     }
//!
//!     async fn register_key(&self, request: &KeyRequest) -> KbsResult<KeyInfo> {
//!         // Implement key registration (for pre-existing keys)
//!         todo!("Implement key registration")
//!     }
//!
//!     async fn transfer_key(&self, key_id: &str) -> KbsResult<Vec<u8>> {
//!         // Retrieve and return the secret key material
//!         // This should return the raw key bytes
//!         todo!("Implement key transfer")
//!     }
//! }
//! ```

use async_trait::async_trait;
use crate::error::KbsResult;
use crate::models::{KeyInfo, KeyRequest};

/// Key Manager trait for KMS operations.
///
/// This trait abstracts the key management operations needed by the KBS service.
/// Implement this trait for your specific KMS backend (Vault, KMIP, etc.).
#[async_trait]
pub trait KeyManager: Send + Sync {
    /// Create a new key in the KMS.
    ///
    /// # Arguments
    /// * `request` - Key creation request with algorithm, key length, etc.
    ///
    /// # Returns
    /// Information about the created key, including a unique identifier.
    async fn create_key(&self, request: &KeyRequest) -> KbsResult<KeyInfo>;

    /// Delete a key from the KMS.
    ///
    /// # Arguments
    /// * `key_id` - Unique identifier of the key to delete
    async fn delete_key(&self, key_id: &str) -> KbsResult<()>;

    /// Register a pre-existing key in the KMS.
    ///
    /// This is used when a key was created elsewhere and needs to be registered
    /// with the KBS service.
    ///
    /// # Arguments
    /// *`request` - Key registration request with the key material
    ///
    /// # Returns
    /// Information about the registered key.
    async fn register_key(&self, request: &KeyRequest) -> KbsResult<KeyInfo>;

    /// Transfer (retrieve) a key from the KMS.
    ///
    /// This retrieves the secret key material for wrapping and transfer.
    ///
    /// # Arguments
    /// * `key_id` - Unique identifier of the key to retrieve
    ///
    /// # Returns
    /// The raw key material as bytes. For asymmetric keys, this returns
    /// the DER-encoded private key. For symmetric keys, returns the raw key bytes.
    async fn transfer_key(&self, key_id: &str) -> KbsResult<Vec<u8>>;
}
