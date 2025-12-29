
use async_trait::async_trait;
use std::sync::Arc;

use crate::error::{KbsError, KbsResult};
use crate::models::{KeyAttributes, KeyFilterCriteria, KeyRequest, KeyResponse, KeyUpdateRequest};
use crate::repositories::{KeyStore, KeyTransferPolicyStore};
use crate::traits::KeyManager;

/// Key service trait.
#[async_trait]
pub trait KeyService: Send + Sync {
    /// Create a new key.
    async fn create_key(&self, request: KeyRequest) -> KbsResult<KeyResponse>;

    /// Register an existing key.
    async fn register_key(&self, request: KeyRequest) -> KbsResult<KeyResponse>;

    /// Update a key's transfer policy.
    async fn update_key(&self, id: uuid::Uuid, request: KeyUpdateRequest) -> KbsResult<KeyResponse>;

    /// Search for keys.
    async fn search_keys(&self, criteria: KeyFilterCriteria) -> KbsResult<Vec<KeyResponse>>;

    /// Delete a key.
    async fn delete_key(&self, id: uuid::Uuid) -> KbsResult<()>;

    /// Get a key by ID.
    async fn get_key(&self, id: uuid::Uuid) -> KbsResult<KeyResponse>;
}

/// Implementation of the key service.
pub struct KeyServiceImpl<K, P, M>
where
    K: KeyStore,
    P: KeyTransferPolicyStore,
    M: KeyManager,
{
    key_store: Arc<K>,
    policy_store: Arc<P>,
    key_manager: Arc<M>,
}

impl<K, P, M> KeyServiceImpl<K, P, M>
where
    K: KeyStore,
    P: KeyTransferPolicyStore,
    M: KeyManager,
{
    /// Create a new key service.
    pub fn new(key_store: Arc<K>, policy_store: Arc<P>, key_manager: Arc<M>) -> Self {
        Self {
            key_store,
            policy_store,
            key_manager,
        }
    }

    /// Get the transfer link for a key.
    fn transfer_link(&self, id: uuid::Uuid) -> String {
        format!("/kbs/v1/keys/{}/transfer", id)
    }
}

#[async_trait]
impl<K, P, M> KeyService for KeyServiceImpl<K, P, M>
where
    K: KeyStore,
    P: KeyTransferPolicyStore,
    M: KeyManager,
{
    async fn create_key(&self, request: KeyRequest) -> KbsResult<KeyResponse> {
        // Validate key info
        request.key_information.validate()?;

        // Verify the transfer policy exists
        self.policy_store
            .retrieve(request.transfer_policy_id)
            .await?;

        // Create the key in the KMS
        let key_info = self
            .key_manager
            .create_key(&request)
            .await
            .map_err(|e| KbsError::KeyManager(e.to_string()))?;

        // Store key metadata
        let key = KeyAttributes {
            id: uuid::Uuid::new_v4(),
            key_info: key_info.clone(),
            transfer_policy_id: request.transfer_policy_id,
            created_at: time::OffsetDateTime::now_utc(),
        };

        let stored = self.key_store.create(&key).await?;

        Ok(KeyResponse {
            id: stored.id,
            key_info: stored.key_info,
            transfer_policy_id: stored.transfer_policy_id,
            transfer_link: self.transfer_link(stored.id),
            created_at: stored.created_at,
        })
    }

    async fn register_key(&self, request: KeyRequest) -> KbsResult<KeyResponse> {
        // Validate key info
        request.key_information.validate()?;

        // Verify the transfer policy exists
        self.policy_store
            .retrieve(request.transfer_policy_id)
            .await?;

        // Register the key in the KMS
        let key_info = self
            .key_manager
            .register_key(&request)
            .await
            .map_err(|e| KbsError::KeyManager(e.to_string()))?;

        // Store key metadata
        let key = KeyAttributes {
            id: uuid::Uuid::new_v4(),
            key_info: key_info.clone(),
            transfer_policy_id: request.transfer_policy_id,
            created_at: time::OffsetDateTime::now_utc(),
        };

        let stored = self.key_store.create(&key).await?;

        Ok(KeyResponse {
            id: stored.id,
            key_info: stored.key_info,
            transfer_policy_id: stored.transfer_policy_id,
            transfer_link: self.transfer_link(stored.id),
            created_at: stored.created_at,
        })
    }

    async fn update_key(
        &self,
        id: uuid::Uuid,
        request: KeyUpdateRequest,
    ) -> KbsResult<KeyResponse> {
        // Get the existing key
        let mut key = self.key_store.retrieve(id).await?;

        // Verify the transfer policy exists
        self.policy_store.retrieve(request.transfer_policy_id).await?;

        // Update the transfer policy
        key.transfer_policy_id = request.transfer_policy_id;

        let updated = self.key_store.update(&key).await?;

        Ok(KeyResponse {
            id: updated.id,
            key_info: updated.key_info,
            transfer_policy_id: updated.transfer_policy_id,
            transfer_link: self.transfer_link(updated.id),
            created_at: updated.created_at,
        })
    }

    async fn search_keys(&self, criteria: KeyFilterCriteria) -> KbsResult<Vec<KeyResponse>> {
        let keys = self.key_store.search(&criteria).await?;

        Ok(keys
            .into_iter()
            .map(|k| KeyResponse {
                id: k.id,
                key_info: k.key_info,
                transfer_policy_id: k.transfer_policy_id,
                transfer_link: self.transfer_link(k.id),
                created_at: k.created_at,
            })
            .collect())
    }

    async fn delete_key(&self, id: uuid::Uuid) -> KbsResult<()> {
        // Get the key first
        let key = self.key_store.retrieve(id).await?;

        // Delete from KMS
        self.key_manager
            .delete_key(&key.id.to_string())
            .await
            .map_err(|e| KbsError::KeyManager(e.to_string()))?;

        // Delete metadata
        self.key_store.delete(id).await
    }

    async fn get_key(&self, id: uuid::Uuid) -> KbsResult<KeyResponse> {
        let key = self.key_store.retrieve(id).await?;

        Ok(KeyResponse {
            id: key.id,
            key_info: key.key_info,
            transfer_policy_id: key.transfer_policy_id,
            transfer_link: self.transfer_link(key.id),
            created_at: key.created_at,
        })
    }
}
