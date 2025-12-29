
use async_trait::async_trait;
use std::path::PathBuf;
use tokio::fs;
use tokio::io::AsyncWriteExt;
use uuid::Uuid;

use crate::error::{KbsError, KbsResult, RepositoryError};
use crate::models::*;
use crate::repositories::{KeyStore, KeyTransferPolicyStore, UserStore};

/// Base directory for storage.
const DATA_DIR: &str = "./data";

/// File-based key store.
#[derive(Clone)]
pub struct FileKeyStore {
    base_dir: PathBuf,
}

impl FileKeyStore {
    /// Create a new file key store.
    pub fn new(base_dir: Option<PathBuf>) -> Self {
        let base_dir = base_dir.unwrap_or_else(|| PathBuf::from(DATA_DIR));
        Self {
            base_dir: base_dir.join("keys"),
        }
    }

    /// Get the file path for a key.
    fn key_path(&self, id: Uuid) -> PathBuf {
        self.base_dir.join(format!("{}.json", id))
    }
}

#[async_trait]
impl KeyStore for FileKeyStore {
    async fn create(&self, key: &KeyAttributes) -> KbsResult<KeyAttributes> {
        // Create directory if it doesn't exist
        fs::create_dir_all(&self.base_dir).await
            .map_err(|e| RepositoryError::Io(e))?;

        let path = self.key_path(key.id);
        let data = serde_json::to_string_pretty(key)
            .map_err(|e| RepositoryError::Serialization(e.to_string()))?;

        let mut file = fs::File::create(&path).await
            .map_err(|e| RepositoryError::Io(e))?;
        file.write_all(data.as_bytes()).await
            .map_err(|e| RepositoryError::Io(e))?;

        Ok(key.clone())
    }

    async fn update(&self, key: &KeyAttributes) -> KbsResult<KeyAttributes> {
        self.create(key).await
    }

    async fn retrieve(&self, id: Uuid) -> KbsResult<KeyAttributes> {
        let path = self.key_path(id);
        let data = fs::read_to_string(&path).await
            .map_err(RepositoryError::Io)?;

        serde_json::from_str(&data)
            .map_err(|e| RepositoryError::Serialization(e.to_string()))
            .map_err(KbsError::Repository)
    }

    async fn delete(&self, id: Uuid) -> KbsResult<()> {
        let path = self.key_path(id);
        fs::remove_file(&path).await
            .map_err(|e| RepositoryError::Io(e))?;
        Ok(())
    }

    async fn search(&self, _criteria: &KeyFilterCriteria) -> KbsResult<Vec<KeyAttributes>> {
        // Read all keys from directory
        let mut keys = Vec::new();

        let mut entries = fs::read_dir(&self.base_dir).await
            .map_err(|e| RepositoryError::Io(e))?;

        while let Some(entry) = entries.next_entry().await
            .map_err(|e| RepositoryError::Io(e))? {
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) != Some("json") {
                continue;
            }

            let data = fs::read_to_string(&path).await
                .map_err(|e| RepositoryError::Io(e))?;

            let key: KeyAttributes = serde_json::from_str(&data)
                .map_err(|e| RepositoryError::Serialization(e.to_string()))?;

            keys.push(key);
        }

        Ok(keys)
    }
}

/// File-based key transfer policy store.
#[derive(Clone)]
pub struct FileKeyTransferPolicyStore {
    base_dir: PathBuf,
}

impl FileKeyTransferPolicyStore {
    /// Create a new file policy store.
    pub fn new(base_dir: Option<PathBuf>) -> Self {
        let base_dir = base_dir.unwrap_or_else(|| PathBuf::from(DATA_DIR));
        Self {
            base_dir: base_dir.join("policies"),
        }
    }

    /// Get the file path for a policy.
    fn policy_path(&self, id: Uuid) -> PathBuf {
        self.base_dir.join(format!("{}.json", id))
    }
}

#[async_trait]
impl KeyTransferPolicyStore for FileKeyTransferPolicyStore {
    async fn create(&self, policy: &KeyTransferPolicy) -> KbsResult<KeyTransferPolicy> {
        // Create directory if it doesn't exist
        fs::create_dir_all(&self.base_dir).await
            .map_err(|e| RepositoryError::Io(e))?;

        let path = self.policy_path(policy.id);
        let data = serde_json::to_string_pretty(policy)
            .map_err(|e| RepositoryError::Serialization(e.to_string()))?;

        let mut file = fs::File::create(&path).await
            .map_err(|e| RepositoryError::Io(e))?;
        file.write_all(data.as_bytes()).await
            .map_err(|e| RepositoryError::Io(e))?;

        Ok(policy.clone())
    }

    async fn retrieve(&self, id: Uuid) -> KbsResult<KeyTransferPolicy> {
        let path = self.policy_path(id);
        let data = fs::read_to_string(&path).await
            .map_err(RepositoryError::Io)?;

        serde_json::from_str(&data)
            .map_err(|e| RepositoryError::Serialization(e.to_string()))
            .map_err(KbsError::Repository)
    }

    async fn delete(&self, id: Uuid) -> KbsResult<()> {
        let path = self.policy_path(id);
        fs::remove_file(&path).await
            .map_err(|e| RepositoryError::Io(e))?;
        Ok(())
    }

    async fn search(
        &self,
        _criteria: &KeyTransferPolicyFilterCriteria,
    ) -> KbsResult<Vec<KeyTransferPolicy>> {
        // Read all policies from directory
        let mut policies = Vec::new();

        let mut entries = fs::read_dir(&self.base_dir).await
            .map_err(|e| RepositoryError::Io(e))?;

        while let Some(entry) = entries.next_entry().await
            .map_err(|e| RepositoryError::Io(e))? {
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) != Some("json") {
                continue;
            }

            let data = fs::read_to_string(&path).await
                .map_err(|e| RepositoryError::Io(e))?;

            let policy: KeyTransferPolicy = serde_json::from_str(&data)
                .map_err(|e| RepositoryError::Serialization(e.to_string()))?;

            policies.push(policy);
        }

        Ok(policies)
    }
}

/// File-based user store.
#[derive(Clone)]
pub struct FileUserStore {
    base_dir: PathBuf,
}

impl FileUserStore {
    /// Create a new file user store.
    pub fn new(base_dir: Option<PathBuf>) -> Self {
        let base_dir = base_dir.unwrap_or_else(|| PathBuf::from(DATA_DIR));
        Self {
            base_dir: base_dir.join("users"),
        }
    }

    /// Get the file path for a user.
    fn user_path(&self, id: Uuid) -> PathBuf {
        self.base_dir.join(format!("{}.json", id))
    }
}

#[async_trait]
impl UserStore for FileUserStore {
    async fn create(&self, user: &UserInfo) -> KbsResult<UserInfo> {
        // Create directory if it doesn't exist
        fs::create_dir_all(&self.base_dir).await
            .map_err(|e| RepositoryError::Io(e))?;

        let path = self.user_path(user.id);
        let data = serde_json::to_string_pretty(user)
            .map_err(|e| RepositoryError::Serialization(e.to_string()))?;

        let mut file = fs::File::create(&path).await
            .map_err(|e| RepositoryError::Io(e))?;
        file.write_all(data.as_bytes()).await
            .map_err(|e| RepositoryError::Io(e))?;

        Ok(user.clone())
    }

    async fn retrieve(&self, id: Uuid) -> KbsResult<UserInfo> {
        let path = self.user_path(id);
        let data = fs::read_to_string(&path).await
            .map_err(RepositoryError::Io)?;

        serde_json::from_str(&data)
            .map_err(|e| RepositoryError::Serialization(e.to_string()))
            .map_err(KbsError::Repository)
    }

    async fn delete(&self, id: Uuid) -> KbsResult<()> {
        let path = self.user_path(id);
        fs::remove_file(&path).await
            .map_err(|e| RepositoryError::Io(e))?;
        Ok(())
    }

    async fn search(&self, _criteria: &UserFilterCriteria) -> KbsResult<Vec<UserInfo>> {
        // Read all users from directory
        let mut users = Vec::new();

        let mut entries = fs::read_dir(&self.base_dir).await
            .map_err(|e| RepositoryError::Io(e))?;

        while let Some(entry) = entries.next_entry().await
            .map_err(|e| RepositoryError::Io(e))? {
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) != Some("json") {
                continue;
            }

            let data = fs::read_to_string(&path).await
                .map_err(|e| RepositoryError::Io(e))?;

            let user: UserInfo = serde_json::from_str(&data)
                .map_err(|e| RepositoryError::Serialization(e.to_string()))?;

            users.push(user);
        }

        Ok(users)
    }

    async fn update(&self, user: &UserInfo) -> KbsResult<UserInfo> {
        self.create(user).await
    }
}
