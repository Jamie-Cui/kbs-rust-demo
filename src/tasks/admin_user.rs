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
//! Admin user creation task.
//!
//! This task creates the default admin user if it doesn't already exist.

use crate::constant::permissions;
use crate::error::{KbsError, KbsResult};
use crate::models::{User, UserFilterCriteria, UserInfo};
use crate::repositories::UserStore;
use bcrypt::{hash, DEFAULT_COST};
use std::sync::Arc;
use time::OffsetDateTime;
use uuid::Uuid;

/// Task for creating the admin user.
///
/// This task will create an admin user with all permissions
/// if one with the specified username doesn't already exist.
pub struct CreateAdminUser<S: UserStore> {
    /// Admin username
    pub admin_username: String,
    /// Admin password
    pub admin_password: String,
    /// User store for creating the user
    pub user_store: Arc<S>,
}

impl<S: UserStore> CreateAdminUser<S> {
    /// Create a new admin user creation task.
    ///
    /// # Arguments
    ///
    /// * `admin_username` - Username for the admin account
    /// * `admin_password` - Password for the admin account
    /// * `user_store` - User store implementation
    pub fn new(admin_username: &str, admin_password: &str, user_store: Arc<S>) -> Self {
        CreateAdminUser {
            admin_username: admin_username.to_string(),
            admin_password: admin_password.to_string(),
            user_store,
        }
    }

    /// Check if admin user already exists.
    pub async fn exists(&self) -> KbsResult<bool> {
        let filter = UserFilterCriteria {
            username: Some(self.admin_username.clone()),
            ..Default::default()
        };

        match self.user_store.search(&filter).await {
            Ok(users) => Ok(!users.is_empty()),
            Err(_) => Ok(false),
        }
    }

    /// Create the admin user if they don't already exist.
    ///
    /// Returns `Ok(true)` if the user was created,
    /// `Ok(false)` if they already existed, or `Err` on failure.
    pub async fn create_if_missing(&self) -> KbsResult<bool> {
        if self.exists().await? {
            return Ok(false);
        }

        self.create().await?;
        Ok(true)
    }

    /// Create the admin user (will fail if username already exists).
    pub async fn create(&self) -> KbsResult<()> {
        if self.admin_username.is_empty() || self.admin_password.is_empty() {
            return Err(KbsError::Validation(
                "Admin username or password cannot be empty".into(),
            ));
        }

        // Generate password hash
        let password_hash = hash(&self.admin_password, DEFAULT_COST).map_err(|e| {
            KbsError::Crypto(format!("Failed to hash password: {}", e))
        })?;

        // Create user with all permissions
        let now = OffsetDateTime::now_utc();
        let user_info = UserInfo {
            id: Uuid::new_v4(),
            created_at: now,
            updated_at: now,
            username: self.admin_username.clone(),
            password_hash,
            password_cost: DEFAULT_COST,
            permissions: permissions::ALL_PERMISSIONS.iter().map(|s| s.to_string()).collect(),
        };

        self.user_store.create(&user_info).await?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::repositories::MemoryUserStore;

    #[tokio::test]
    async fn test_create_admin_user() {
        let user_store = Arc::new(MemoryUserStore::new());
        let task = CreateAdminUser::new("admin", "password123", user_store);

        // Should create successfully
        let created = task.create_if_missing().await.unwrap();
        assert!(created);

        // Second call should skip
        let created = task.create_if_missing().await.unwrap();
        assert!(!created);

        // Verify user exists
        let exists = task.exists().await.unwrap();
        assert!(exists);

        // Verify permissions
        let filter = UserFilterCriteria {
            username: Some("admin".to_string()),
            ..Default::default()
        };
        let users = task.user_store.search(filter).await.unwrap();
        assert_eq!(users.len(), 1);
        assert_eq!(users[0].username, "admin");
        assert!(users[0].permissions.contains(&"keys:create".to_string()));
        assert!(users[0].permissions.contains(&"users:create".to_string()));
    }

    #[tokio::test]
    async fn test_create_admin_user_empty_credentials() {
        let user_store = Arc::new(MemoryUserStore::new());

        // Empty username
        let task = CreateAdminUser::new("", "password123", user_store.clone());
        let result = task.create().await;
        assert!(result.is_err());

        // Empty password
        let task = CreateAdminUser::new("admin", "", user_store);
        let result = task.create().await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_create_admin_user_exists() {
        let user_store = Arc::new(MemoryUserStore::new());
        let task = CreateAdminUser::new("admin", "password123", user_store);

        // Create user
        task.create().await.unwrap();

        // Check exists
        let exists = task.exists().await.unwrap();
        assert!(exists);
    }
}
