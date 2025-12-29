/*
 *   Copyright (c) 2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

//! User service.

use async_trait::async_trait;
use std::sync::Arc;

use crate::error::{KbsError, KbsResult, ServiceError};
use crate::models::{UpdateUserRequest, User, UserInfo, UserFilterCriteria, UserResponse};
use crate::repositories::UserStore;

/// User service trait.
#[async_trait]
pub trait UserService: Send + Sync {
    /// Create a new user.
    async fn create_user(&self, request: User) -> KbsResult<UserResponse>;

    /// Update an existing user.
    async fn update_user(&self, id: uuid::Uuid, request: UpdateUserRequest) -> KbsResult<UserResponse>;

    /// Search for users.
    async fn search_users(&self, criteria: UserFilterCriteria) -> KbsResult<Vec<UserResponse>>;

    /// Delete a user.
    async fn delete_user(&self, id: uuid::Uuid) -> KbsResult<()>;

    /// Get a user by ID.
    async fn get_user(&self, id: uuid::Uuid) -> KbsResult<UserResponse>;
}

/// Implementation of the user service.
pub struct UserServiceImpl<U> {
    user_store: Arc<U>,
}

impl<U> UserServiceImpl<U>
where
    U: UserStore,
{
    /// Create a new user service.
    pub fn new(user_store: Arc<U>) -> Self {
        Self { user_store }
    }
}

#[async_trait]
impl<U> UserService for UserServiceImpl<U>
where
    U: UserStore,
{
    async fn create_user(&self, request: User) -> KbsResult<UserResponse> {
        // Validate the request
        request.validate()?;

        // Check if user already exists
        let existing = self
            .user_store
            .search(&UserFilterCriteria {
                username: Some(request.username.clone()),
            })
            .await?;

        if !existing.is_empty() {
            return Err(KbsError::Service(ServiceError::UserExists(
                request.username,
            )));
        }

        // Hash the password
        let password_hash = bcrypt::hash(&request.password, bcrypt::DEFAULT_COST)
            .map_err(|e| KbsError::Internal(format!("Password hashing failed: {}", e)))?;

        // Create the user
        let user = UserInfo {
            id: uuid::Uuid::new_v4(),
            created_at: time::OffsetDateTime::now_utc(),
            updated_at: time::OffsetDateTime::now_utc(),
            username: request.username.clone(),
            password_hash,
            password_cost: bcrypt::DEFAULT_COST,
            permissions: request.permissions.clone(),
        };

        let created = self.user_store.create(&user).await?;

        Ok(created.to_response())
    }

    async fn update_user(
        &self,
        id: uuid::Uuid,
        request: UpdateUserRequest,
    ) -> KbsResult<UserResponse> {
        // Get the existing user
        let mut user = self.user_store.retrieve(id).await?;

        // Update username if provided
        if let Some(username) = request.username {
            // Check if username is already taken by another user
            let existing = self
                .user_store
                .search(&UserFilterCriteria {
                    username: Some(username.clone()),
                })
                .await?;

            for existing_user in existing {
                if existing_user.id != id {
                    return Err(KbsError::Validation(
                        "Username already taken".into(),
                    ));
                }
            }

            user.username = username;
        }

        // Update password if provided
        if let Some(password) = request.password {
            if password.len() < 8 || password.len() > 64 {
                return Err(KbsError::Validation(
                    "Password must be between 8 and 64 characters".into(),
                ));
            }

            user.password_hash = bcrypt::hash(&password, bcrypt::DEFAULT_COST)
                .map_err(|e| KbsError::Internal(format!("Password hashing failed: {}", e)))?;
        }

        // Update permissions if provided
        if let Some(permissions) = request.permissions {
            if permissions.is_empty() {
                return Err(KbsError::Validation(
                    "At least one permission is required".into(),
                ));
            }
            user.permissions = permissions;
        }

        user.updated_at = time::OffsetDateTime::now_utc();

        let updated = self.user_store.update(&user).await?;

        Ok(updated.to_response())
    }

    async fn search_users(
        &self,
        criteria: UserFilterCriteria,
    ) -> KbsResult<Vec<UserResponse>> {
        let users = self.user_store.search(&criteria).await?;

        Ok(users.into_iter().map(|u| u.to_response()).collect())
    }

    async fn delete_user(&self, id: uuid::Uuid) -> KbsResult<()> {
        self.user_store.delete(id).await
    }

    async fn get_user(&self, id: uuid::Uuid) -> KbsResult<UserResponse> {
        let user = self.user_store.retrieve(id).await?;
        Ok(user.to_response())
    }
}
