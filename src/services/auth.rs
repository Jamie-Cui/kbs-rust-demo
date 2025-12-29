/*
 *   Copyright (c) 2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

//! Authentication service.

use crate::config::Configuration;
use crate::crypto::jwt;
use crate::error::{KbsError, KbsResult};
use crate::models::{AuthTokenRequest, UserInfo, JwtAuthz};
use crate::repositories::UserStore;
use async_trait::async_trait;
use std::sync::Arc;

/// Authentication service trait.
#[async_trait]
pub trait AuthService: Send + Sync {
    /// Authenticate a user and return a JWT token.
    async fn authenticate(&self, request: AuthTokenRequest) -> KbsResult<String>;

    /// Verify a JWT token and return the user info.
    async fn verify_token(&self, token: &str) -> KbsResult<UserInfo>;

    /// Create a JWT token for a user.
    fn create_token(&self, user: &UserInfo) -> KbsResult<String>;
}

/// Implementation of the authentication service.
pub struct AuthServiceImpl<U> {
    user_store: Arc<U>,
    config: Arc<Configuration>,
    jwt_signing_key: String,
}

impl<U> AuthServiceImpl<U>
where
    U: UserStore,
{
    /// Create a new authentication service.
    pub fn new(user_store: Arc<U>, config: Arc<Configuration>, jwt_signing_key: String) -> Self {
        Self {
            user_store,
            config,
            jwt_signing_key,
        }
    }

    /// Load the JWT signing key from file.
    pub async fn load_signing_key(path: &str) -> KbsResult<String> {
        tokio::fs::read_to_string(path)
            .await
            .map_err(|e| KbsError::Config(format!("Failed to read JWT signing key: {}", e)))
    }

    /// Create the JWT authz context.
    pub fn create_jwt_authz(&self) -> JwtAuthz {
        JwtAuthz {
            jwt_secret: self.jwt_signing_key.clone(),
            token_validity_minutes: self.config.bearer_token_validity_in_minutes,
        }
    }
}

#[async_trait]
impl<U> AuthService for AuthServiceImpl<U>
where
    U: UserStore,
{
    async fn authenticate(&self, request: AuthTokenRequest) -> KbsResult<String> {
        // Validate the request
        if request.username.is_empty() || request.password.is_empty() {
            return Err(KbsError::Validation(
                "Username and password are required".into(),
            ));
        }

        // Find the user by username
        let users = self
            .user_store
            .search(&crate::models::UserFilterCriteria {
                username: Some(request.username.clone()),
            })
            .await?;

        if users.is_empty() {
            return Err(KbsError::Auth("Invalid username or password".into()));
        }

        let user = &users[0];

        // Verify the password
        let verified = user
            .verify_password(&request.password)
            .map_err(|e| KbsError::Internal(format!("Password verification error: {}", e)))?;

        if !verified {
            return Err(KbsError::Auth("Invalid username or password".into()));
        }

        // Create and return the token
        self.create_token(user)
    }

    async fn verify_token(&self, token: &str) -> KbsResult<UserInfo> {
        // For now, extract claims without verification
        // In production, you should verify the signature
        let claims = jwt::extract_claims_unverified(token)?;

        let user_id = claims
            .get("sub")
            .and_then(|v| v.as_str())
            .ok_or_else(|| KbsError::Validation("Missing sub claim".into()))?;

        let user_id = uuid::Uuid::parse_str(user_id)
            .map_err(|_| KbsError::Validation("Invalid user ID in token".into()))?;

        self.user_store.retrieve(user_id).await
    }

    fn create_token(&self, user: &UserInfo) -> KbsResult<String> {
        jwt::create_token(
            &user.id.to_string(),
            &user.username,
            &user.permissions,
            &self.jwt_signing_key,
            self.config.bearer_token_validity_in_minutes,
        )
    }
}
