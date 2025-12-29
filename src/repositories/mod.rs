/*
 *   Copyright (c) 2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

//! Repository layer for data persistence.

pub mod directory;

use async_trait::async_trait;
use crate::error::KbsResult;
use crate::models::*;
use uuid::Uuid;

/// Key store trait.
#[async_trait]
pub trait KeyStore: Send + Sync {
    /// Create a new key record.
    async fn create(&self, key: &KeyAttributes) -> KbsResult<KeyAttributes>;

    /// Update an existing key record.
    async fn update(&self, key: &KeyAttributes) -> KbsResult<KeyAttributes>;

    /// Retrieve a key by ID.
    async fn retrieve(&self, id: Uuid) -> KbsResult<KeyAttributes>;

    /// Delete a key by ID.
    async fn delete(&self, id: Uuid) -> KbsResult<()>;

    /// Search for keys by criteria.
    async fn search(&self, criteria: &KeyFilterCriteria) -> KbsResult<Vec<KeyAttributes>>;
}

/// Key transfer policy store trait.
#[async_trait]
pub trait KeyTransferPolicyStore: Send + Sync {
    /// Create a new policy.
    async fn create(&self, policy: &KeyTransferPolicy) -> KbsResult<KeyTransferPolicy>;

    /// Retrieve a policy by ID.
    async fn retrieve(&self, id: Uuid) -> KbsResult<KeyTransferPolicy>;

    /// Delete a policy by ID.
    async fn delete(&self, id: Uuid) -> KbsResult<()>;

    /// Search for policies by criteria.
    async fn search(
        &self,
        criteria: &KeyTransferPolicyFilterCriteria,
    ) -> KbsResult<Vec<KeyTransferPolicy>>;
}

/// User store trait.
#[async_trait]
pub trait UserStore: Send + Sync {
    /// Create a new user.
    async fn create(&self, user: &UserInfo) -> KbsResult<UserInfo>;

    /// Retrieve a user by ID.
    async fn retrieve(&self, id: Uuid) -> KbsResult<UserInfo>;

    /// Delete a user by ID.
    async fn delete(&self, id: Uuid) -> KbsResult<()>;

    /// Search for users by criteria.
    async fn search(&self, criteria: &UserFilterCriteria) -> KbsResult<Vec<UserInfo>>;

    /// Update an existing user.
    async fn update(&self, user: &UserInfo) -> KbsResult<UserInfo>;
}

/// Combined repository.
#[derive(Clone)]
pub struct Repository<K, P, U>
where
    K: KeyStore,
    P: KeyTransferPolicyStore,
    U: UserStore,
{
    pub key_store: K,
    pub key_transfer_policy_store: P,
    pub user_store: U,
}

impl<K, P, U> Repository<K, P, U>
where
    K: KeyStore,
    P: KeyTransferPolicyStore,
    U: UserStore,
{
    pub fn new(key_store: K, key_transfer_policy_store: P, user_store: U) -> Self {
        Self {
            key_store,
            key_transfer_policy_store,
            user_store,
        }
    }
}
