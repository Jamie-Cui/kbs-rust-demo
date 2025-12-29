/*
 *   Copyright (c) 2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

//! Key transfer policy handlers.

use axum::{
    extract::{Path, State},
    response::Json,
};
use uuid::Uuid;
use crate::error::KbsError;
use crate::handlers::AppState;
use crate::models::{KeyTransferPolicy, KeyTransferPolicyFilterCriteria};

/// GET /key-transfer-policies - Search for policies.
pub async fn search_policies(
    State(state): State<AppState>,
) -> Result<Json<Vec<KeyTransferPolicy>>, KbsError> {
    let policies = state
        .key_transfer_policy_service
        .search_policies(KeyTransferPolicyFilterCriteria)
        .await?;
    Ok(Json(policies))
}

/// POST /key-transfer-policies - Create a new policy.
pub async fn create_policy(
    State(state): State<AppState>,
    Json(mut policy): Json<KeyTransferPolicy>,
) -> Result<Json<KeyTransferPolicy>, KbsError> {
    // Ensure the policy has an ID
    if policy.id == Uuid::nil() {
        policy.id = Uuid::new_v4();
    }

    let created = state
        .key_transfer_policy_service
        .create_policy(policy)
        .await?;
    Ok(Json(created))
}

/// GET /key-transfer-policies/:id - Get a policy by ID.
pub async fn get_policy(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<KeyTransferPolicy>, KbsError> {
    let policy = state.key_transfer_policy_service.get_policy(id).await?;
    Ok(Json(policy))
}

/// DELETE /key-transfer-policies/:id - Delete a policy.
pub async fn delete_policy(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<(), KbsError> {
    state.key_transfer_policy_service.delete_policy(id).await?;
    Ok(())
}
