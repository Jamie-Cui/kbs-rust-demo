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
