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
    extract::{Path, Query, State},
    response::Json,
};
use uuid::Uuid;
use crate::error::KbsError;
use crate::handlers::AppState;
use crate::models::{KeyFilterCriteria, KeyRequest, KeyUpdateRequest, KeyResponse};

/// GET /keys - Search for keys.
pub async fn search_keys(
    State(state): State<AppState>,
    Query(mut criteria): Query<KeyFilterCriteria>,
) -> Result<Json<Vec<KeyResponse>>, KbsError> {
    // Normalize algorithm to uppercase if present
    if let Some(ref mut alg) = criteria.algorithm {
        *alg = alg.to_uppercase();
    }

    let keys = state.key_service.search_keys(criteria).await?;
    Ok(Json(keys))
}

/// POST /keys - Create a new key.
pub async fn create_key(
    State(state): State<AppState>,
    Json(request): Json<KeyRequest>,
) -> Result<Json<KeyResponse>, KbsError> {
    let key = state.key_service.create_key(request).await?;
    Ok(Json(key))
}

/// GET /keys/:id - Get a key by ID.
pub async fn get_key(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<KeyResponse>, KbsError> {
    let key = state.key_service.get_key(id).await?;
    Ok(Json(key))
}

/// DELETE /keys/:id - Delete a key.
pub async fn delete_key(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<(), KbsError> {
    state.key_service.delete_key(id).await?;
    Ok(())
}

/// PUT /keys/:id - Update a key.
pub async fn update_key(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Json(request): Json<KeyUpdateRequest>,
) -> Result<Json<KeyResponse>, KbsError> {
    let key = state.key_service.update_key(id, request).await?;
    Ok(Json(key))
}
