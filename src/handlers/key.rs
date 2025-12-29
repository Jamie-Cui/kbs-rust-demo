
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
