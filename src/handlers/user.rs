
use axum::{
    extract::{Path, Query, State},
    response::Json,
};
use uuid::Uuid;
use crate::error::KbsError;
use crate::handlers::AppState;
use crate::models::{UpdateUserRequest, User, UserFilterCriteria, UserResponse};

/// GET /users - Search for users.
pub async fn search_users(
    State(state): State<AppState>,
    Query(criteria): Query<UserFilterCriteria>,
) -> Result<Json<Vec<UserResponse>>, KbsError> {
    let users = state.user_service.search_users(criteria).await?;
    Ok(Json(users))
}

/// POST /users - Create a new user.
pub async fn create_user(
    State(state): State<AppState>,
    Json(request): Json<User>,
) -> Result<Json<UserResponse>, KbsError> {
    let user = state.user_service.create_user(request).await?;
    Ok(Json(user))
}

/// GET /users/:id - Get a user by ID.
pub async fn get_user(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<UserResponse>, KbsError> {
    let user = state.user_service.get_user(id).await?;
    Ok(Json(user))
}

/// DELETE /users/:id - Delete a user.
pub async fn delete_user(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<(), KbsError> {
    state.user_service.delete_user(id).await?;
    Ok(())
}

/// PUT /users/:id - Update a user.
pub async fn update_user(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Json(request): Json<UpdateUserRequest>,
) -> Result<Json<UserResponse>, KbsError> {
    let user = state.user_service.update_user(id, request).await?;
    Ok(Json(user))
}
