
use axum::{
    extract::{State, Json},
    response::{IntoResponse, Response},
    http::StatusCode,
};
use crate::error::KbsError;
use crate::handlers::AppState;
use crate::models::AuthTokenRequest;

/// POST /token - Create an authentication token.
pub async fn create_auth_token(
    State(state): State<AppState>,
    Json(request): Json<AuthTokenRequest>,
) -> Result<Response, KbsError> {
    let token = state.auth_service.authenticate(request).await?;

    // Return the token as plain text
    Ok((StatusCode::OK, token).into_response())
}
