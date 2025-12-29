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
    extract::{State, Json},
    response::{IntoResponse, Response},
    http::StatusCode,
};
use crate::defender::ClientKey;
use crate::error::KbsError;
use crate::handlers::AppState;
use crate::models::AuthTokenRequest;

/// POST /token - Create an authentication token.
pub async fn create_auth_token(
    State(state): State<AppState>,
    Json(request): Json<AuthTokenRequest>,
) -> Result<Response, KbsError> {
    // Check rate limiting using defender
    let client_key = ClientKey::username(&request.username);

    // Check if user is currently banned
    if state.defender.is_banned(&client_key).await {
        return Err(KbsError::Authorization(
            "Too many failed authentication attempts. Please try again later.".into(),
        ));
    }

    // Increment attempt counter
    let just_banned = state.defender.inc(client_key.clone()).await;

    if just_banned {
        return Err(KbsError::Authorization(
            "Too many failed authentication attempts. Account temporarily locked.".into(),
        ));
    }

    // Attempt authentication
    let token = state.auth_service.authenticate(request.clone()).await?;

    // On successful auth, remove from rate limiting
    state.defender.remove_client(&client_key).await;

    // Return the token as plain text
    Ok((StatusCode::OK, token).into_response())
}
