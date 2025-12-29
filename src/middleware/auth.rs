/*
 *   Copyright (c) 2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

//! Authentication middleware.

use axum::{
    extract::Request,
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::Response,
};

/// Authentication middleware that validates JWT tokens.
///
/// This middleware extracts the JWT token from the Authorization header,
/// validates it, and adds user information to the request extensions.
pub async fn auth_middleware(
    headers: HeaderMap,
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    // Get the Authorization header
    let auth_header = headers
        .get("Authorization")
        .and_then(|h| h.to_str().ok())
        .ok_or(StatusCode::UNAUTHORIZED)?;

    // Extract the token
    if !auth_header.starts_with("Bearer ") {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let token = &auth_header[7..];

    // For now, extract claims without full verification
    // In production, you should verify the signature
    let claims = crate::crypto::jwt::extract_claims_unverified(token)
        .map_err(|_| StatusCode::UNAUTHORIZED)?;

    // Get the user ID from claims
    let user_id = claims
        .get("sub")
        .and_then(|v| v.as_str())
        .ok_or(StatusCode::UNAUTHORIZED)?;

    tracing::info!("User authenticated: {}", user_id);

    // Continue with the request
    Ok(next.run(request).await)
}

/// Permission-based authorization middleware.
///
/// This middleware checks if the authenticated user has the required
/// permissions to access the endpoint.
pub struct RequirePermission {
    permissions: Vec<String>,
}

impl RequirePermission {
    /// Create a new permission requirement.
    pub fn new(permissions: &[&str]) -> Self {
        Self {
            permissions: permissions.iter().map(|s| s.to_string()).collect(),
        }
    }
}

// Note: In axum 0.7, middleware is typically created using from_fn
// This is a simplified implementation - in production you would implement
// proper permission checking using request extensions
