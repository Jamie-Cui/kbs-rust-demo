/*
 *   Copyright (c) 2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

//! HTTP middleware.

pub mod auth;

use axum::{
    extract::Request,
    middleware::Next,
    response::Response,
};

/// Logging middleware to add request context.
pub async fn logging_middleware(
    request: Request,
    next: Next,
) -> Response {
    let uri = request.uri().clone();
    let method = request.method().clone();

    let response = next.run(request).await;

    tracing::info!("{} {} - {}", method, uri, response.status());

    response
}
