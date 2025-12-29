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
    http::StatusCode,
    response::{IntoResponse, Json, Response},
};
use serde::Serialize;
use thiserror::Error;

/// Main error type for the KBS service.
#[derive(Error, Debug)]
pub enum KbsError {
    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Repository error: {0}")]
    Repository(#[from] RepositoryError),

    #[error("Service error: {0}")]
    Service(#[from] ServiceError),

    #[error("Authentication error: {0}")]
    Auth(String),

    #[error("Authorization error: {0}")]
    Authorization(String),

    #[error("Validation error: {0}")]
    Validation(String),

    #[error("Key manager error: {0}")]
    KeyManager(String),

    #[error("ITA client error: {0}")]
    ItaClient(String),

    #[error("Crypto error: {0}")]
    Crypto(String),

    #[error("Not found: {0}")]
    NotFound(String),

    #[error("Internal error: {0}")]
    Internal(String),
}

/// Repository-specific errors.
#[derive(Error, Debug)]
pub enum RepositoryError {
    #[error("Record not found: {0}")]
    NotFound(String),

    #[error("Failed to serialize/deserialize: {0}")]
    Serialization(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Failed to parse: {0}")]
    Parse(String),
}

/// Service-specific errors.
#[derive(Error, Debug)]
pub enum ServiceError {
    #[error("Invalid input: {0}")]
    InvalidInput(String),

    #[error("Policy validation failed: {0}")]
    PolicyValidation(String),

    #[error("Attestation verification failed: {0}")]
    AttestationVerification(String),

    #[error("Key transfer failed: {0}")]
    KeyTransfer(String),

    #[error("User already exists: {0}")]
    UserExists(String),

    #[error("Unauthorized operation")]
    Unauthorized,
}

/// HTTP error response wrapper.
#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}

impl IntoResponse for KbsError {
    fn into_response(self) -> Response {
        let (status, message) = match &self {
            KbsError::Config(_) => (StatusCode::INTERNAL_SERVER_ERROR, self.to_string()),
            KbsError::Repository(e) => match e {
                RepositoryError::NotFound(_) => (StatusCode::NOT_FOUND, self.to_string()),
                _ => (StatusCode::INTERNAL_SERVER_ERROR, self.to_string()),
            },
            KbsError::Service(e) => match e {
                ServiceError::InvalidInput(_) => (StatusCode::BAD_REQUEST, self.to_string()),
                ServiceError::Unauthorized => (StatusCode::UNAUTHORIZED, self.to_string()),
                ServiceError::PolicyValidation(_) => (StatusCode::UNAUTHORIZED, self.to_string()),
                ServiceError::AttestationVerification(_) => {
                    (StatusCode::UNAUTHORIZED, self.to_string())
                }
                ServiceError::UserExists(_) => (StatusCode::BAD_REQUEST, self.to_string()),
                _ => (StatusCode::INTERNAL_SERVER_ERROR, self.to_string()),
            },
            KbsError::Auth(_) => (StatusCode::UNAUTHORIZED, self.to_string()),
            KbsError::Authorization(_) => (StatusCode::FORBIDDEN, self.to_string()),
            KbsError::Validation(_) => (StatusCode::BAD_REQUEST, self.to_string()),
            KbsError::KeyManager(_) => (StatusCode::INTERNAL_SERVER_ERROR, self.to_string()),
            KbsError::ItaClient(_) => (StatusCode::BAD_GATEWAY, self.to_string()),
            KbsError::NotFound(_) => (StatusCode::NOT_FOUND, self.to_string()),
            KbsError::Internal(_) => (StatusCode::INTERNAL_SERVER_ERROR, self.to_string()),
            KbsError::Crypto(_) => (StatusCode::INTERNAL_SERVER_ERROR, self.to_string()),
        };

        let body = Json(ErrorResponse { error: message });
        (status, body).into_response()
    }
}

/// Result type alias for KBS operations.
pub type KbsResult<T> = Result<T, KbsError>;

// Implement From for config crate errors
impl From<config::ConfigError> for KbsError {
    fn from(err: config::ConfigError) -> Self {
        KbsError::Config(err.to_string())
    }
}

// Implement From for String to allow `?` operator with String errors
impl From<String> for KbsError {
    fn from(err: String) -> Self {
        KbsError::Validation(err)
    }
}

// Implement From for std::io::Error to allow `?` operator in file operations
impl From<std::io::Error> for KbsError {
    fn from(err: std::io::Error) -> Self {
        KbsError::Internal(format!("IO error: {}", err))
    }
}

// Implement From for pkcs8::Error to allow `?` operator in crypto operations
impl From<pkcs8::Error> for KbsError {
    fn from(err: pkcs8::Error) -> Self {
        KbsError::Crypto(format!("PKCS8 error: {}", err))
    }
}

// Implement From for rsa::Error to allow `?` operator in crypto operations
impl From<rsa::Error> for KbsError {
    fn from(err: rsa::Error) -> Self {
        KbsError::Crypto(format!("RSA error: {}", err))
    }
}

// Implement From for bcrypt::BcryptError to allow `?` operator in password hashing
impl From<bcrypt::BcryptError> for KbsError {
    fn from(err: bcrypt::BcryptError) -> Self {
        KbsError::Crypto(format!("Bcrypt error: {}", err))
    }
}

// Implement From for rcgen::RcgenError to allow `?` operator in certificate generation
impl From<rcgen::RcgenError> for KbsError {
    fn from(err: rcgen::RcgenError) -> Self {
        KbsError::Crypto(format!("Certificate generation error: {}", err))
    }
}

#[cfg(test)]
#[path = "error_tests.rs"]
mod error_tests;
