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


use super::*;
use axum::http::StatusCode;

#[test]
fn test_kbs_error_display() {
    let err = KbsError::Config("config error".to_string());
    assert_eq!(format!("{}", err), "Configuration error: config error");

    let err = KbsError::NotFound("key".to_string());
    assert_eq!(format!("{}", err), "Not found: key");
}

#[test]
fn test_repository_error_display() {
    let err = RepositoryError::NotFound("record".to_string());
    assert_eq!(format!("{}", err), "Record not found: record");

    let err = RepositoryError::Serialization("parse error".to_string());
    assert_eq!(format!("{}", err), "Failed to serialize/deserialize: parse error");
}

#[test]
fn test_service_error_display() {
    let err = ServiceError::InvalidInput("bad input".to_string());
    assert_eq!(format!("{}", err), "Invalid input: bad input");

    let err = ServiceError::PolicyValidation("policy failed".to_string());
    assert_eq!(format!("{}", err), "Policy validation failed: policy failed");
}

#[test]
fn test_kbs_error_into_response_status() {
    // Test various error types return correct status codes
    let tests = vec![
        (KbsError::Config("err".to_string()), StatusCode::INTERNAL_SERVER_ERROR),
        (KbsError::Auth("auth err".to_string()), StatusCode::UNAUTHORIZED),
        (KbsError::Authorization("authz err".to_string()), StatusCode::FORBIDDEN),
        (KbsError::Validation("val err".to_string()), StatusCode::BAD_REQUEST),
        (KbsError::NotFound("not found".to_string()), StatusCode::NOT_FOUND),
        (KbsError::Crypto("crypto err".to_string()), StatusCode::INTERNAL_SERVER_ERROR),
    ];

    for (error, expected_status) in tests {
        let error_str = format!("{}", error);
        let response = error.into_response();
        let status = response.status();
        assert_eq!(status, expected_status, "Expected {} for error: {}", expected_status, error_str);
    }
}

#[test]
fn test_repository_error_from_io() {
    let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
    let repo_err: RepositoryError = io_err.into();
    assert!(matches!(repo_err, RepositoryError::Io(_)));
}

#[test]
fn test_service_error_from_repository() {
    let repo_err = RepositoryError::NotFound("key".to_string());
    let kbs_err: KbsError = repo_err.into();
    assert!(matches!(kbs_err, KbsError::Repository(_)));
}

#[test]
fn test_service_error_from_service() {
    let svc_err = ServiceError::Unauthorized;
    let kbs_err: KbsError = svc_err.into();
    assert!(matches!(kbs_err, KbsError::Service(_)));
}

#[test]
fn test_kbs_error_from_string() {
    let str_err = "validation failed".to_string();
    let kbs_err: KbsError = str_err.into();
    assert!(matches!(kbs_err, KbsError::Validation(_)));
    assert_eq!(format!("{}", kbs_err), "Validation error: validation failed");
}

#[test]
fn test_error_response_serialization() {
    // The ErrorResponse struct is used in IntoResponse
    // This test verifies the error can be converted to a response
    let error = KbsError::Validation("test error".to_string());
    let _response = error.into_response();
    // If we got here without panicking, the test passes
}
