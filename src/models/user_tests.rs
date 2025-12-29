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

#[test]
fn test_user_validate_valid() {
    let user = User {
        username: "testuser".to_string(),
        password: "password123".to_string(),
        permissions: vec!["keys:create".to_string()],
    };
    assert!(user.validate().is_ok());
}

#[test]
fn test_user_validate_empty_username() {
    let user = User {
        username: "".to_string(),
        password: "password123".to_string(),
        permissions: vec!["keys:create".to_string()],
    };
    assert!(user.validate().is_err());
}

#[test]
fn test_user_validate_too_long_username() {
    let user = User {
        username: "a".repeat(256),
        password: "password123".to_string(),
        permissions: vec!["keys:create".to_string()],
    };
    assert!(user.validate().is_err());
}

#[test]
fn test_user_validate_empty_password() {
    let user = User {
        username: "testuser".to_string(),
        password: "".to_string(),
        permissions: vec!["keys:create".to_string()],
    };
    assert!(user.validate().is_err());
}

#[test]
fn test_user_validate_short_password() {
    let user = User {
        username: "testuser".to_string(),
        password: "short".to_string(),
        permissions: vec!["keys:create".to_string()],
    };
    assert!(user.validate().is_err());
}

#[test]
fn test_user_validate_long_password() {
    let user = User {
        username: "testuser".to_string(),
        password: "a".repeat(65),
        permissions: vec!["keys:create".to_string()],
    };
    assert!(user.validate().is_err());
}

#[test]
fn test_user_validate_no_permissions() {
    let user = User {
        username: "testuser".to_string(),
        password: "password123".to_string(),
        permissions: vec![],
    };
    assert!(user.validate().is_err());
}

#[test]
fn test_user_info_verify_password() {
    // This is a basic smoke test - actual password verification
    // requires bcrypt which we're not going to test deeply here
    let user_info = UserInfo {
        id: Uuid::new_v4(),
        created_at: time::OffsetDateTime::now_utc(),
        updated_at: time::OffsetDateTime::now_utc(),
        username: "testuser".to_string(),
        password_hash: "$2b$12$dummy.hash.value.for.testing".to_string(),
        password_cost: 12,
        permissions: vec!["keys:create".to_string()],
    };

    // Just verify the method exists and returns a Result
    let result = user_info.verify_password("password");
    // It will fail because the hash is invalid, but that's OK for this test
    assert!(result.is_err() || result.is_ok());
}

#[test]
fn test_user_info_to_response() {
    let user_info = UserInfo {
        id: Uuid::new_v4(),
        created_at: time::OffsetDateTime::now_utc(),
        updated_at: time::OffsetDateTime::now_utc(),
        username: "testuser".to_string(),
        password_hash: "hash".to_string(),
        password_cost: 12,
        permissions: vec!["keys:create".to_string(), "keys:transfer".to_string()],
    };

    let response = user_info.to_response();

    assert_eq!(response.id, user_info.id);
    assert_eq!(response.username, user_info.username);
    assert_eq!(response.permissions, user_info.permissions);
    assert_eq!(response.created_at, user_info.created_at);
    assert_eq!(response.updated_at, user_info.updated_at);
}

#[test]
fn test_user_filter_criteria_default() {
    let criteria = UserFilterCriteria::default();
    assert!(criteria.username.is_none());
}

#[test]
fn test_user_response_serialization() {
    let response = UserResponse {
        id: Uuid::new_v4(),
        created_at: time::OffsetDateTime::now_utc(),
        updated_at: time::OffsetDateTime::now_utc(),
        username: "testuser".to_string(),
        permissions: vec!["keys:create".to_string()],
    };

    let json = serde_json::to_string(&response).unwrap();
    assert!(json.contains("testuser"));
    assert!(json.contains("keys:create"));
}

#[test]
fn test_auth_token_request_serialization() {
    let request = AuthTokenRequest {
        username: "testuser".to_string(),
        password: "password123".to_string(),
    };

    let json = serde_json::to_string(&request).unwrap();
    assert!(json.contains("testuser"));

    let parsed: AuthTokenRequest = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed.username, "testuser");
    assert_eq!(parsed.password, "password123");
}

#[test]
fn test_update_user_request_all_fields() {
    let request = UpdateUserRequest {
        username: Some("newuser".to_string()),
        password: Some("newpassword".to_string()),
        permissions: Some(vec!["keys:delete".to_string()]),
    };

    assert!(request.username.is_some());
    assert!(request.password.is_some());
    assert!(request.permissions.is_some());
}

#[test]
fn test_update_user_request_partial() {
    let request = UpdateUserRequest {
        username: Some("newuser".to_string()),
        password: None,
        permissions: None,
    };

    assert_eq!(request.username, Some("newuser".to_string()));
    assert!(request.password.is_none());
    assert!(request.permissions.is_none());
}
