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
fn test_key_info_validate_aes_valid() {
    let key_info = KeyInfo {
        algorithm: "AES".to_string(),
        key_length: Some(256),
        curve_type: None,
        key_data: None,
        kmip_key_id: None,
    };
    assert!(key_info.validate().is_ok());
}

#[test]
fn test_key_info_validate_aes_valid_all_sizes() {
    for length in [128, 192, 256] {
        let key_info = KeyInfo {
            algorithm: "AES".to_string(),
            key_length: Some(length),
            curve_type: None,
            key_data: None,
            kmip_key_id: None,
        };
        assert!(key_info.validate().is_ok(), "AES-{} should be valid", length);
    }
}

#[test]
fn test_key_info_validate_aes_invalid_length() {
    let key_info = KeyInfo {
        algorithm: "AES".to_string(),
        key_length: Some(512),
        curve_type: None,
        key_data: None,
        kmip_key_id: None,
    };
    assert!(key_info.validate().is_err());
}

#[test]
fn test_key_info_validate_aes_missing_length() {
    let key_info = KeyInfo {
        algorithm: "AES".to_string(),
        key_length: None,
        curve_type: None,
        key_data: None,
        kmip_key_id: None,
    };
    assert!(key_info.validate().is_err());
}

#[test]
fn test_key_info_validate_rsa_valid() {
    for length in [2048, 3072, 4096, 7680] {
        let key_info = KeyInfo {
            algorithm: "RSA".to_string(),
            key_length: Some(length),
            curve_type: None,
            key_data: None,
            kmip_key_id: None,
        };
        assert!(key_info.validate().is_ok(), "RSA-{} should be valid", length);
    }
}

#[test]
fn test_key_info_validate_rsa_invalid_length() {
    let key_info = KeyInfo {
        algorithm: "RSA".to_string(),
        key_length: Some(1024),
        curve_type: None,
        key_data: None,
        kmip_key_id: None,
    };
    assert!(key_info.validate().is_err());
}

#[test]
fn test_key_info_validate_ec_valid() {
    for curve in ["secp256r1", "secp384r1", "secp521r1", "prime256v1"] {
        let key_info = KeyInfo {
            algorithm: "EC".to_string(),
            key_length: None,
            curve_type: Some(curve.to_string()),
            key_data: None,
            kmip_key_id: None,
        };
        assert!(key_info.validate().is_ok(), "EC with {} should be valid", curve);
    }
}

#[test]
fn test_key_info_validate_ec_missing_curve() {
    let key_info = KeyInfo {
        algorithm: "EC".to_string(),
        key_length: None,
        curve_type: None,
        key_data: None,
        kmip_key_id: None,
    };
    assert!(key_info.validate().is_err());
}

#[test]
fn test_key_info_validate_ec_invalid_curve() {
    let key_info = KeyInfo {
        algorithm: "EC".to_string(),
        key_length: None,
        curve_type: Some("invalid_curve".to_string()),
        key_data: None,
        kmip_key_id: None,
    };
    assert!(key_info.validate().is_err());
}

#[test]
fn test_key_info_validate_invalid_algorithm() {
    let key_info = KeyInfo {
        algorithm: "INVALID".to_string(),
        key_length: None,
        curve_type: None,
        key_data: None,
        kmip_key_id: None,
    };
    assert!(key_info.validate().is_err());
}

#[test]
fn test_key_info_is_create() {
    let key_info = KeyInfo {
        algorithm: "AES".to_string(),
        key_length: Some(256),
        curve_type: None,
        key_data: None,
        kmip_key_id: None,
    };
    assert!(key_info.is_create());
    assert!(!key_info.is_register());
}

#[test]
fn test_key_info_is_register_with_key_data() {
    let key_info = KeyInfo {
        algorithm: "AES".to_string(),
        key_length: Some(256),
        curve_type: None,
        key_data: Some("aGVsbG8=".to_string()),
        kmip_key_id: None,
    };
    assert!(!key_info.is_create());
    assert!(key_info.is_register());
}

#[test]
fn test_key_info_is_register_with_kmip_id() {
    let key_info = KeyInfo {
        algorithm: "AES".to_string(),
        key_length: Some(256),
        curve_type: None,
        key_data: None,
        kmip_key_id: Some("kmip-123".to_string()),
    };
    assert!(!key_info.is_create());
    assert!(key_info.is_register());
}

#[test]
fn test_key_info_case_insensitive_algorithm() {
    // Lowercase
    let key_info = KeyInfo {
        algorithm: "aes".to_string(),
        key_length: Some(256),
        curve_type: None,
        key_data: None,
        kmip_key_id: None,
    };
    assert!(key_info.validate().is_ok());

    // Mixed case
    let key_info = KeyInfo {
        algorithm: "AeS".to_string(),
        key_length: Some(256),
        curve_type: None,
        key_data: None,
        kmip_key_id: None,
    };
    assert!(key_info.validate().is_ok());
}

#[test]
fn test_key_response_serialization() {
    let response = KeyResponse {
        id: Uuid::new_v4(),
        key_info: KeyInfo {
            algorithm: "AES".to_string(),
            key_length: Some(256),
            curve_type: None,
            key_data: None,
            kmip_key_id: None,
        },
        transfer_policy_id: Uuid::new_v4(),
        transfer_link: "/transfer/123".to_string(),
        created_at: time::OffsetDateTime::now_utc(),
    };

    let json = serde_json::to_string(&response).unwrap();
    assert!(json.contains("transfer_link"));
    assert!(json.contains("created_at"));
}

#[test]
fn test_key_filter_criteria_default() {
    let criteria = KeyFilterCriteria::default();
    assert!(criteria.algorithm.is_none());
    assert!(criteria.key_length.is_none());
    assert!(criteria.curve_type.is_none());
    assert!(criteria.transfer_policy_id.is_none());
}
