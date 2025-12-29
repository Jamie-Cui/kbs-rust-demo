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

#[tokio::test]
async fn test_memory_key_manager_new() {
    let manager = MemoryKeyManager::new();
    // Just verify it can be created
    assert_eq!(manager.keys.read().await.len(), 0);
}

#[tokio::test]
async fn test_memory_key_manager_default() {
    let manager = MemoryKeyManager::default();
    // Just verify it can be created with default
    assert_eq!(manager.keys.read().await.len(), 0);
}

#[tokio::test]
async fn test_memory_key_manager_create_aes_key() {
    let manager = MemoryKeyManager::new();
    let request = KeyRequest {
        key_information: KeyInfo {
            algorithm: "AES".to_string(),
            key_length: Some(256),
            curve_type: None,
            key_data: None,
            kmip_key_id: None,
        },
        transfer_policy_id: Uuid::new_v4(),
    };

    let result = manager.create_key(&request).await;
    assert!(result.is_ok());

    let key_info = result.unwrap();
    assert_eq!(key_info.algorithm, "AES");
    assert_eq!(key_info.key_length, Some(256));
    assert!(key_info.kmip_key_id.is_some());
}

#[tokio::test]
async fn test_memory_key_manager_create_invalid_key() {
    let manager = MemoryKeyManager::new();
    let request = KeyRequest {
        key_information: KeyInfo {
            algorithm: "AES".to_string(),
            key_length: Some(999), // Invalid length
            curve_type: None,
            key_data: None,
            kmip_key_id: None,
        },
        transfer_policy_id: Uuid::new_v4(),
    };

    let result = manager.create_key(&request).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_memory_key_manager_create_rsa_key() {
    let manager = MemoryKeyManager::new();
    let request = KeyRequest {
        key_information: KeyInfo {
            algorithm: "RSA".to_string(),
            key_length: Some(2048),
            curve_type: None,
            key_data: None,
            kmip_key_id: None,
        },
        transfer_policy_id: Uuid::new_v4(),
    };

    let result = manager.create_key(&request).await;
    assert!(result.is_ok());

    let key_info = result.unwrap();
    assert_eq!(key_info.algorithm, "RSA");
    assert!(key_info.kmip_key_id.is_some());
}

#[tokio::test]
async fn test_memory_key_manager_create_ec_key_fails() {
    let manager = MemoryKeyManager::new();
    let request = KeyRequest {
        key_information: KeyInfo {
            algorithm: "EC".to_string(),
            key_length: None,
            curve_type: Some("secp256r1".to_string()),
            key_data: None,
            kmip_key_id: None,
        },
        transfer_policy_id: Uuid::new_v4(),
    };

    let result = manager.create_key(&request).await;
    // EC not implemented
    assert!(result.is_err());
}

#[tokio::test]
async fn test_memory_key_manager_delete_key() {
    let manager = MemoryKeyManager::new();
    let request = KeyRequest {
        key_information: KeyInfo {
            algorithm: "AES".to_string(),
            key_length: Some(256),
            curve_type: None,
            key_data: None,
            kmip_key_id: None,
        },
        transfer_policy_id: Uuid::new_v4(),
    };

    let key_info = manager.create_key(&request).await.unwrap();
    let key_id = key_info.kmip_key_id.unwrap();

    let result = manager.delete_key(&key_id).await;
    assert!(result.is_ok());

    // Verify key is deleted
    let result = manager.delete_key(&key_id).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_memory_key_manager_transfer_key() {
    let manager = MemoryKeyManager::new();
    let request = KeyRequest {
        key_information: KeyInfo {
            algorithm: "AES".to_string(),
            key_length: Some(256),
            curve_type: None,
            key_data: None,
            kmip_key_id: None,
        },
        transfer_policy_id: Uuid::new_v4(),
    };

    let key_info = manager.create_key(&request).await.unwrap();
    let key_id = key_info.kmip_key_id.unwrap();

    let result = manager.transfer_key(&key_id).await;
    assert!(result.is_ok());

    let key_material = result.unwrap();
    // AES-256 key should be 32 bytes
    assert_eq!(key_material.len(), 32);
}

#[tokio::test]
async fn test_memory_key_manager_transfer_nonexistent_key() {
    let manager = MemoryKeyManager::new();
    let result = manager.transfer_key("nonexistent").await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_memory_key_manager_register_key_with_key_data() {
    let manager = MemoryKeyManager::new();
    use base64::Engine;

    let key_data = base64::engine::general_purpose::STANDARD.encode(vec![1u8; 32]);
    let request = KeyRequest {
        key_information: KeyInfo {
            algorithm: "AES".to_string(),
            key_length: Some(256),
            curve_type: None,
            key_data: Some(key_data),
            kmip_key_id: None,
        },
        transfer_policy_id: Uuid::new_v4(),
    };

    let result = manager.register_key(&request).await;
    assert!(result.is_ok());

    let key_info = result.unwrap();
    assert!(key_info.kmip_key_id.is_some());
}

#[tokio::test]
async fn test_memory_key_manager_register_key_without_key_data_fails() {
    let manager = MemoryKeyManager::new();
    let request = KeyRequest {
        key_information: KeyInfo {
            algorithm: "AES".to_string(),
            key_length: Some(256),
            curve_type: None,
            key_data: None,
            kmip_key_id: None,
        },
        transfer_policy_id: Uuid::new_v4(),
    };

    let result = manager.register_key(&request).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_memory_key_manager_register_key_with_kmip_id() {
    let manager = MemoryKeyManager::new();
    let request = KeyRequest {
        key_information: KeyInfo {
            algorithm: "AES".to_string(),
            key_length: Some(256),
            curve_type: None,
            key_data: None,
            kmip_key_id: Some("existing-key-id".to_string()),
        },
        transfer_policy_id: Uuid::new_v4(),
    };

    let result = manager.register_key(&request).await;
    // This should succeed but won't store key material
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_memory_key_manager_register_invalid_base64() {
    let manager = MemoryKeyManager::new();
    let request = KeyRequest {
        key_information: KeyInfo {
            algorithm: "AES".to_string(),
            key_length: Some(256),
            curve_type: None,
            key_data: Some("invalid-base64!!".to_string()),
            kmip_key_id: None,
        },
        transfer_policy_id: Uuid::new_v4(),
    };

    let result = manager.register_key(&request).await;
    assert!(result.is_err());
}

#[test]
fn test_memory_key_manager_generate_key_id() {
    let id1 = MemoryKeyManager::generate_key_id();
    let id2 = MemoryKeyManager::generate_key_id();

    assert_ne!(id1, id2);
    assert!(id1.starts_with("kms-"));
    assert!(id2.starts_with("kms-"));
}
