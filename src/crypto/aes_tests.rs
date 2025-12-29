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
fn test_generate_aes_key() {
    let key = generate_aes_key().unwrap();
    assert_eq!(key.len(), AES_256_KEY_SIZE);
    // Verify key is not all zeros
    assert_ne!(key, [0u8; AES_256_KEY_SIZE]);
}

#[test]
fn test_generate_aes_key_with_size_valid() {
    // Test AES-128 (16 bytes)
    let key_128 = generate_aes_key_with_size(16).unwrap();
    assert_eq!(key_128.len(), 16);

    // Test AES-192 (24 bytes)
    let key_192 = generate_aes_key_with_size(24).unwrap();
    assert_eq!(key_192.len(), 24);

    // Test AES-256 (32 bytes)
    let key_256 = generate_aes_key_with_size(32).unwrap();
    assert_eq!(key_256.len(), 32);
}

#[test]
fn test_generate_aes_key_with_size_invalid() {
    let result = generate_aes_key_with_size(15);
    assert!(result.is_err());

    let result = generate_aes_key_with_size(20);
    assert!(result.is_err());

    let result = generate_aes_key_with_size(64);
    assert!(result.is_err());
}

#[test]
fn test_aes_gcm_encrypt_decrypt() {
    let key = generate_aes_key().unwrap();
    let plaintext = b"Hello, World! This is a test message.";

    let (nonce, ciphertext) = aes_gcm_encrypt(plaintext, &key).unwrap();

    // Ciphertext should be longer than plaintext (due to auth tag)
    assert!(ciphertext.len() >= plaintext.len());
    // Nonce should be 12 bytes
    assert_eq!(nonce.len(), 12);

    // Decrypt
    let decrypted = aes_gcm_decrypt(&ciphertext, &nonce, &key).unwrap();
    assert_eq!(decrypted, plaintext);
}

#[test]
fn test_aes_gcm_decrypt_with_wrong_key() {
    let key1 = generate_aes_key().unwrap();
    let key2 = generate_aes_key().unwrap();
    let plaintext = b"Secret message";

    let (nonce, ciphertext) = aes_gcm_encrypt(plaintext, &key1).unwrap();

    // Try to decrypt with wrong key
    let result = aes_gcm_decrypt(&ciphertext, &nonce, &key2);
    assert!(result.is_err());
}

#[test]
fn test_aes_gcm_decrypt_with_wrong_nonce() {
    let key = generate_aes_key().unwrap();
    let plaintext = b"Secret message";

    let (_nonce, ciphertext) = aes_gcm_encrypt(plaintext, &key).unwrap();

    // Use wrong nonce
    let wrong_nonce = vec![0u8; 12];
    let result = aes_gcm_decrypt(&ciphertext, &wrong_nonce, &key);
    assert!(result.is_err());
}

#[test]
fn test_zeroize() {
    let mut data = vec![1, 2, 3, 4, 5];
    zeroize(&mut data);
    assert_eq!(data, vec![0, 0, 0, 0, 0]);
}

#[test]
fn test_empty_data_encrypt_decrypt() {
    let key = generate_aes_key().unwrap();
    let plaintext = b"";

    let (nonce, ciphertext) = aes_gcm_encrypt(plaintext, &key).unwrap();
    let decrypted = aes_gcm_decrypt(&ciphertext, &nonce, &key).unwrap();

    assert_eq!(decrypted, plaintext);
}

#[test]
fn test_large_data_encrypt_decrypt() {
    let key = generate_aes_key().unwrap();
    let plaintext = vec![42u8; 10000]; // 10KB of data

    let (nonce, ciphertext) = aes_gcm_encrypt(&plaintext, &key).unwrap();
    let decrypted = aes_gcm_decrypt(&ciphertext, &nonce, &key).unwrap();

    assert_eq!(decrypted, plaintext);
}
