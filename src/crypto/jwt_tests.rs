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
use rsa::RsaPrivateKey;
use pkcs8::EncodePrivateKey;
use rsa::pkcs1::EncodeRsaPublicKey;
use base64::Engine;

fn generate_test_keypair() -> (String, String) {
    let mut rng = rand::thread_rng();
    let private_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();

    // Use DER encoding and then convert to base64-like PEM format manually
    let private_der = private_key.to_pkcs8_der().unwrap();
    let private_pem = format!(
        "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----",
        base64::engine::general_purpose::STANDARD.encode(private_der.to_bytes())
    );

    let public_key = private_key.to_public_key();
    let public_der = public_key.to_pkcs1_der().unwrap();
    let public_pem = format!(
        "-----BEGIN RSA PUBLIC KEY-----\n{}\n-----END RSA PUBLIC KEY-----",
        base64::engine::general_purpose::STANDARD.encode(public_der.as_bytes())
    );

    (
        private_pem,
        public_pem,
    )
}

#[test]
fn test_create_and_verify_token() {
    let (private_pem, public_pem) = generate_test_keypair();

    let token = create_token(
        "user-123",
        "testuser",
        &["keys:create".to_string(), "keys:transfer".to_string()],
        &private_pem,
        60,
    )
    .unwrap();

    assert!(!token.is_empty());

    // Verify the token
    let claims = verify_token(&token, &public_pem).unwrap();
    assert_eq!(claims.sub, "user-123");
    assert_eq!(claims.username, "testuser");
    assert_eq!(claims.permissions, vec!["keys:create", "keys:transfer"]);
}

#[test]
fn test_verify_token_with_wrong_key() {
    let (private_pem1, _) = generate_test_keypair();
    let (_, public_pem2) = generate_test_keypair();

    let token = create_token("user-123", "testuser", &[], &private_pem1, 60).unwrap();

    // Try to verify with different key
    let result = verify_token(&token, &public_pem2);
    assert!(result.is_err());
}

#[test]
fn test_extract_claims_unverified() {
    let (private_pem, _) = generate_test_keypair();

    let token = create_token(
        "user-456",
        "alice",
        &["users:create".to_string()],
        &private_pem,
        30,
    )
    .unwrap();

    let claims = extract_claims_unverified(&token).unwrap();
    assert_eq!(claims["sub"], "user-456");
    assert_eq!(claims["username"], "alice");
    assert!(claims["permissions"].is_array());
}

#[test]
fn test_extract_claims_invalid_token() {
    let result = extract_claims_unverified("invalid.token");
    assert!(result.is_err());

    let result = extract_claims_unverified("not-even-a-token");
    assert!(result.is_err());
}

#[test]
fn test_create_token_different_validity() {
    let (private_pem, public_pem) = generate_test_keypair();

    let token = create_token("user-789", "bob", &[], &private_pem, 5).unwrap();
    let claims = verify_token(&token, &public_pem).unwrap();

    // Check that expiration is approximately 5 minutes from now
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

    assert!(claims.exp > now + 290); // ~4:50 minutes
    assert!(claims.exp <= now + 305); // ~5:05 minutes
}
