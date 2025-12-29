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


use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use crate::error::{KbsError, KbsResult};
use std::time::{SystemTime, UNIX_EPOCH};

/// JWT claims for KBS authentication.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KbsClaims {
    /// Subject (user ID)
    pub sub: String,

    /// Username
    pub username: String,

    /// User permissions
    pub permissions: Vec<String>,

    /// Issued at timestamp
    pub iat: i64,

    /// Expiration timestamp
    pub exp: i64,

    /// JWT ID
    pub jti: String,
}

/// Create a JWT token for a user.
///
/// # Arguments
/// * `user_id` - User ID
/// * `username` - Username
/// * `permissions` - User permissions
/// * `secret_pem` - RSA private key in PEM format for signing
/// * `validity_minutes` - Token validity in minutes
///
/// # Returns
/// The encoded JWT token string.
pub fn create_token(
    user_id: &str,
    username: &str,
    permissions: &[String],
    secret_pem: &str,
    validity_minutes: i64,
) -> KbsResult<String> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| KbsError::Crypto(format!("Time error: {}", e)))?
        .as_secs() as i64;

    let exp = now + (validity_minutes * 60);

    let claims = KbsClaims {
        sub: user_id.to_string(),
        username: username.to_string(),
        permissions: permissions.to_vec(),
        iat: now,
        exp,
        jti: uuid::Uuid::new_v4().to_string(),
    };

    // Use RS256 (RSA signature with SHA-256)
    let mut header = Header::new(jsonwebtoken::Algorithm::RS256);
    header.kid = Some("kbs-signing-key".to_string());

    let encoding_key = EncodingKey::from_rsa_pem(secret_pem.as_bytes())
        .map_err(|e| KbsError::Crypto(format!("Invalid signing key: {}", e)))?;

    let token = encode(&header, &claims, &encoding_key)
        .map_err(|e| KbsError::Crypto(format!("Token creation failed: {}", e)))?;

    Ok(token)
}

/// Verify a JWT token.
///
/// # Arguments
/// * `token` - The JWT token string
/// * `public_key_pem` - RSA public key in PEM format for verification
///
/// # Returns
/// The decoded claims if verification succeeds.
pub fn verify_token(token: &str, public_key_pem: &str) -> KbsResult<KbsClaims> {
    let decoding_key = DecodingKey::from_rsa_pem(public_key_pem.as_bytes())
        .map_err(|e| KbsError::Crypto(format!("Invalid verification key: {}", e)))?;

    let mut validation = Validation::new(jsonwebtoken::Algorithm::RS256);
    validation.validate_exp = true;

    let token_data = decode::<KbsClaims>(token, &decoding_key, &validation)
        .map_err(|e| KbsError::Auth(format!("Token verification failed: {}", e)))?;

    Ok(token_data.claims)
}

/// Extract claims from a token without verification (for debugging).
pub fn extract_claims_unverified(token: &str) -> KbsResult<serde_json::Value> {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(KbsError::Validation("Invalid token format".into()));
    }

    // Decode the payload (middle part)
    let payload = parts[1];
    let decoded = URL_SAFE_NO_PAD
        .decode(payload)
        .map_err(|e| KbsError::Validation(format!("Failed to decode token payload: {}", e)))?;

    let claims: serde_json::Value = serde_json::from_slice(&decoded)
        .map_err(|e| KbsError::Validation(format!("Failed to parse claims: {}", e)))?;

    Ok(claims)
}

#[cfg(test)]
#[path = "jwt_tests.rs"]
mod jwt_tests;
