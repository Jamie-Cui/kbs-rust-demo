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

//!
//! JWT signing key generation task.
//!
//! This task generates an RSA private key for JWT token signing
//! if it doesn't already exist.

use crate::constant::DEFAULT_JWT_SIGNING_KEY_PATH;
use crate::crypto::x509::generate_jwt_signing_key;
use crate::error::{KbsError, KbsResult};
use std::fs;

/// Task for generating JWT signing key.
///
/// This task will generate an RSA private key for JWT signing
/// if one doesn't already exist.
pub struct CreateSigningKey {
    /// Path where the JWT signing key will be saved
    pub jwt_signing_key_path: String,
}

impl CreateSigningKey {
    /// Create a new JWT signing key generation task with default path.
    pub fn new() -> Self {
        CreateSigningKey {
            jwt_signing_key_path: DEFAULT_JWT_SIGNING_KEY_PATH.to_string(),
        }
    }

    /// Create a new JWT signing key generation task with custom path.
    ///
    /// # Arguments
    ///
    /// * `jwt_signing_key_path` - Path for the JWT signing key
    pub fn with_path(jwt_signing_key_path: &str) -> Self {
        CreateSigningKey {
            jwt_signing_key_path: jwt_signing_key_path.to_string(),
        }
    }

    /// Check if JWT signing key already exists.
    pub fn exists(&self) -> bool {
        fs::metadata(&self.jwt_signing_key_path).is_ok()
    }

    /// Generate the JWT signing key if it doesn't exist.
    ///
    /// Returns `Ok(true)` if the key was generated,
    /// `Ok(false)` if it already existed, or `Err` on failure.
    pub fn generate_if_missing(&self) -> KbsResult<bool> {
        if self.exists() {
            return Ok(false);
        }

        self.generate()?;
        Ok(true)
    }

    /// Generate the JWT signing key (overwriting if it exists).
    pub fn generate(&self) -> KbsResult<()> {
        generate_jwt_signing_key(&self.jwt_signing_key_path)
    }
}

impl Default for CreateSigningKey {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_create_signing_key_new() {
        let task = CreateSigningKey::new();
        assert_eq!(task.jwt_signing_key_path, DEFAULT_JWT_SIGNING_KEY_PATH);
    }

    #[test]
    fn test_create_signing_key_with_path() {
        let task = CreateSigningKey::with_path("/tmp/jwt.key");
        assert_eq!(task.jwt_signing_key_path, "/tmp/jwt.key");
    }

    #[test]
    fn test_create_signing_key_generate() {
        let temp_dir = TempDir::new().unwrap();
        let key_path = temp_dir.path().join("jwt-signing.key");

        let task = CreateSigningKey::with_path(key_path.to_str().unwrap());

        assert!(!task.exists());
        task.generate().unwrap();
        assert!(task.exists());

        // File should exist
        assert!(key_path.exists());
    }

    #[test]
    fn test_create_signing_key_generate_if_missing() {
        let temp_dir = TempDir::new().unwrap();
        let key_path = temp_dir.path().join("jwt-signing.key");

        let task = CreateSigningKey::with_path(key_path.to_str().unwrap());

        // First call - should generate
        let generated = task.generate_if_missing().unwrap();
        assert!(generated);

        // Second call - should skip
        let generated = task.generate_if_missing().unwrap();
        assert!(!generated);
    }
}
