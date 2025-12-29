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
//! TLS certificate and key generation task.
//!
//! This task generates a self-signed TLS certificate and private key
//! for HTTPS server operation if they don't already exist.

use crate::constant::{DEFAULT_TLS_CERT_PATH, DEFAULT_TLS_KEY_PATH, DEFAULT_TLS_SAN};
use crate::crypto::x509::generate_tls_certificate;
use crate::error::{KbsError, KbsResult};
use std::fs;

/// Task for generating TLS certificate and key.
///
/// This task will generate a self-signed certificate if one doesn't exist.
pub struct TlsKeyAndCert {
    /// Path where the TLS certificate will be saved
    pub cert_path: String,
    /// Path where the TLS private key will be saved
    pub key_path: String,
    /// Comma-separated list of Subject Alternative Names
    pub san_list: String,
}

impl TlsKeyAndCert {
    /// Create a new TLS certificate generation task with default paths.
    pub fn new() -> Self {
        TlsKeyAndCert {
            cert_path: DEFAULT_TLS_CERT_PATH.to_string(),
            key_path: DEFAULT_TLS_KEY_PATH.to_string(),
            san_list: DEFAULT_TLS_SAN.to_string(),
        }
    }

    /// Create a new TLS certificate generation task with custom paths.
    ///
    /// # Arguments
    ///
    /// * `cert_path` - Path for the certificate
    /// * `key_path` - Path for the private key
    /// * `san_list` - Comma-separated SAN list
    pub fn with_paths(cert_path: &str, key_path: &str, san_list: &str) -> Self {
        TlsKeyAndCert {
            cert_path: cert_path.to_string(),
            key_path: key_path.to_string(),
            san_list: san_list.to_string(),
        }
    }

    /// Check if TLS certificate and key already exist.
    pub fn exists(&self) -> bool {
        fs::metadata(&self.cert_path).is_ok() && fs::metadata(&self.key_path).is_ok()
    }

    /// Generate the TLS certificate and key if they don't exist.
    ///
    /// Returns `Ok(true)` if the certificate was generated,
    /// `Ok(false)` if it already existed, or `Err` on failure.
    pub fn generate_if_missing(&self) -> KbsResult<bool> {
        if self.exists() {
            return Ok(false);
        }

        self.generate()?;
        Ok(true)
    }

    /// Generate the TLS certificate and key (overwriting if they exist).
    pub fn generate(&self) -> KbsResult<()> {
        generate_tls_certificate(&self.cert_path, &self.key_path, &self.san_list)
    }
}

impl Default for TlsKeyAndCert {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_tls_key_and_cert_new() {
        let task = TlsKeyAndCert::new();
        assert_eq!(task.cert_path, DEFAULT_TLS_CERT_PATH);
        assert_eq!(task.key_path, DEFAULT_TLS_KEY_PATH);
        assert_eq!(task.san_list, DEFAULT_TLS_SAN);
    }

    #[test]
    fn test_tls_key_and_cert_with_paths() {
        let task = TlsKeyAndCert::with_paths("/tmp/cert.pem", "/tmp/key.pem", "localhost");
        assert_eq!(task.cert_path, "/tmp/cert.pem");
        assert_eq!(task.key_path, "/tmp/key.pem");
        assert_eq!(task.san_list, "localhost");
    }

    #[test]
    fn test_tls_key_and_cert_generate() {
        let temp_dir = TempDir::new().unwrap();
        let cert_path = temp_dir.path().join("tls.crt");
        let key_path = temp_dir.path().join("tls.key");

        let task = TlsKeyAndCert::with_paths(
            cert_path.to_str().unwrap(),
            key_path.to_str().unwrap(),
            "127.0.0.1,localhost",
        );

        assert!(!task.exists());
        task.generate().unwrap();
        assert!(task.exists());

        // Files should exist
        assert!(cert_path.exists());
        assert!(key_path.exists());
    }

    #[test]
    fn test_tls_key_and_cert_generate_if_missing() {
        let temp_dir = TempDir::new().unwrap();
        let cert_path = temp_dir.path().join("tls.crt");
        let key_path = temp_dir.path().join("tls.key");

        let task = TlsKeyAndCert::with_paths(
            cert_path.to_str().unwrap(),
            key_path.to_str().unwrap(),
            "127.0.0.1,localhost",
        );

        // First call - should generate
        let generated = task.generate_if_missing().unwrap();
        assert!(generated);

        // Second call - should skip
        let generated = task.generate_if_missing().unwrap();
        assert!(!generated);
    }
}
