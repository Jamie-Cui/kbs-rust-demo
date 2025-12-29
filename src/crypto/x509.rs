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
//! X.509 certificate utilities for TLS and JWT signing keys.
//!
//! This module provides functions to generate self-signed certificates
//! and RSA private keys for TLS and JWT signing purposes.

use crate::crypto::rsa::RsaPrivateKey;
use crate::error::{KbsError, KbsResult};
use pem::Pem;
use pkcs8::EncodePrivateKey;
use rand::rngs::OsRng;
use std::fs::File;
use std::io::Write;
use std::path::Path;

/// Generate a self-signed TLS certificate and private key.
///
/// # Arguments
///
/// * `cert_path` - Path where to save the certificate (PEM format)
/// * `key_path` - Path where to save the private key (PKCS#8 PEM format)
/// * `san_list` - Comma-separated list of Subject Alternative Names (IP addresses and DNS names)
///
/// # Example
///
/// ```rust,no_run
/// use gta_kbs::crypto::x509::generate_tls_certificate;
///
/// generate_tls_certificate(
///     "/etc/kbs/certs/tls/tls.crt",
///     "/etc/kbs/certs/tls/tls.key",
///     "127.0.0.1,localhost,kbs.example.com"
/// ).unwrap();
/// ```
pub fn generate_tls_certificate(
    cert_path: &str,
    key_path: &str,
    san_list: &str,
) -> KbsResult<()> {
    // Create parent directories if they don't exist
    if let Some(parent) = Path::new(cert_path).parent() {
        std::fs::create_dir_all(parent)?;
    }
    if let Some(parent) = Path::new(key_path).parent() {
        std::fs::create_dir_all(parent)?;
    }

    // Parse SAN list
    let sans = parse_san_list(san_list)?;

    // Generate certificate using the simple self-signed function
    let certified_key = rcgen::generate_simple_self_signed(sans)
        .map_err(|e| KbsError::Crypto(format!("Failed to generate certificate: {}", e)))?;

    // Serialize certificate to PEM
    let cert_pem = certified_key.cert.pem();

    // Serialize private key to PEM
    let key_pem = certified_key.key_pair.serialize_pem();

    // Write certificate
    let mut cert_file = File::create(cert_path)?;
    cert_file.write_all(cert_pem.as_bytes())?;
    cert_file.flush()?;

    // Set restrictive permissions on the cert file
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(cert_path)?.permissions();
        perms.set_mode(0o600);
        std::fs::set_permissions(cert_path, perms)?;
    }

    // Write private key
    let mut key_file = File::create(key_path)?;
    key_file.write_all(key_pem.as_bytes())?;
    key_file.flush()?;

    // Set restrictive permissions on the key file (0600)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(key_path)?.permissions();
        perms.set_mode(0o600);
        std::fs::set_permissions(key_path, perms)?;
    }

    Ok(())
}

/// Generate an RSA private key for JWT signing (PKCS#8 PEM format).
///
/// # Arguments
///
/// * `key_path` - Path where to save the private key
///
/// # Example
///
/// ```rust,no_run
/// use gta_kbs::crypto::x509::generate_jwt_signing_key;
///
/// generate_jwt_signing_key("/etc/kbs/certs/signing-keys/jwt-signing.key").unwrap();
/// ```
pub fn generate_jwt_signing_key(key_path: &str) -> KbsResult<()> {
    // Create parent directory if it doesn't exist
    if let Some(parent) = Path::new(key_path).parent() {
        std::fs::create_dir_all(parent)?;
    }

    // Generate RSA private key
    let mut rng = OsRng;
    let private_key = RsaPrivateKey::new(&mut rng, 3072)?;

    // Write private key (PKCS#8 PEM)
    let key_der = private_key.to_pkcs8_der()?;
    let key_pem = Pem::new("PRIVATE KEY", key_der.as_bytes());

    let mut key_file = File::create(key_path)?;
    key_file.write_all(pem::encode(&key_pem).as_bytes())?;
    key_file.flush()?;

    // Set restrictive permissions (0600)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(key_path)?.permissions();
        perms.set_mode(0o600);
        std::fs::set_permissions(key_path, perms)?;
    }

    Ok(())
}

/// Parse a comma-separated SAN list into IP addresses and DNS names.
fn parse_san_list(san_list: &str) -> KbsResult<Vec<String>> {
    let mut sans = Vec::new();

    for san in san_list.split(',') {
        let san = san.trim();
        if !san.is_empty() {
            sans.push(san.to_string());
        }
    }

    if sans.is_empty() {
        // Add default localhost entries if SAN list is empty
        sans.push("127.0.0.1".to_string());
        sans.push("localhost".to_string());
    }

    Ok(sans)
}

#[cfg(test)]
#[path = "x509_tests.rs"]
mod x509_tests;
