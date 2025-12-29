/*
 *   Copyright (c) 2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

//! RSA encryption utilities (RSA-OAEP).

use rsa::{
    Oaep,
    sha2::Sha256,
};
use crate::error::{KbsError, KbsResult};

// Re-export RSA types for convenience
pub use rsa::{RsaPrivateKey, RsaPublicKey};

/// Wrap data using RSA-OAEP with SHA-256.
///
/// This is used to wrap the Symmetric Wrapping Key (SWK) with the public key
/// from the attested workload.
///
/// # Arguments
/// * `data` - Data to wrap (typically the SWK)
/// * `public_key` - RSA public key
///
/// # Returns
/// The wrapped data as bytes.
pub fn rsa_oaep_wrap(data: &[u8], public_key: &RsaPublicKey) -> KbsResult<Vec<u8>> {
    let mut rng = rand::thread_rng();
    let padding = Oaep::new::<Sha256>();

    let wrapped = public_key
        .encrypt(&mut rng, padding, data)
        .map_err(|e| KbsError::Crypto(format!("RSA-OAEP encryption failed: {}", e)))?;

    Ok(wrapped)
}

/// Unwrap data using RSA-OAEP with SHA-256.
///
/// # Arguments
/// * `wrapped_data` - Wrapped data to unwrap
/// * `private_key` - RSA private key
///
/// # Returns
/// The unwrapped data.
pub fn rsa_oaep_unwrap(wrapped_data: &[u8], private_key: &RsaPrivateKey) -> KbsResult<Vec<u8>> {
    let padding = Oaep::new::<Sha256>();

    let unwrapped = private_key
        .decrypt(padding, wrapped_data)
        .map_err(|e| KbsError::Crypto(format!("RSA-OAEP decryption failed: {}", e)))?;

    Ok(unwrapped)
}

/// Parse an RSA public key from attester held data.
///
/// The attester held data contains the RSA public key in a specific format:
/// - 4 bytes: exponent (little-endian u32)
/// - Remaining bytes: modulus
///
/// For SGX, the modulus is in little-endian format and needs to be swapped.
///
/// # Arguments
/// * `data` - Base64-encoded attester held data
/// * `is_sgx` - Whether this is from SGX (affects endianness)
///
/// # Returns
/// The parsed RSA public key.
pub fn parse_public_key_from_attester_data(
    data: &str,
    is_sgx: bool,
) -> KbsResult<RsaPublicKey> {
    use base64::Engine as _;
    let key_bytes = base64::engine::general_purpose::STANDARD.decode(data)
        .map_err(|e| KbsError::Crypto(format!("Failed to decode attester data: {}", e)))?;

    if key_bytes.len() < 8 {
        return Err(KbsError::Crypto(
            "Attester data too short to contain public key".into(),
        ));
    }

    // First 4 bytes are the exponent (little-endian)
    let exp_bytes = arrayref::array_ref![key_bytes, 0, 4];
    let exp = u32::from_le_bytes(*exp_bytes);

    // Remaining bytes are the modulus
    let mut mod_bytes = key_bytes[4..].to_vec();

    // For SGX, the modulus is in little-endian format - reverse it
    if is_sgx {
        mod_bytes.reverse();
    }

    // Validate minimum key size (2048 bits = 256 bytes)
    if mod_bytes.len() * 8 < 2048 {
        return Err(KbsError::Crypto(
            "RSA key size must be at least 2048 bits".into(),
        ));
    }

    // Create the public key
    let public_key = RsaPublicKey::new(
        rsa::BigUint::from_bytes_be(&mod_bytes),
        rsa::BigUint::from(exp),
    )
    .map_err(|e| KbsError::Crypto(format!("Failed to create RSA public key: {}", e)))?;

    Ok(public_key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rsa_wrap_unwrap() {
        use rsa::RsaPrivateKey;

        // Generate a key pair for testing
        let mut rng = rand::thread_rng();
        let private_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let public_key = private_key.to_public_key();

        let data = b"secret key material";

        // Wrap and unwrap
        let wrapped = rsa_oaep_wrap(data, &public_key).unwrap();
        let unwrapped = rsa_oaep_unwrap(&wrapped, &private_key).unwrap();

        assert_eq!(data.to_vec(), unwrapped);
    }
}
