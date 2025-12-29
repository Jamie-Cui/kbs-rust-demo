
use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use crate::error::{KbsError, KbsResult};

/// AES-256-GCM key size (32 bytes).
pub const AES_256_KEY_SIZE: usize = 32;

/// Generate a random AES-256 key.
pub fn generate_aes_key() -> KbsResult<[u8; AES_256_KEY_SIZE]> {
    let key = Aes256Gcm::generate_key(&mut OsRng);
    Ok(key.into())
}

/// Generate a random AES key with specified size.
///
/// # Arguments
/// * `size` - Key size in bytes (16 for AES-128, 24 for AES-192, 32 for AES-256)
///
/// # Returns
/// A vector containing the random key bytes.
pub fn generate_aes_key_with_size(size: usize) -> KbsResult<Vec<u8>> {
    // Validate size
    if ![16, 24, 32].contains(&size) {
        return Err(KbsError::Crypto(format!(
            "Invalid AES key size: {}. Must be 16 (AES-128), 24 (AES-192), or 32 (AES-256) bytes",
            size
        )));
    }

    let mut key = vec![0u8; size];
    use rand::RngCore;
    OsRng.fill_bytes(&mut key);
    Ok(key)
}

/// Encrypt data using AES-256-GCM.
///
/// # Arguments
/// * `data` - Data to encrypt
/// * `key` - 32-byte AES-256 key
///
/// # Returns
/// A tuple of (nonce, ciphertext). The nonce is 12 bytes.
pub fn aes_gcm_encrypt(data: &[u8], key: &[u8; AES_256_KEY_SIZE]) -> KbsResult<(Vec<u8>, Vec<u8>)> {
    let cipher = Aes256Gcm::new(key.into());
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

    let ciphertext = cipher
        .encrypt(&nonce, data)
        .map_err(|e| KbsError::Crypto(format!("AES-GCM encryption failed: {}", e)))?;

    Ok((nonce.to_vec(), ciphertext))
}

/// Decrypt data using AES-256-GCM.
///
/// # Arguments
/// * `ciphertext` - Data to decrypt
/// * `nonce` - 12-byte nonce
/// * `key` - 32-byte AES-256 key
///
/// # Returns
/// The decrypted plaintext.
pub fn aes_gcm_decrypt(
    ciphertext: &[u8],
    nonce: &[u8],
    key: &[u8; AES_256_KEY_SIZE],
) -> KbsResult<Vec<u8>> {
    let cipher = Aes256Gcm::new(key.into());
    let nonce = Nonce::from_slice(nonce);

    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| KbsError::Crypto(format!("AES-GCM decryption failed: {}", e)))?;

    Ok(plaintext)
}

/// Zeroize a byte array in memory.
pub fn zeroize(data: &mut [u8]) {
    for byte in data.iter_mut() {
        *byte = 0;
    }
}
