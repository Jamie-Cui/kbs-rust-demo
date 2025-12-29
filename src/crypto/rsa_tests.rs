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
use base64::Engine;

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

#[test]
fn test_rsa_wrap_unwrap_different_key_sizes() {
    use rsa::RsaPrivateKey;

    for bits in [2048, 3072, 4096] {
        let mut rng = rand::thread_rng();
        let private_key = RsaPrivateKey::new(&mut rng, bits).unwrap();
        let public_key = private_key.to_public_key();

        let data = b"test data for RSA wrapping";

        let wrapped = rsa_oaep_wrap(data, &public_key).unwrap();
        let unwrapped = rsa_oaep_unwrap(&wrapped, &private_key).unwrap();

        assert_eq!(data.to_vec(), unwrapped);
    }
}

#[test]
fn test_rsa_wrap_unwrap_with_different_key() {
    use rsa::RsaPrivateKey;

    let mut rng = rand::thread_rng();
    let private_key1 = RsaPrivateKey::new(&mut rng, 2048).unwrap();
    let public_key1 = private_key1.to_public_key();
    let private_key2 = RsaPrivateKey::new(&mut rng, 2048).unwrap();
    let public_key2 = private_key2.to_public_key();

    let data = b"secret message";

    let wrapped = rsa_oaep_wrap(data, &public_key1).unwrap();

    // Try to unwrap with different key
    let result = rsa_oaep_unwrap(&wrapped, &private_key2);
    assert!(result.is_err());
}

#[test]
fn test_parse_public_key_from_attester_data_sgx() {
    use rsa::RsaPrivateKey;
    use rsa::traits::PublicKeyParts;

    // Generate a test key
    let mut rng = rand::thread_rng();
    let private_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
    let public_key = private_key.to_public_key();

    // Convert to the format expected by parse_public_key_from_attester_data
    let modulus_be = public_key.n().to_bytes_be();
    let exp_be = public_key.e().to_bytes_be();

    // Pad/truncate exp to 4 bytes (little-endian)
    let mut exp_bytes = [0u8; 4];
    let exp_len = exp_be.len().min(4);
    // Copy the last bytes of exp_be (which is the little-endian representation of BigUint)
    let start = exp_be.len().saturating_sub(4);
    exp_bytes[..exp_be.len() - start].copy_from_slice(&exp_be[start..]);

    // Get modulus and reverse for little-endian (SGX format)
    let mut modulus = modulus_be;
    modulus.reverse();

    let mut key_bytes = Vec::new();
    key_bytes.extend_from_slice(&exp_bytes);
    key_bytes.extend_from_slice(&modulus);

    let encoded = base64::engine::general_purpose::STANDARD.encode(&key_bytes);

    // Parse the key
    let parsed = parse_public_key_from_attester_data(&encoded, true).unwrap();

    assert_eq!(parsed.e(), public_key.e());
}

#[test]
fn test_parse_public_key_from_attester_data_tdx() {
    use rsa::RsaPrivateKey;
    use rsa::traits::PublicKeyParts;

    // Generate a test key
    let mut rng = rand::thread_rng();
    let private_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
    let public_key = private_key.to_public_key();

    // Convert to the format expected by parse_public_key_from_attester_data
    let modulus_be = public_key.n().to_bytes_be();
    let exp_be = public_key.e().to_bytes_be();

    // Pad/truncate exp to 4 bytes (little-endian)
    let mut exp_bytes = [0u8; 4];
    let exp_len = exp_be.len().min(4);
    let start = exp_be.len().saturating_sub(4);
    exp_bytes[..exp_be.len() - start].copy_from_slice(&exp_be[start..]);

    let mut key_bytes = Vec::new();
    key_bytes.extend_from_slice(&exp_bytes);
    key_bytes.extend_from_slice(&modulus_be);

    let encoded = base64::engine::general_purpose::STANDARD.encode(&key_bytes);

    // Parse the key (TDX - not SGX, so don't reverse)
    let parsed = parse_public_key_from_attester_data(&encoded, false).unwrap();

    assert_eq!(parsed.e(), public_key.e());
}

#[test]
fn test_parse_public_key_invalid_base64() {
    let result = parse_public_key_from_attester_data("invalid-base64!!", true);
    assert!(result.is_err());
}

#[test]
fn test_parse_public_key_too_short() {
    let short_data = base64::engine::general_purpose::STANDARD.encode(&[1, 2, 3, 4]);
    let result = parse_public_key_from_attester_data(&short_data, true);
    assert!(result.is_err());
}

#[test]
fn test_rsa_large_data() {
    use rsa::RsaPrivateKey;

    let mut rng = rand::thread_rng();
    let private_key = RsaPrivateKey::new(&mut rng, 4096).unwrap();
    let public_key = private_key.to_public_key();

    // Max data size for RSA-OAEP with SHA-256 is key_size - 2*hash_size - 2
    // For 4096-bit key: 512 - 2*32 - 2 = 446 bytes
    let data = vec![0xABu8; 200];

    let wrapped = rsa_oaep_wrap(&data, &public_key).unwrap();
    let unwrapped = rsa_oaep_unwrap(&wrapped, &private_key).unwrap();

    assert_eq!(data, unwrapped);
}
