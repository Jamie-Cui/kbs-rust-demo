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
//! Zeroization utilities for secure memory handling.
//!
//! This module provides functions to securely clear sensitive data from memory.
//! It uses the `zeroize` crate which employs best practices to ensure data is
//! actually zeroed and not optimized away by the compiler.

use zeroize::{Zeroize, ZeroizeOnDrop};

/// Securely zero out a byte array.
///
/// This function overwrites the contents of the byte array with zeros
/// before it goes out of scope. The `zeroize` crate ensures the compiler
/// won't optimize this away.
///
/// # Example
///
/// ```rust
/// use gta_kbs::crypto::zeroize::zeroize_byte_array;
///
/// let mut secret = vec![0x41, 0x42, 0x43]; // "ABC"
/// zeroize_byte_array(&mut secret);
/// // secret is now all zeros
/// assert!(secret.iter().all(|&b| b == 0));
/// ```
pub fn zeroize_byte_array(bytes: &mut Vec<u8>) {
    bytes.zeroize();
}

/// Securely zero out a byte slice.
///
/// This is a convenience function for working with slices.
pub fn zeroize_bytes(bytes: &mut [u8]) {
    bytes.zeroize();
}

/// Securely zero out a string.
///
/// # Example
///
/// ```rust
/// use gta_kbs::crypto::zeroize::zeroize_string;
///
/// let mut secret = String::from("my secret password");
/// zeroize_string(&mut secret);
/// // secret is now an empty string (all zeros cleared)
/// assert!(secret.is_empty());
/// ```
pub fn zeroize_string(s: &mut String) {
    s.zeroize();
}

/// Zeroizable wrapper for byte arrays.
///
/// This type implements `Drop` to automatically zero its contents
/// when it goes out of scope.
///
/// # Example
///
/// ```rust
/// use gta_kbs::crypto::zeroize::SecureBytes;
///
/// {
///     let mut secure = SecureBytes::new(vec![0x41, 0x42, 0x43]);
///     // ... use the secure data ...
/// } // secure is automatically zeroed here
/// ```
#[derive(Debug, Clone)]
pub struct SecureBytes {
    bytes: Vec<u8>,
}

impl Drop for SecureBytes {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

impl ZeroizeOnDrop for SecureBytes {}

impl SecureBytes {
    /// Create a new secure bytes container.
    pub fn new(bytes: Vec<u8>) -> Self {
        SecureBytes { bytes }
    }

    /// Get a reference to the inner bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Get a mutable reference to the inner bytes.
    pub fn as_bytes_mut(&mut self) -> &mut [u8] {
        &mut self.bytes
    }

    /// Consume and return the inner bytes.
    ///
    /// Warning: The caller is responsible for zeroizing the returned bytes.
    pub fn into_inner(mut self) -> Vec<u8> {
        let bytes = std::mem::take(&mut self.bytes);
        bytes
    }

    /// Check if the secure bytes are empty.
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Get the length of the secure bytes.
    pub fn len(&self) -> usize {
        self.bytes.len()
    }
}

impl AsRef<[u8]> for SecureBytes {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

impl AsMut<[u8]> for SecureBytes {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.bytes
    }
}

/// Zeroizable wrapper for strings.
///
/// This type implements `Drop` to automatically zero its contents
/// when it goes out of scope.
#[derive(Debug, Clone)]
pub struct SecureString {
    s: String,
}

impl Drop for SecureString {
    fn drop(&mut self) {
        self.s.zeroize();
    }
}

impl ZeroizeOnDrop for SecureString {}

impl SecureString {
    /// Create a new secure string container.
    pub fn new(s: String) -> Self {
        SecureString { s }
    }

    /// Get a reference to the inner string.
    pub fn as_str(&self) -> &str {
        &self.s
    }

    /// Get a mutable reference to the inner string.
    pub fn as_str_mut(&mut self) -> &mut str {
        &mut self.s
    }

    /// Consume and return the inner string.
    ///
    /// Warning: The caller is responsible for zeroizing the returned string.
    pub fn into_inner(mut self) -> String {
        let s = std::mem::take(&mut self.s);
        s
    }

    /// Check if the secure string is empty.
    pub fn is_empty(&self) -> bool {
        self.s.is_empty()
    }

    /// Get the length of the secure string.
    pub fn len(&self) -> usize {
        self.s.len()
    }
}

impl AsRef<str> for SecureString {
    fn as_ref(&self) -> &str {
        &self.s
    }
}

#[cfg(test)]
#[path = "zeroize_tests.rs"]
mod zeroize_tests;
