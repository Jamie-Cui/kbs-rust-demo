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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zeroize_byte_array() {
        let mut secret = vec![0x41, 0x42, 0x43];
        zeroize_byte_array(&mut secret);
        assert!(secret.iter().all(|&b| b == 0));
    }

    #[test]
    fn test_zeroize_bytes() {
        let mut data = [0x41, 0x42, 0x43];
        zeroize_bytes(&mut data);
        assert!(data.iter().all(|&b| b == 0));
    }

    #[test]
    fn test_zeroize_string() {
        let mut secret = String::from("my secret password");
        zeroize_string(&mut secret);
        // After zeroization, the string should be empty (zeroized)
        assert!(secret.is_empty() || secret.chars().all(|c| c == '\0'));
    }

    #[test]
    fn test_secure_bytes() {
        let mut secure = SecureBytes::new(vec![0x41, 0x42, 0x43]);
        assert_eq!(secure.as_bytes(), &[0x41, 0x42, 0x43]);
        assert_eq!(secure.len(), 3);
        assert!(!secure.is_empty());
    }

    #[test]
    fn test_secure_bytes_as_mut() {
        let mut secure = SecureBytes::new(vec![0x41, 0x42, 0x43]);
        secure.as_bytes_mut()[0] = 0xFF;
        assert_eq!(secure.as_bytes()[0], 0xFF);
    }

    #[test]
    fn test_secure_bytes_into_inner() {
        let secure = SecureBytes::new(vec![0x41, 0x42, 0x43]);
        let bytes = secure.into_inner();
        assert_eq!(bytes, vec![0x41, 0x42, 0x43]);
    }

    #[test]
    fn test_secure_string() {
        let secure = SecureString::new(String::from("my secret"));
        assert_eq!(secure.as_str(), "my secret");
        assert_eq!(secure.len(), 9);
        assert!(!secure.is_empty());
    }

    #[test]
    fn test_secure_string_into_inner() {
        let secure = SecureString::new(String::from("my secret"));
        let s = secure.into_inner();
        assert_eq!(s, "my secret");
    }

    #[test]
    fn test_secure_bytes_as_ref() {
        let secure = SecureBytes::new(vec![0x41, 0x42, 0x43]);
        let bytes: &[u8] = secure.as_ref();
        assert_eq!(bytes, &[0x41, 0x42, 0x43]);
    }

    #[test]
    fn test_secure_string_as_ref() {
        let secure = SecureString::new(String::from("my secret"));
        let s: &str = secure.as_ref();
        assert_eq!(s, "my secret");
    }
}
