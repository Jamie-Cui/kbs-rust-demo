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
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn test_generate_jwt_signing_key() {
        let temp_dir = TempDir::new().unwrap();
        let key_path = temp_dir.path().join("jwt-signing.key");

        let result = generate_jwt_signing_key(key_path.to_str().unwrap());
        assert!(result.is_ok());

        // Verify file exists
        assert!(key_path.exists());

        // Verify it's a valid PEM file
        let contents = fs::read_to_string(&key_path).unwrap();
        assert!(contents.contains("-----BEGIN PRIVATE KEY-----"));
        assert!(contents.contains("-----END PRIVATE KEY-----"));
    }

    #[test]
    fn test_generate_tls_certificate() {
        let temp_dir = TempDir::new().unwrap();
        let cert_path = temp_dir.path().join("tls.crt");
        let key_path = temp_dir.path().join("tls.key");

        let result = generate_tls_certificate(
            cert_path.to_str().unwrap(),
            key_path.to_str().unwrap(),
            "127.0.0.1,localhost",
        );
        assert!(result.is_ok());

        // Verify files exist
        assert!(cert_path.exists());
        assert!(key_path.exists());

        // Verify certificate is a valid PEM file
        let cert_contents = fs::read_to_string(&cert_path).unwrap();
        assert!(cert_contents.contains("-----BEGIN CERTIFICATE-----"));
        assert!(cert_contents.contains("-----END CERTIFICATE-----"));

        // Verify key is a valid PEM file
        let key_contents = fs::read_to_string(&key_path).unwrap();
        assert!(key_contents.contains("-----BEGIN PRIVATE KEY-----"));
        assert!(key_contents.contains("-----END PRIVATE KEY-----"));
    }

    #[test]
    fn test_parse_san_list() {
        // Test with IP addresses and DNS names
        let sans = parse_san_list("127.0.0.1,localhost,kbs.example.com").unwrap();
        assert_eq!(sans.len(), 3);
        assert_eq!(sans[0], "127.0.0.1");
        assert_eq!(sans[1], "localhost");
        assert_eq!(sans[2], "kbs.example.com");
    }

    #[test]
    fn test_parse_san_list_empty() {
        // Empty list should use defaults
        let sans = parse_san_list("").unwrap();
        assert!(!sans.is_empty()); // Should have defaults
        assert_eq!(sans.len(), 2); // 127.0.0.1 and localhost
    }

    #[test]
    fn test_parse_san_list_whitespace() {
        // Test with extra whitespace
        let sans = parse_san_list(" 127.0.0.1 , localhost ").unwrap();
        assert_eq!(sans.len(), 2);
    }
}
