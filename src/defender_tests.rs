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
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::time::Duration;

    #[tokio::test]
    async fn test_defender_creation() {
        let defender = Defender::new(5, Duration::from_secs(60), Duration::from_secs(300));
        assert_eq!(defender.client_count().await, 0);
        assert_eq!(defender.banned_count().await, 0);
    }

    #[tokio::test]
    async fn test_defender_from_config() {
        let defender = Defender::from_config(5, 5, 15).unwrap();
        assert_eq!(defender.client_count().await, 0);
    }

    #[tokio::test]
    async fn test_defender_from_config_invalid() {
        let result = Defender::from_config(0, 5, 15);
        assert!(result.is_err());

        let result = Defender::from_config(5, 0, 15);
        assert!(result.is_err());

        let result = Defender::from_config(5, 5, 0);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_defender_ban_username() {
        let defender = Defender::new(2, Duration::from_secs(1), Duration::from_secs(5));

        let key = ClientKey::username("test_user");

        // First attempt - not banned
        assert!(!defender.inc(key.clone()).await);
        assert!(!defender.is_banned(&key).await);

        // Second attempt - not banned yet
        assert!(!defender.inc(key.clone()).await);
        assert!(!defender.is_banned(&key).await);

        // Third attempt - should be banned
        assert!(defender.inc(key.clone()).await);
        assert!(defender.is_banned(&key).await);

        // Check ban list
        let ban_list = defender.ban_list().await;
        assert_eq!(ban_list.len(), 1);
        assert_eq!(ban_list[0].key, key);
    }

    #[tokio::test]
    async fn test_defender_ban_ip() {
        let defender = Defender::new(2, Duration::from_secs(1), Duration::from_secs(5));

        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let key = ClientKey::ip_addr(ip);

        // First attempt - not banned
        assert!(!defender.inc(key.clone()).await);

        // Second attempt - not banned yet
        assert!(!defender.inc(key.clone()).await);

        // Third attempt - should be banned
        assert!(defender.inc(key.clone()).await);
        assert!(defender.is_banned(&key).await);
    }

    #[tokio::test]
    async fn test_defender_remove_client() {
        let defender = Defender::new(2, Duration::from_secs(1), Duration::from_secs(5));

        let key = ClientKey::username("test_user");

        // Add some attempts
        defender.inc(key.clone()).await;
        assert_eq!(defender.client_count().await, 1);

        // Remove client
        defender.remove_client(&key).await;
        assert_eq!(defender.client_count().await, 0);
        assert!(!defender.is_banned(&key).await);
    }

    #[tokio::test]
    async fn test_defender_cleanup() {
        let defender = Defender::new(2, Duration::from_millis(100), Duration::from_secs(5));

        let key1 = ClientKey::username("user1");
        let key2 = ClientKey::username("user2");

        // Add attempts
        defender.inc(key1.clone()).await;
        defender.inc(key2.clone()).await;

        assert_eq!(defender.client_count().await, 2);

        // Wait for expiration and cleanup
        tokio::time::sleep(Duration::from_millis(500)).await;
        defender.cleanup().await;

        // Clients should be cleaned up
        assert_eq!(defender.client_count().await, 0);
    }

    #[tokio::test]
    async fn test_defender_separate_clients() {
        let defender = Defender::new(2, Duration::from_secs(1), Duration::from_secs(5));

        let key1 = ClientKey::username("user1");
        let key2 = ClientKey::username("user2");

        // Ban first user
        defender.inc(key1.clone()).await;
        defender.inc(key1.clone()).await;
        defender.inc(key1.clone()).await;

        // Second user should not be affected
        assert!(!defender.is_banned(&key2).await);
        assert!(defender.is_banned(&key1).await);
    }

    #[tokio::test]
    async fn test_client_key_username() {
        let key = ClientKey::username("test_user");
        assert!(matches!(key, ClientKey::Username(_)));
    }

    #[tokio::test]
    async fn test_client_key_ip_addr() {
        let ip = IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1));
        let key = ClientKey::ip_addr(ip);
        assert!(matches!(key, ClientKey::IpAddr(_)));
    }
}
