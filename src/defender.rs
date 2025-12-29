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
//! Defender module for authentication rate limiting and brute force protection.
//!
//! This module provides functionality to track and limit authentication attempts,
//! temporarily banning clients that exceed a configured threshold.
//!
//! # Example
//!
//! ```rust
//! use gta_kbs::defender::Defender;
//! use std::time::Duration;
//!
//! let defender = Defender::new(5, Duration::from_secs(60), Duration::from_secs(300));
//!
//! // Track authentication attempts by username
//! if defender.inc("test_user") {
//!     println!("User has been banned due to too many attempts");
//! }
//! ```

use crate::error::{KbsError, KbsResult};
use governor::{
    clock::DefaultClock,
    state::{InMemoryState, NotKeyed},
    Quota, RateLimiter,
};
use std::collections::HashMap;
use std::net::IpAddr;
use std::num::NonZeroU32;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

/// Factor for calculating cleanup interval
const DEFENDER_FACTOR: u32 = 10;

/// Client information tracked by the defender
#[derive(Debug, Clone)]
pub struct Client {
    /// The key that identifies this client (username or IP)
    pub key: ClientKey,
    /// When this client's ban expires
    pub expire: Option<Instant>,
    /// Whether this client is currently banned
    pub banned: bool,
}

/// Key that identifies a client for rate limiting
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ClientKey {
    /// Username-based identification
    Username(String),
    /// IP address-based identification
    IpAddr(IpAddr),
}

impl ClientKey {
    /// Create a new username-based client key
    pub fn username(username: impl Into<String>) -> Self {
        ClientKey::Username(username.into())
    }

    /// Create a new IP-based client key
    pub fn ip_addr(ip: IpAddr) -> Self {
        ClientKey::IpAddr(ip)
    }
}

impl Client {
    /// Create a new client
    pub fn new(key: ClientKey) -> Self {
        Client {
            key,
            expire: None,
            banned: false,
        }
    }

    /// Check if the client's ban has expired
    pub fn ban_expired(&self) -> bool {
        if !self.banned {
            return false;
        }
        if let Some(expire) = self.expire {
            Instant::now() > expire
        } else {
            false
        }
    }
}

/// Defender provides rate limiting and brute force protection for authentication.
///
/// It tracks authentication attempts per client (username or IP) and can temporarily
/// ban clients that exceed the configured threshold.
#[derive(Clone)]
pub struct Defender {
    /// Clients being tracked
    clients: Arc<RwLock<HashMap<ClientKey, ClientData>>>,
    /// Maximum number of attempts allowed within the duration
    max_attempts: u32,
    /// Time window for rate limiting
    duration: Duration,
    /// How long a ban lasts
    ban_duration: Duration,
}

/// Internal client data
#[derive(Debug)]
struct ClientData {
    /// Rate limiter for this client
    limiter: RateLimiter<NotKeyed, InMemoryState, DefaultClock>,
    /// When this client's data should expire (for cleanup)
    expire: Instant,
    /// Whether this client is currently banned
    banned: bool,
    /// When the ban expires
    ban_expire: Option<Instant>,
}

impl Defender {
    /// Create a new Defender.
    ///
    /// # Arguments
    ///
    /// * `max_attempts` - Maximum number of attempts allowed within the duration window
    /// * `duration` - Time window for rate limiting (e.g., 1 minute)
    /// * `ban_duration` - How long to ban a client who exceeds the limit
    ///
    /// # Example
    ///
    /// ```rust
    /// use gta_kbs::defender::Defender;
    /// use std::time::Duration;
    ///
    /// // Allow 5 attempts per minute, ban for 15 minutes on exceeding
    /// let defender = Defender::new(5, Duration::from_secs(60), Duration::from_secs(900));
    /// ```
    pub fn new(max_attempts: u32, duration: Duration, ban_duration: Duration) -> Self {
        Defender {
            clients: Arc::new(RwLock::new(HashMap::new())),
            max_attempts,
            duration,
            ban_duration,
        }
    }

    /// Check if a client is currently banned.
    ///
    /// # Arguments
    ///
    /// * `key` - The client key to check
    pub async fn is_banned(&self, key: &ClientKey) -> bool {
        let clients = self.clients.read().await;
        if let Some(data) = clients.get(key) {
            if data.banned {
                if let Some(expire) = data.ban_expire {
                    return Instant::now() < expire;
                }
            }
        }
        false
    }

    /// Increment the attempt counter for a client.
    ///
    /// Returns `true` if the client has just been banned due to exceeding the limit.
    ///
    /// # Arguments
    ///
    /// * `key` - The client key to increment
    pub async fn inc(&self, key: ClientKey) -> bool {
        let mut clients = self.clients.write().await;
        let now = Instant::now();

        // Get or create client data
        let data = clients.entry(key.clone()).or_insert_with(|| {
            let burst_size = NonZeroU32::new(self.max_attempts).unwrap();
            let quota = Quota::with_period(self.duration / self.max_attempts as u32)
                .unwrap_or_else(|| Quota::per_second(NonZeroU32::new(1).unwrap()))
                .allow_burst(burst_size);

            ClientData {
                limiter: RateLimiter::direct(quota),
                expire: now + self.duration * DEFENDER_FACTOR as u32,
                banned: false,
                ban_expire: None,
            }
        });

        // Check if ban has expired
        if data.banned {
            if let Some(expire) = data.ban_expire {
                if now > expire {
                    data.banned = false;
                    data.ban_expire = None;
                } else {
                    // Still banned
                    return false;
                }
            }
        }

        // Update expiration
        data.expire = now + self.duration * DEFENDER_FACTOR as u32;

        // Check rate limit - check returns Result<(), NotUntil>
        if data.limiter.check().is_err() {
            // Exceeded rate limit - ban the client
            data.banned = true;
            data.ban_expire = Some(now + self.ban_duration);
            return true;
        }

        false
    }

    /// Get the ban list (all currently banned clients).
    pub async fn ban_list(&self) -> Vec<Client> {
        let clients = self.clients.read().await;
        let now = Instant::now();

        clients
            .iter()
            .filter(|(_, data)| {
                data.banned
                    && data
                        .ban_expire
                        .map_or(false, |expire| now < expire)
            })
            .map(|(key, data)| Client {
                key: key.clone(),
                expire: data.ban_expire,
                banned: true,
            })
            .collect()
    }

    /// Remove a client from tracking (e.g., after successful auth).
    pub async fn remove_client(&self, key: &ClientKey) {
        let mut clients = self.clients.write().await;
        clients.remove(key);
    }

    /// Clean up expired client data.
    ///
    /// Should be called periodically to prevent memory leaks.
    pub async fn cleanup(&self) {
        let mut clients = self.clients.write().await;
        let now = Instant::now();

        clients.retain(|_, data| now < data.expire);
    }

    /// Get the number of clients currently being tracked.
    pub async fn client_count(&self) -> usize {
        let clients = self.clients.read().await;
        clients.len()
    }

    /// Get the number of currently banned clients.
    pub async fn banned_count(&self) -> usize {
        let clients = self.clients.read().await;
        let now = Instant::now();

        clients
            .values()
            .filter(|data| {
                data.banned && data.ban_expire.map_or(false, |expire| now < expire)
            })
            .count()
    }
}

/// Wrapper to create a defender from config values
impl Defender {
    /// Create a defender from configuration values.
    ///
    /// # Arguments
    ///
    /// * `max_attempts` - Maximum attempts from config
    /// * `interval_minutes` - Interval in minutes from config
    /// * `lockout_minutes` - Lockout duration in minutes from config
    pub fn from_config(
        max_attempts: u32,
        interval_minutes: u64,
        lockout_minutes: u64,
    ) -> KbsResult<Self> {
        if max_attempts < 1 {
            return Err(KbsError::Config(
                "Authentication defend max attempts must be at least 1".into(),
            ));
        }
        if interval_minutes < 1 {
            return Err(KbsError::Config(
                "Authentication defend interval minutes must be at least 1".into(),
            ));
        }
        if lockout_minutes < 1 {
            return Err(KbsError::Config(
                "Authentication defend lockout minutes must be at least 1".into(),
            ));
        }

        Ok(Defender::new(
            max_attempts,
            Duration::from_secs(interval_minutes * 60),
            Duration::from_secs(lockout_minutes * 60),
        ))
    }
}

#[cfg(test)]
#[path = "defender_tests.rs"]
mod defender_tests;
