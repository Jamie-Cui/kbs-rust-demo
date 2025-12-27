/*
 *   Copyright (c) 2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

//! Configuration management for the KBS service.

use crate::{
    constant::{
        DEFAULT_AUTH_DEFEND_INTERVAL_MINUTES, DEFAULT_AUTH_DEFEND_LOCKOUT_MINUTES,
        DEFAULT_AUTH_DEFEND_MAX_ATTEMPTS, DEFAULT_BEARER_TOKEN_VALIDITY_MINUTES,
        DEFAULT_HTTP_READ_HEADER_TIMEOUT, DEFAULT_LOG_LEVEL, DEFAULT_SERVICE_PORT,
        MAX_TOKEN_VALIDITY_MINUTES, MIN_TOKEN_VALIDITY_MINUTES,
    },
    error::{KbsError, KbsResult},
};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

/// Main configuration structure.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Configuration {
    /// Service port
    #[serde(default = "default_service_port")]
    pub service_port: u16,

    /// Log level
    #[serde(default = "default_log_level")]
    pub log_level: String,

    /// Log caller
    #[serde(default)]
    pub log_caller: bool,

    /// Trust Authority base URL
    #[serde(rename = "trustauthority-base-url")]
    pub trust_authority_base_url: String,

    /// Trust Authority API URL
    #[serde(rename = "trustauthority-api-url")]
    pub trust_authority_api_url: String,

    /// Trust Authority API key (base64 encoded)
    #[serde(rename = "trustauthority-api-key")]
    pub trust_authority_api_key: String,

    /// Key manager type (VAULT or KMIP)
    #[serde(default = "default_key_manager", rename = "key-manager")]
    pub key_manager: String,

    /// Admin username
    #[serde(rename = "admin-username")]
    pub admin_username: String,

    /// Admin password
    #[serde(rename = "admin-password")]
    pub admin_password: String,

    /// SAN list for TLS certificate
    #[serde(default, rename = "san-list")]
    pub san_list: Option<String>,

    /// KMIP configuration
    #[serde(default)]
    pub kmip: KmipConfig,

    /// Vault configuration
    #[serde(default)]
    pub vault: VaultConfig,

    /// Bearer token validity in minutes
    #[serde(
        default = "default_bearer_token_validity",
        rename = "bearer-token-validity-in-minutes"
    )]
    pub bearer_token_validity_in_minutes: i64,

    /// HTTP read header timeout in seconds
    #[serde(
        default = "default_http_read_header_timeout",
        rename = "http-read-header-timeout"
    )]
    pub http_read_header_timeout: u64,

    /// Authentication defend max attempts
    #[serde(
        default = "default_auth_defend_max_attempts",
        rename = "authentication-defend-max-attempts"
    )]
    pub authentication_defend_max_attempts: u32,

    /// Authentication defend interval in minutes
    #[serde(
        default = "default_auth_defend_interval_minutes",
        rename = "authentication-defend-interval-minutes"
    )]
    pub authentication_defend_interval_minutes: u64,

    /// Authentication defend lockout in minutes
    #[serde(
        default = "default_auth_defend_lockout_minutes",
        rename = "authentication-defend-lockout-minutes"
    )]
    pub authentication_defend_lockout_minutes: u64,
}

/// KMIP configuration.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct KmipConfig {
    /// KMIP version
    pub version: Option<String>,

    /// KMIP server IP
    #[serde(rename = "server-ip")]
    pub server_ip: Option<String>,

    /// KMIP server port
    #[serde(rename = "server-port")]
    pub server_port: Option<String>,

    /// KMIP hostname
    pub hostname: Option<String>,

    /// KMIP username
    pub username: Option<String>,

    /// KMIP password
    pub password: Option<String>,

    /// KMIP client key path
    #[serde(rename = "client-key-path")]
    pub client_key_path: Option<String>,

    /// KMIP client certificate path
    #[serde(rename = "client-cert-path")]
    pub client_cert_path: Option<String>,

    /// KMIP root certificate path
    #[serde(rename = "root-cert-path")]
    pub root_cert_path: Option<String>,
}

/// Vault configuration.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct VaultConfig {
    /// Vault server IP
    #[serde(rename = "server-ip")]
    pub server_ip: Option<String>,

    /// Vault server port
    #[serde(rename = "server-port")]
    pub server_port: Option<String>,

    /// Vault client token
    #[serde(rename = "client-token")]
    pub client_token: Option<String>,
}

impl Configuration {
    /// Load configuration from environment variables.
    pub fn from_env() -> KbsResult<Self> {
        let mut config = config::Config::builder()
            .set_default("service_port", default_service_port())?
            .set_default("log_level", default_log_level())?
            .set_default("log_caller", false)?
            .set_default(
                "bearer_token_validity_in_minutes",
                default_bearer_token_validity(),
            )?
            .set_default(
                "http_read_header_timeout",
                default_http_read_header_timeout(),
            )?
            .set_default(
                "authentication_defend_max_attempts",
                default_auth_defend_max_attempts(),
            )?
            .set_default(
                "authentication_defend_interval_minutes",
                default_auth_defend_interval_minutes(),
            )?
            .set_default(
                "authentication_defend_lockout_minutes",
                default_auth_defend_lockout_minutes(),
            )?
            .set_default("key_manager", default_key_manager())?;

        // Add environment variables with underscores replacing hyphens/dots
        config = config
            .set_override(
                "service_port",
                std::env::var("SERVICE_PORT")
                    .ok()
                    .or_else(|| std::env::var("SERVICE.PORT").ok()),
            )?
            .set_override(
                "log_level",
                std::env::var("LOG_LEVEL")
                    .ok()
                    .or_else(|| std::env::var("LOG.LEVEL").ok()),
            )?
            .set_override(
                "log_caller",
                std::env::var("LOG_CALLER")
                    .ok()
                    .or_else(|| std::env::var("LOG.CALLER").ok()),
            )?
            .set_override(
                "trustauthority_base_url",
                std::env::var("TRUSTAUTHORITY_BASE_URL")
                    .ok()
                    .or_else(|| std::env::var("TRUSTAUTHORITY.BASE.URL").ok()),
            )?
            .set_override(
                "trustauthority_api_url",
                std::env::var("TRUSTAUTHORITY_API_URL")
                    .ok()
                    .or_else(|| std::env::var("TRUSTAUTHORITY.API.URL").ok()),
            )?
            .set_override(
                "trustauthority_api_key",
                std::env::var("TRUSTAUTHORITY_API_KEY")
                    .ok()
                    .or_else(|| std::env::var("TRUSTAUTHORITY.API.KEY").ok()),
            )?
            .set_override(
                "key_manager",
                std::env::var("KEY_MANAGER")
                    .ok()
                    .or_else(|| std::env::var("KEY.MANAGER").ok()),
            )?
            .set_override(
                "admin_username",
                std::env::var("ADMIN_USERNAME")
                    .ok()
                    .or_else(|| std::env::var("ADMIN.USERNAME").ok()),
            )?
            .set_override(
                "admin_password",
                std::env::var("ADMIN_PASSWORD")
                    .ok()
                    .or_else(|| std::env::var("ADMIN.PASSWORD").ok()),
            )?
            .set_override(
                "san_list",
                std::env::var("SAN_LIST")
                    .ok()
                    .or_else(|| std::env::var("SAN.LIST").ok()),
            )?
            .set_override(
                "bearer_token_validity_in_minutes",
                std::env::var("BEARER_TOKEN_VALIDITY_IN_MINUTES")
                    .ok()
                    .or_else(|| std::env::var("BEARER.TOKEN.VALIDITY.IN.MINUTES").ok()),
            )?
            .set_override(
                "http_read_header_timeout",
                std::env::var("HTTP_READ_HEADER_TIMEOUT")
                    .ok()
                    .or_else(|| std::env::var("HTTP.READ.HEADER.TIMEOUT").ok()),
            )?
            .set_override(
                "authentication_defend_max_attempts",
                std::env::var("AUTHENTICATION_DEFEND_MAX_ATTEMPTS")
                    .ok()
                    .or_else(|| std::env::var("AUTHENTICATION.DEFEND.MAX.ATTEMPTS").ok()),
            )?
            .set_override(
                "authentication_defend_interval_minutes",
                std::env::var("AUTHENTICATION_DEFEND_INTERVAL_MINUTES")
                    .ok()
                    .or_else(|| std::env::var("AUTHENTICATION.DEFEND.INTERVAL.MINUTES").ok()),
            )?
            .set_override(
                "authentication_defend_lockout_minutes",
                std::env::var("AUTHENTICATION_DEFEND_LOCKOUT_MINUTES")
                    .ok()
                    .or_else(|| std::env::var("AUTHENTICATION.DEFEND.LOCKOUT.MINUTES").ok()),
            )?;

        // Build and deserialize
        let config: Configuration = config.build()?.try_deserialize()?;

        // Validate
        config.validate()?;

        Ok(config)
    }

    /// Validate the configuration.
    pub fn validate(&self) -> KbsResult<()> {
        // Validate port
        if self.service_port < 1024 || self.service_port > 65535 {
            return Err(KbsError::Config(format!(
                "Invalid port: {}. Must be between 1024 and 65535",
                self.service_port
            )));
        }

        // Validate Trust Authority URLs
        if self.trust_authority_api_url.is_empty()
            || self.trust_authority_api_key.is_empty()
            || self.trust_authority_base_url.is_empty()
        {
            return Err(KbsError::Config(
                "TRUSTAUTHORITY_API_URL, TRUSTAUTHORITY_API_KEY, and TRUSTAUTHORITY_BASE_URL must be set".into()
            ));
        }

        // Validate URLs
        if let Err(e) = url::Url::parse(&self.trust_authority_api_url) {
            return Err(KbsError::Config(format!(
                "Invalid TRUSTAUTHORITY_API_URL: {}",
                e
            )));
        }

        if let Err(e) = url::Url::parse(&self.trust_authority_base_url) {
            return Err(KbsError::Config(format!(
                "Invalid TRUSTAUTHORITY_BASE_URL: {}",
                e
            )));
        }

        // Validate base64 API key
        base64::decode(&self.trust_authority_api_key).map_err(|e| {
            KbsError::Config(format!("Invalid TRUSTAUTHORITY_API_KEY encoding: {}", e))
        })?;

        // Validate admin credentials
        if self.admin_username.is_empty() || self.admin_password.is_empty() {
            return Err(KbsError::Config(
                "ADMIN_USERNAME and ADMIN_PASSWORD must be set".into(),
            ));
        }

        // Validate username format
        validate_username(&self.admin_username)?;

        // Validate password format
        validate_password(&self.admin_password)?;

        // Validate token validity
        if self.bearer_token_validity_in_minutes < MIN_TOKEN_VALIDITY_MINUTES
            || self.bearer_token_validity_in_minutes > MAX_TOKEN_VALIDITY_MINUTES
        {
            return Err(KbsError::Config(format!(
                "BEARER_TOKEN_VALIDITY_IN_MINUTES: invalid range {}-{}",
                MIN_TOKEN_VALIDITY_MINUTES, MAX_TOKEN_VALIDITY_MINUTES
            )));
        }

        // Validate authentication defend settings
        if self.authentication_defend_interval_minutes < 1 {
            return Err(KbsError::Config(
                "AUTHENTICATION_DEFEND_INTERVAL_MINUTES must be at least 1".into(),
            ));
        }

        if self.authentication_defend_max_attempts < 1 {
            return Err(KbsError::Config(
                "AUTHENTICATION_DEFEND_MAX_ATTEMPTS must be at least 1".into(),
            ));
        }

        if self.authentication_defend_lockout_minutes < 1 {
            return Err(KbsError::Config(
                "AUTHENTICATION_DEFEND_LOCKOUT_MINUTES must be at least 1".into(),
            ));
        }

        Ok(())
    }

    /// Get the socket address for the service.
    pub fn socket_addr(&self) -> SocketAddr {
        SocketAddr::from(([0, 0, 0, 0], self.service_port))
    }
}

fn validate_username(username: &str) -> KbsResult<()> {
    let regex =
        regex::Regex::new(r"^[a-zA-Z0-9.-_]+@?[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$")
            .map_err(|e| KbsError::Config(format!("Invalid username regex: {}", e)))?;

    if username.len() >= 256 || !regex.is_match(username) {
        return Err(KbsError::Config("Invalid username format".into()));
    }

    Ok(())
}

fn validate_password(password: &str) -> KbsResult<()> {
    // Remove double quote from pattern - use char class instead
    let pattern = r#"^[a-zA-Z0-9_\\., @!#$%^+=>?:{}\[\]|;~*-]+$"#;
    let regex = regex::Regex::new(pattern)
        .map_err(|e| KbsError::Config(format!("Invalid password regex: {}", e)))?;

    if password.len() < 8 || password.len() > 64 || !regex.is_match(password) {
        return Err(KbsError::Config(String::from("Invalid password structure")));
    }

    Ok(())
}

// Default functions
fn default_service_port() -> u16 {
    DEFAULT_SERVICE_PORT
}

fn default_log_level() -> String {
    DEFAULT_LOG_LEVEL.to_string()
}

fn default_key_manager() -> String {
    "VAULT".to_string()
}

fn default_bearer_token_validity() -> i64 {
    DEFAULT_BEARER_TOKEN_VALIDITY_MINUTES
}

fn default_http_read_header_timeout() -> u64 {
    DEFAULT_HTTP_READ_HEADER_TIMEOUT
}

fn default_auth_defend_max_attempts() -> u32 {
    DEFAULT_AUTH_DEFEND_MAX_ATTEMPTS
}

fn default_auth_defend_interval_minutes() -> u64 {
    DEFAULT_AUTH_DEFEND_INTERVAL_MINUTES
}

fn default_auth_defend_lockout_minutes() -> u64 {
    DEFAULT_AUTH_DEFEND_LOCKOUT_MINUTES
}
