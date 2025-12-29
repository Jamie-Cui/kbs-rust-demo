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


/// Service name
pub const SERVICE_NAME: &str = "kbs";

/// API version
pub const API_VERSION: &str = "v1";

/// Default service port
pub const DEFAULT_SERVICE_PORT: u16 = 9443;

/// Default HTTP read header timeout (seconds)
pub const DEFAULT_HTTP_READ_HEADER_TIMEOUT: u64 = 10;

/// Default log level
pub const DEFAULT_LOG_LEVEL: &str = "INFO";

/// Default bearer token validity (minutes)
pub const DEFAULT_BEARER_TOKEN_VALIDITY_MINUTES: i64 = 5;

/// Minimum bearer token validity (minutes)
pub const MIN_TOKEN_VALIDITY_MINUTES: i64 = 1;

/// Maximum bearer token validity (minutes)
pub const MAX_TOKEN_VALIDITY_MINUTES: i64 = 30;

/// Default authentication defend max attempts
pub const DEFAULT_AUTH_DEFEND_MAX_ATTEMPTS: u32 = 5;

/// Default authentication defend interval (minutes)
pub const DEFAULT_AUTH_DEFEND_INTERVAL_MINUTES: u64 = 5;

/// Default authentication defend lockout (minutes)
pub const DEFAULT_AUTH_DEFEND_LOCKOUT_MINUTES: u64 = 15;

/// Config directory
pub const CONFIG_DIR: &str = "/etc/kbs";

/// TLS certs directory
pub const TLS_CERTS_PATH: &str = "/etc/kbs/certs/tls/";

/// JWT signing certs directory
pub const JWT_SIGNING_CERTS_PATH: &str = "/etc/kbs/certs/signing-keys/";

/// Default TLS cert path
pub const DEFAULT_TLS_CERT_PATH: &str = "/etc/kbs/certs/tls/tls.crt";

/// Default TLS key path
pub const DEFAULT_TLS_KEY_PATH: &str = "/etc/kbs/certs/tls/tls.key";

/// Default JWT signing key path
pub const DEFAULT_JWT_SIGNING_KEY_PATH: &str = "/etc/kbs/certs/signing-keys/jwt-signing.key";

/// TLS certificate validity (days)
pub const TLS_VALIDITY_DAYS: u32 = 365;

/// TLS certificate common name
pub const TLS_COMMON_NAME: &str = "KBS TLS Certificate";

/// TLS certificate issuer
pub const TLS_ISSUER: &str = "Intel";

/// Default TLS SAN list
pub const DEFAULT_TLS_SAN: &str = "127.0.0.1,localhost";

/// Default RSA key length (bits)
pub const DEFAULT_KEY_LENGTH: u32 = 3072;

/// Base directory for KBS data
pub const HOME_DIR: &str = "/opt/kbs";

/// Directory for keys
pub const KEYS_DIR: &str = "/keys";

/// Directory for key transfer policies
pub const KEYS_TRANSFER_POLICY_DIR: &str = "/keys-transfer-policy";

/// Directory for users
pub const USER_DIR: &str = "/users";

/// TCB status up-to-date
pub const TCB_STATUS_UP_TO_DATE: &str = "UpToDate";

/// TCB status out-of-date
pub const TCB_STATUS_OUT_OF_DATE: &str = "OutOfDate";

/// Algorithm constants
pub const CRYPTO_ALG_AES: &str = "AES";
pub const CRYPTO_ALG_RSA: &str = "RSA";
pub const CRYPTO_ALG_EC: &str = "EC";

/// Attestation types
pub const ATTESTATION_TYPE_SGX: &str = "SGX";
pub const ATTESTATION_TYPE_TDX: &str = "TDX";

/// UUID regex pattern
pub const UUID_REGEX: &str =
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}";

/// Permissions
pub mod permissions {
    pub const KEY_CREATE: &str = "keys:create";
    pub const KEY_DELETE: &str = "keys:delete";
    pub const KEY_SEARCH: &str = "keys:search";
    pub const KEY_TRANSFER: &str = "keys:transfer";
    pub const KEY_UPDATE: &str = "keys:update";

    pub const KEY_TRANSFER_POLICY_CREATE: &str = "key_transfer_policies:create";
    pub const KEY_TRANSFER_POLICY_DELETE: &str = "key_transfer_policies:delete";
    pub const KEY_TRANSFER_POLICY_SEARCH: &str = "key_transfer_policies:search";

    pub const USER_CREATE: &str = "users:create";
    pub const USER_DELETE: &str = "users:delete";
    pub const USER_SEARCH: &str = "users:search";
    pub const USER_UPDATE: &str = "users:update";

    pub const ALL_PERMISSIONS: &[&str] = &[
        KEY_SEARCH,
        KEY_CREATE,
        KEY_DELETE,
        KEY_TRANSFER,
        KEY_UPDATE,
        KEY_TRANSFER_POLICY_CREATE,
        KEY_TRANSFER_POLICY_SEARCH,
        KEY_TRANSFER_POLICY_DELETE,
        USER_DELETE,
        USER_SEARCH,
        USER_CREATE,
        USER_UPDATE,
    ];
}

/// Log context keys
pub mod log_keys {
    pub const USER_ID: &str = "user_id";
}
