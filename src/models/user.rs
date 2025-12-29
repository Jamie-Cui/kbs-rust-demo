
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// User creation request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    /// Username
    pub username: String,

    /// Password
    pub password: String,

    /// Permissions
    pub permissions: Vec<String>,
}

/// User response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserResponse {
    /// User ID
    pub id: Uuid,

    /// Creation timestamp
    #[serde(rename = "created_at")]
    pub created_at: time::OffsetDateTime,

    /// Last update timestamp
    #[serde(rename = "updated_at")]
    pub updated_at: time::OffsetDateTime,

    /// Username
    pub username: String,

    /// Permissions
    pub permissions: Vec<String>,
}

/// Internal user info (stored in repository).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserInfo {
    /// User ID
    pub id: Uuid,

    /// Creation timestamp
    #[serde(rename = "created_at")]
    pub created_at: time::OffsetDateTime,

    /// Last update timestamp
    #[serde(rename = "updated_at")]
    pub updated_at: time::OffsetDateTime,

    /// Username
    pub username: String,

    /// Password hash
    #[serde(rename = "password_hash")]
    pub password_hash: String,

    /// Password cost (bcrypt cost factor)
    #[serde(rename = "password_cost")]
    pub password_cost: u32,

    /// Permissions
    pub permissions: Vec<String>,
}

/// User update request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateUserRequest {
    /// Username (optional)
    pub username: Option<String>,

    /// Password (optional)
    pub password: Option<String>,

    /// Permissions (optional)
    pub permissions: Option<Vec<String>>,
}

/// User filter criteria for searching.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UserFilterCriteria {
    /// Username filter
    pub username: Option<String>,
}

/// Auth token request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthTokenRequest {
    /// Username
    pub username: String,

    /// Password
    pub password: String,
}

/// JWT authorization context.
#[derive(Debug, Clone)]
pub struct JwtAuthz {
    /// JWT secret (for signing - RSA private key in PEM format)
    pub jwt_secret: String,

    /// Token validity in minutes
    pub token_validity_minutes: i64,
}

impl UserInfo {
    /// Verify the password against the stored hash.
    pub fn verify_password(&self, password: &str) -> Result<bool, bcrypt::BcryptError> {
        bcrypt::verify(password, &self.password_hash)
    }

    /// Create a user response from user info (hiding sensitive data).
    pub fn to_response(&self) -> UserResponse {
        UserResponse {
            id: self.id,
            created_at: self.created_at,
            updated_at: self.updated_at,
            username: self.username.clone(),
            permissions: self.permissions.clone(),
        }
    }
}

impl User {
    /// Validate the user request.
    pub fn validate(&self) -> Result<(), String> {
        if self.username.is_empty() {
            return Err("username is required".to_string());
        }

        if self.username.len() >= 256 {
            return Err("username must be less than 256 characters".to_string());
        }

        if self.password.is_empty() {
            return Err("password is required".to_string());
        }

        if self.password.len() < 8 || self.password.len() > 64 {
            return Err("password must be between 8 and 64 characters".to_string());
        }

        if self.permissions.is_empty() {
            return Err("at least one permission is required".to_string());
        }

        Ok(())
    }
}
