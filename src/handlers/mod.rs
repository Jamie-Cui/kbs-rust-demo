
pub mod auth;
pub mod key;
pub mod key_transfer;
pub mod key_transfer_policy;
pub mod user;
pub mod version;

use std::sync::Arc;
use axum::{
    Router,
    routing::{get, post},
};
use crate::config::Configuration;
use crate::services::*;

/// Application state shared by all handlers.
#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Configuration>,
    pub auth_service: Arc<dyn AuthService>,
    pub user_service: Arc<dyn UserService>,
    pub key_service: Arc<dyn KeyService>,
    pub key_transfer_policy_service: Arc<dyn KeyTransferPolicyService>,
    pub key_transfer_service: Arc<dyn KeyTransferService>,
}

/// Create the HTTP router.
pub fn create_router(state: AppState) -> Router {
    Router::new()
        .route("/token", post(auth::create_auth_token))
        .route("/keys", get(key::search_keys).post(key::create_key))
        .route("/keys/:id", get(key::get_key).delete(key::delete_key).put(key::update_key))
        .route("/keys/:id/transfer", post(key_transfer::transfer_key))
        .route("/key-transfer-policies", get(key_transfer_policy::search_policies).post(key_transfer_policy::create_policy))
        .route("/key-transfer-policies/:id", get(key_transfer_policy::get_policy).delete(key_transfer_policy::delete_policy))
        .route("/users", get(user::search_users).post(user::create_user))
        .route("/users/:id", get(user::get_user).delete(user::delete_user).put(user::update_user))
        .route("/version", get(version::get_version))
        .with_state(state)
}
