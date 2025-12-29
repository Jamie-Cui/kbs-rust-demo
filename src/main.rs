/*
 *   Copyright (c) 2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

//! Intel Trust Authority Key Broker Service (KBS)
//!
//! Main entry point for the KBS service.

use gta_kbs::config::Configuration;
use gta_kbs::constant::*;
use gta_kbs::handlers::AppState;
use gta_kbs::ita::MockItaClient;
use gta_kbs::kms::MemoryKeyManager;
use gta_kbs::repositories::directory::*;
use gta_kbs::services::*;
use std::sync::Arc;
use tokio::signal;
use tower_http::{
    cors::CorsLayer,
    trace::TraceLayer,
};
use tracing::info;
use tracing_subscriber::{
    fmt::{self, format::FmtSpan},
    layer::SubscriberExt,
    util::SubscriberInitExt,
    EnvFilter,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing
    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info"));

    tracing_subscriber::registry()
        .with(env_filter)
        .with(
            fmt::layer()
                .with_span_events(FmtSpan::CLOSE)
                .with_target(false),
        )
        .init();

    info!("Starting Intel Trust Authority Key Broker Service (KBS)");

    // Load configuration
    let config = Arc::new(Configuration::from_env()?);
    info!("Configuration loaded successfully");

    // Create repositories
    let key_store = Arc::new(FileKeyStore::new(None));
    let policy_store = Arc::new(FileKeyTransferPolicyStore::new(None));
    let user_store = Arc::new(FileUserStore::new(None));

    // Create Key Manager (in-memory implementation for development)
    // For production, replace with a real KMS integration like Vault
    let key_manager = Arc::new(MemoryKeyManager::new());
    info!("Using in-memory KeyManager (for development only)");

    // Create ITA Client (mock implementation for development)
    // For production, replace with IntelItaClient
    let ita_client = Arc::new(MockItaClient::new());
    info!("Using mock ITA client (for development only)");

    // Create services with concrete types
    type KeyStoreType = FileKeyStore;
    type PolicyStoreType = FileKeyTransferPolicyStore;
    type UserStoreType = FileUserStore;
    type KeyManagerType = MemoryKeyManager;
    type ItaClientType = MockItaClient;

    let auth_service: Arc<dyn AuthService> = Arc::new(
        AuthServiceImpl::<UserStoreType>::new(
            user_store.clone(),
            config.clone(),
            // Load JWT signing key
            AuthServiceImpl::<UserStoreType>::load_signing_key(DEFAULT_JWT_SIGNING_KEY_PATH).await?,
        )
    );

    let user_service: Arc<dyn UserService> = Arc::new(
        UserServiceImpl::<UserStoreType>::new(user_store.clone())
    );

    let key_service: Arc<dyn KeyService> = Arc::new(
        KeyServiceImpl::<KeyStoreType, PolicyStoreType, KeyManagerType>::new(
            key_store.clone(),
            policy_store.clone(),
            key_manager.clone(),
        )
    );

    let key_transfer_policy_service: Arc<dyn KeyTransferPolicyService> = Arc::new(
        KeyTransferPolicyServiceImpl::<PolicyStoreType>::new(policy_store.clone())
    );

    let key_transfer_service: Arc<dyn KeyTransferService> = Arc::new(
        KeyTransferServiceImpl::<KeyStoreType, PolicyStoreType, KeyManagerType, ItaClientType>::new(
            key_store.clone(),
            policy_store.clone(),
            key_manager.clone(),
            ita_client.clone(),
            false, // is_sgx - configure based on your environment
        ),
    );

    // Create application state
    let state = AppState {
        config: config.clone(),
        auth_service,
        user_service,
        key_service,
        key_transfer_policy_service,
        key_transfer_service,
    };

    // Create router
    let app = gta_kbs::handlers::create_router(state)
        .layer(CorsLayer::permissive())
        .layer(TraceLayer::new_for_http());

    // Bind to address
    let addr = config.socket_addr();
    info!("Listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    info!("Service stopped gracefully");
    Ok(())
}

/// Graceful shutdown signal handler.
async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await
            .expect("failed to receive terminate signal");
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {
            info!("Received Ctrl+C signal");
        },
        _ = terminate => {
            info!("Received terminate signal");
        },
    }
}
