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
//! Main entry point for the KBS service.

use gta_kbs::config::Configuration;
use gta_kbs::constant::*;
use gta_kbs::defender::Defender;
use gta_kbs::error::KbsResult;
use gta_kbs::handlers::AppState;
use gta_kbs::ita::MockItaClient;
use gta_kbs::kms::MemoryKeyManager;
use gta_kbs::repositories::directory::*;
use gta_kbs::services::*;
use gta_kbs::tasks::{admin_user::CreateAdminUser, jwt_key::CreateSigningKey, tls_cert::TlsKeyAndCert};
use std::sync::Arc;
use std::time::Duration;
use tokio::signal;
use tower_http::{
    cors::CorsLayer,
    trace::TraceLayer,
};
use tracing::{info, warn};
use tracing_subscriber::{
    fmt::{self, format::FmtSpan},
    layer::SubscriberExt,
    util::SubscriberInitExt,
    EnvFilter,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    run().await.map_err(|e| Box::new(e) as Box<dyn std::error::Error>)
}

async fn run() -> gta_kbs::KbsResult<()> {
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

    // Initialize JWT signing key (generate if missing)
    let jwt_key_task = CreateSigningKey::new();
    match jwt_key_task.generate_if_missing() {
        Ok(true) => info!("Generated JWT signing key"),
        Ok(false) => info!("JWT signing key already exists"),
        Err(e) => {
            warn!("Failed to generate JWT signing key: {}", e);
            return Err(e);
        }
    }

    // Initialize TLS certificate (generate if missing)
    let tls_cert_task = TlsKeyAndCert::with_paths(
        DEFAULT_TLS_CERT_PATH,
        DEFAULT_TLS_KEY_PATH,
        &config.san_list.clone().unwrap_or_else(|| DEFAULT_TLS_SAN.to_string()),
    );
    match tls_cert_task.generate_if_missing() {
        Ok(true) => info!("Generated TLS certificate and key"),
        Ok(false) => info!("TLS certificate and key already exist"),
        Err(e) => {
            warn!("Failed to generate TLS certificate: {}", e);
            // Non-fatal, continue without TLS
        }
    }

    // Create repositories
    let key_store = Arc::new(FileKeyStore::new(None));
    let policy_store = Arc::new(FileKeyTransferPolicyStore::new(None));
    let user_store = Arc::new(FileUserStore::new(None));

    // Initialize Defender for rate limiting
    let defender = Arc::new(Defender::from_config(
        config.authentication_defend_max_attempts,
        config.authentication_defend_interval_minutes,
        config.authentication_defend_lockout_minutes,
    )?);
    info!("Defender initialized: max_attempts={}, interval={}min, lockout={}min",
        config.authentication_defend_max_attempts,
        config.authentication_defend_interval_minutes,
        config.authentication_defend_lockout_minutes);

    // Spawn background task for periodic defender cleanup
    let defender_cleanup = defender.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(300)); // Every 5 minutes
        loop {
            interval.tick().await;
            defender_cleanup.cleanup().await;
        }
    });

    // Create Key Manager (in-memory implementation for development)
    // For production, replace with a real KMS integration like Vault
    let key_manager = Arc::new(MemoryKeyManager::new());
    info!("Using in-memory KeyManager (for development only)");

    // Create ITA Client (mock implementation for development)
    // For production, replace with IntelItaClient
    let ita_client = Arc::new(MockItaClient::new());
    info!("Using mock ITA client (for development only)");

    // Create admin user if they don't exist
    let admin_user_task = CreateAdminUser::new(
        &config.admin_username,
        &config.admin_password,
        user_store.clone(),
    );
    match admin_user_task.create_if_missing().await {
        Ok(true) => info!("Created admin user: {}", config.admin_username),
        Ok(false) => info!("Admin user already exists: {}", config.admin_username),
        Err(e) => {
            warn!("Failed to create admin user: {}", e);
            return Err(e);
        }
    }

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
        defender,
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
