/*
 *   Copyright (c) 2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

//! Intel Trust Authority Key Broker Service (KBS) - Rust implementation
//!
//! This is a Rust rewrite of the Intel Trust Authority Key Broker Service.
//! It acts as a relying party in remote attestation architectures, brokering
//! access to keys stored in KMS systems based on TEE attestation policies.
//!
//! # Architecture
//!
//! The service follows a clean architecture pattern:
//! - **Handlers**: HTTP request/response handling
//! - **Services**: Business logic layer
//! - **Repositories**: Data persistence layer
//! - **Traits**: External integrations (KeyManager, ItaClient)
//!
//! # External Dependencies
//!
//! You must implement the following traits for the service to work:
//! - [`KeyManager`](traits::KeyManager): For KMS operations (Vault, KMIP, etc.)
//! - [`ItaClient`](traits::ItaClient): For Intel Trust Authority integration

pub mod config;
pub mod constant;
pub mod crypto;
pub mod error;
pub mod handlers;
pub mod ita;
pub mod kms;
pub mod middleware;
pub mod models;
pub mod repositories;
pub mod services;
pub mod traits;

pub use config::Configuration;
pub use error::{KbsError, KbsResult};
pub use ita::{IntelItaClient, MockItaClient, TestItaClient};
pub use kms::MemoryKeyManager;

#[cfg(feature = "vault")]
pub use kms::VaultKeyManager;
