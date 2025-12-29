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
