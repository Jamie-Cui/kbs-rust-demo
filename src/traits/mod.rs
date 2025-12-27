/*
 *   Copyright (c) 2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

//! Trait definitions for external integrations.
//!
//! These traits define the interfaces for external services that you will need to implement:
//! - KeyManager: Interface for key management operations (Vault, KMIP, etc.)
//! - ItaClient: Interface for Intel Trust Authority client

pub mod ita_client;
pub mod key_manager;

pub use ita_client::*;
pub use key_manager::*;
