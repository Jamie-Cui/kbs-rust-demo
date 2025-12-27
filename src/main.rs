/*
 *   Copyright (c) 2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

//! Intel Trust Authority Key Broker Service (KBS) - Rust implementation
//!
//! This is the entry point for the KBS service.

mod config;
mod constant;
mod error;
mod ita_client;
mod models;
mod repositories;
mod traits;

fn main() {
    println!("Hello, world!");
}
