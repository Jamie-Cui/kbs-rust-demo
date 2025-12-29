# Intel Trust Authority Key Broker Service (KBS) - Rust Implementation

A complete Rust implementation of the Intel Trust Authority Key Broker Service (KBS), acting as a relying party in Trusted Execution Environment (TEE) remote attestation architectures.

## Overview

This service bridges TEE remote attestation with Key Management Systems (KMS), enabling secure key transfer to attested workloads based on configurable policies. It supports both Intel SGX and Intel TDX attestation.

## Features

- **Remote Attestation**: SGX and TDX quote verification via Intel Trust Authority
- **Key Management**: Double-wrapping key transfer (AES-GCM + RSA-OAEP)
- **Two Attestation Modes**:
  - **Passport Mode**: Client provides pre-obtained attestation token
  - **Background Verification**: Service orchestrates attestation with Intel Trust Authority
- **Policy-Based Access**: Configurable SGX/TDX attribute matching policies
- **JWT Authentication**: Token-based user authentication
- **Clean Architecture**: Handlers → Services → Repositories pattern
- **Extensible**: Trait-based design for custom KMS and attestation providers

## Architecture

```
┌─────────────┐
│   Client    │
└──────┬──────┘
       │ HTTP/REST
       ▼
┌─────────────────────────────────────────────────────────────┐
│                      HTTP Layer                             │
│  ┌──────────────────────────────────────────────────────┐  │
│  │  Handlers (auth, key, key_transfer, user, policy)  │  │
│  └───────────────┬──────────────────────────────────────┘  │
│                  │                                          │
│  ┌───────────────▼──────────────────────────────────────┐  │
│  │     Middleware (JWT Auth, CORS, Tracing)            │  │
│  └───────────────┬──────────────────────────────────────┘  │
└──────────────────┼──────────────────────────────────────────┘
                   │
┌──────────────────▼──────────────────────────────────────────┐
│                    Service Layer                            │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────┐   │
│  │ AuthService  │  │  KeyService  │  │ KeyTransferSvc   │   │
│  └──────────────┘  └──────────────┘  └──────────────────┘   │
│  ┌──────────────┐  ┌──────────────────────────────────────┐ │
│  │ UserService  │  │   KeyTransferPolicyService           │ │
│  └──────────────┘  └──────────────────────────────────────┘ │
└───────────────────┬──────────────────────────────────────────┘
                    │
┌───────────────────▼──────────────────────────────────────────┐
│                  Repository Layer                             │
│  ┌──────────────────┐  ┌──────────────────┐  ┌────────────┐  │
│  │   UserStore     │  │    KeyStore      │  │ PolicyStore │  │
│  │  (File-based)    │  │   (File-based)   │  │ (File-based)│  │
│  └──────────────────┘  └──────────────────┘  └────────────┘  │
└────────────────────────────────────────────────────────────────┘
                    │
┌───────────────────▼──────────────────────────────────────────┐
│                  External Integrations                        │
│  ┌──────────────────┐  ┌──────────────────────────────────┐  │
│  │   KeyManager     │  │        ItaClient                  │  │
│  │  (KMS Backend)   │  │  (Intel Trust Authority)          │  │
│  │                  │  │                                  │  │
│  │ • MemoryKeyMgr   │  │ • IntelItaClient (production)     │  │
│  │ • VaultKeyMgr    │  │ • MockItaClient (development)      │  │
│  └──────────────────┘  └──────────────────────────────────┘  │
└────────────────────────────────────────────────────────────────┘
```

## Requirements

- Rust 1.75 or later
- OpenSSL (for JWT key generation)

## Installation

```bash
# Clone the repository
git clone https://github.com/Jamie-Cui/kbs-rust-demo.git
cd kbs-rust-demo

# Build in release mode
cargo build --release
```

## Configuration

Create a `.env` file in the project root:

```env
# Service Configuration
KBS_SERVICE_PORT=8080
KBS_SERVICE_HOST=0.0.0.0

# JWT Signing Key (auto-generated if missing)
KBS_JWT_SIGNING_KEY_PATH=./jwt_signing.pem

# Intel Trust Authority
TRUSTAUTHORITY_API_URL=https://api.trustauthority.intel.com
TRUSTAUTHORITY_API_KEY=<base64-encoded-api-key>
```

### Generate JWT Signing Key

```bash
# Generate RSA private key for JWT signing
openssl genrsa -out jwt_signing.pem 2048

# Extract public key (for verification)
openssl rsa -in jwt_signing.pem -pubout -out jwt_signing.pub.pem
```

## Running the Service

```bash
# Development mode
cargo run

# Release mode
cargo run --release

# With custom environment file
cargo run -- --config .env.production
```

The service will start on http://localhost:8080

## API Endpoints

### Authentication

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/token` | Create authentication token |

### Keys

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/keys` | List keys (with filtering) |
| POST | `/keys` | Create a new key |
| GET | `/keys/:id` | Get key details |
| PUT | `/keys/:id` | Update key |
| DELETE | `/keys/:id` | Delete key |
| POST | `/keys/:id/transfer` | Transfer key with attestation |
| GET | `/keys/:id/nonce` | Get nonce for background verification |

### Key Transfer Policies

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/key-transfer-policies` | List policies |
| POST | `/key-transfer-policies` | Create policy |
| GET | `/key-transfer-policies/:id` | Get policy details |
| DELETE | `/key-transfer-policies/:id` | Delete policy |

### Users

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/users` | List users |
| POST | `/users` | Create user |
| GET | `/users/:id` | Get user details |
| PUT | `/users/:id` | Update user |
| DELETE | `/users/:id` | Delete user |

### System

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/version` | Get service version |

## Usage Examples

### 1. Create a User

```bash
curl -X POST http://localhost:8080/users \
  -H "Content-Type: application/json" \
  -d '{
    "username": "admin",
    "password": "secure_password",
    "permissions": ["key:create", "key:transfer"]
  }'
```

### 2. Get Authentication Token

```bash
curl -X POST http://localhost:8080/token \
  -H "Content-Type: application/json" \
  -d '{
    "username": "admin",
    "password": "secure_password"
  }'
```

### 3. Create a Key Transfer Policy

```bash
curl -X POST http://localhost:8080/key-transfer-policies \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <jwt-token>" \
  -d '{
    "name": "SGX Enclave Policy",
    "attestation_type": "SGX",
    "sgx": {
      "mrenclave": ["a3b67c0fb8fc12bc56b720f7befcb7cfcb1862324a89e05ae7a31e8d1082f0a"],
      "mrsigner": ["aae07df6a1927e88a88a8928f9bee3e0a88ee5f9e2fbc27c62a2df08ace3d2b"],
      "isvprodid": [0],
      "isvsvn": [0, 1, 2],
      "is_debuggable": false
    }
  }'
```

### 4. Create a Key

```bash
curl -X POST http://localhost:8080/keys \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <jwt-token>" \
  -d '{
    "key_info": {
      "algorithm": "AES",
      "key_length": 256
    },
    "transfer_policy_id": "<policy-uuid>"
  }'
```

### 5. Transfer Key (Background Verification)

First, get a nonce:

```bash
curl -X GET http://localhost:8080/keys/<key-uuid>/nonce \
  -H "Authorization: Bearer <jwt-token>"
```

Then transfer with the quote and nonce:

```bash
curl -X POST http://localhost:8080/keys/<key-uuid>/transfer \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <jwt-token>" \
  -d '{
    "quote": "<base64-sgx-quote>",
    "user_data": "<base64-public-key>",
    "nonce": {
      "val": "<base64-nonce-value>",
      "iat": "<base64-timestamp>",
      "signature": "<base64-signature>"
    }
  }'
```

### 6. Transfer Key (Passport Mode)

```bash
curl -X POST http://localhost:8080/keys/<key-uuid>/transfer \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <jwt-token>" \
  -d '{
    "attestation_token": "<ita-jwt-token>"
  }'
```

## Key Manager Implementations

### MemoryKeyManager (Development)

```rust
use gta_kbs::kms::MemoryKeyManager;

let key_manager = MemoryKeyManager::new();
```

In-memory key storage. **Do not use in production** - keys are lost on restart.

### VaultKeyManager (Production)

Enable with `--features vault`:

```toml
[dependencies]
gta-kbs = { version = "1.3", features = ["vault"] }
```

```rust
use gta_kbs::kms::VaultKeyManager;

let key_manager = VaultKeyManager::new(
    "http://localhost:8200".to_string(),
    "vault-token".to_string(),
    "secret".to_string(),
)?;
```

Stores keys in HashiCorp Vault's KV secrets engine.

## Intel Trust Authority Client Implementations

### IntelItaClient (Production)

```rust
use gta_kbs::ita::IntelItaClient;

let client = IntelItaClient::new(
    "https://api.trustauthority.intel.com".to_string(),
    "<api-key>".to_string(),
)?;

// Get nonce
let nonce = client.get_nonce("request-id").await?;

// Get token
let token = client.get_token(quote, user_data, event_log, &nonce, policies, "request-id").await?;

// Verify token
let claims = client.verify_token(&token).await?;
```

### MockItaClient (Testing)

```rust
use gta_kbs::ita::MockItaClient;

let client = MockItaClient::new();
```

Returns mock responses without network calls.

### TestItaClient (Advanced Testing)

```rust
use gta_kbs::ita::TestItaClient;

let client = TestItaClient::new();
client.set_nonce_response(Ok(mock_nonce)).await;
```

Allows setting custom responses for testing scenarios.

## Development

### Running Tests

```bash
# Unit tests
cargo test

# Unit tests with output
cargo test -- --nocapture

# Run specific test
cargo test test_rsa_wrap_unwrap

# Doc tests
cargo test --doc
```

### Code Formatting

```bash
cargo fmt
```

### Linting

```bash
cargo clippy
```

### Build Check

```bash
cargo check
```

## Project Structure

```
src/
├── lib.rs              # Library exports
├── main.rs             # Binary entry point
├── error.rs            # Error types
├── constant.rs         # Constants
├── config.rs           # Configuration
├── models/             # Data models
│   ├── attestation.rs  # Attestation token claims
│   ├── key.rs          # Key models
│   ├── key_transfer.rs # Key transfer models
│   ├── key_transfer_policy.rs  # Policy models
│   └── user.rs         # User models
├── traits/             # External integration traits
│   ├── key_manager.rs  # KMS operations trait
│   └── ita_client.rs   # Intel Trust Authority trait
├── repositories/       # Data persistence
│   └── directory.rs    # File-based storage
├── crypto/             # Cryptographic utilities
│   ├── aes.rs          # AES-GCM encryption
│   ├── rsa.rs          # RSA-OAEP encryption
│   └── jwt.rs          # JWT utilities
├── services/           # Business logic
│   ├── auth.rs         # Authentication
│   ├── user.rs         # User management
│   ├── key.rs          # Key lifecycle
│   ├── key_transfer_policy.rs  # Policy management
│   ├── key_transfer.rs # Key transfer orchestration
│   └── validation.rs   # Attestation validation
├── handlers/           # HTTP handlers
│   ├── auth.rs
│   ├── user.rs
│   ├── key.rs
│   ├── key_transfer.rs
│   ├── key_transfer_policy.rs
│   └── version.rs
├── middleware/         # HTTP middleware
│   └── auth.rs         # JWT authentication
├── kms.rs              # KeyManager implementations
└── ita.rs              # ItaClient implementations
```

## License

BSD-3-Clause

## Copyright

Copyright (c) 2024 Intel Corporation

## Acknowledgments

Based on the [Intel Trust Authority KBS](https://github.com/intel/trustauthority-kbs) Go implementation.
