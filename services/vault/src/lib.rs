//! BYOK Vault: stores tenant-owned LLM provider API keys envelope-encrypted
//! (AES-256-GCM, Argon2id-derived KEK) in PostgreSQL and releases plaintext
//! only to authorised internal services over mutual TLS.
//!
//! Contract: `proto/jarvis/vault/v1/vault.proto`.

pub mod audit;
pub mod authz;
pub mod config;
pub mod crypto;
pub mod domain;
pub mod error;
pub mod proto;
pub mod server;
pub mod service;
pub mod store;
