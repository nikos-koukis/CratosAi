//! Jarvis local daemon: runs commands for the orchestrator on the user's Mac.
//!
//! Allowlisted commands run immediately; anything else needs an approval
//! signed by one of the user's devices. Every command runs inside the macOS
//! sandbox. The daemon is reachable only over Tailscale, with mutual TLS.
//!
//! Contract: `proto/jarvis/device/v1/device.proto`.

pub mod approval;
pub mod config;
pub mod executor;
pub mod network;
pub mod policy;
pub mod proto;
pub mod sandbox;
pub mod server;
pub mod service;
