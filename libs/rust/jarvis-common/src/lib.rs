//! Building blocks shared by the Jarvis Rust services. Security-sensitive
//! pieces (caller identity, authorization) live here once, so every service
//! enforces them identically.

pub mod authz;
pub mod mtls;
pub mod telemetry;
