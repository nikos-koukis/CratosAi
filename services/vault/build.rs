//! Generates the gRPC types from `/proto`.
//!
//! protox is a pure-Rust protobuf compiler, so building the Vault needs no
//! `protoc` binary on the machine.

use std::{env, error::Error, fs, path::PathBuf};

use prost::Message;

const PROTO_ROOT: &str = "../../proto";
const PROTO_FILES: &[&str] = &["jarvis/vault/v1/vault.proto"];

/// Messages that carry plaintext secrets. Their `Debug` impls are written by
/// hand in `src/proto.rs` so that a stray `{:?}` can never print a key.
const SECRET_BEARING_MESSAGES: &[&str] = &[
    ".jarvis.vault.v1.CreateKeyRequest",
    ".jarvis.vault.v1.GetDecryptedKeyResponse",
    ".jarvis.vault.v1.SealDataRequest",
    ".jarvis.vault.v1.OpenDataResponse",
];

fn main() -> Result<(), Box<dyn Error>> {
    println!("cargo:rerun-if-changed={PROTO_ROOT}");

    let descriptors = protox::compile(PROTO_FILES, [PROTO_ROOT])?;

    let out_dir = PathBuf::from(env::var("OUT_DIR")?);
    fs::write(
        out_dir.join("jarvis_descriptor.bin"),
        descriptors.encode_to_vec(),
    )?;

    tonic_prost_build::configure()
        .build_server(true)
        .build_client(true)
        .skip_debug(SECRET_BEARING_MESSAGES.iter().copied())
        .compile_fds(descriptors)?;

    Ok(())
}
