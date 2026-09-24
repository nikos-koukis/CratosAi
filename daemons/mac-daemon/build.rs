//! Generates the gRPC types from `/proto` with protox (no `protoc` needed).

use std::{env, error::Error, fs, path::PathBuf};

use prost::Message;

const PROTO_ROOT: &str = "../../proto";
const PROTO_FILES: &[&str] = &["jarvis/device/v1/device.proto"];

fn main() -> Result<(), Box<dyn Error>> {
    println!("cargo:rerun-if-changed={PROTO_ROOT}");

    let descriptors = protox::compile(PROTO_FILES, [PROTO_ROOT])?;
    let out_dir = PathBuf::from(env::var("OUT_DIR")?);
    fs::write(
        out_dir.join("device_descriptor.bin"),
        descriptors.encode_to_vec(),
    )?;

    tonic_prost_build::configure()
        .build_server(true)
        .build_client(true)
        .compile_fds(descriptors)?;
    Ok(())
}
