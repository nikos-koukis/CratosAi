//! Generated gRPC types for the device contract.

#[allow(clippy::all, clippy::pedantic, missing_debug_implementations)]
pub mod jarvis {
    pub mod device {
        pub mod v1 {
            tonic::include_proto!("jarvis.device.v1");
        }
    }
}

pub use jarvis::device::v1 as device_v1;

/// Encoded `FileDescriptorSet` for the device contract (gRPC reflection).
pub const FILE_DESCRIPTOR_SET: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/device_descriptor.bin"));
