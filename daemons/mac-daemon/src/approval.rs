//! Signed approvals for commands that are not allowlisted.
//!
//! The daemon issues an `ApprovalPayload` describing exactly one command and
//! remembers its fingerprint. An approver device (the user's phone, or the
//! `jarvis-approve` CLI during development) displays the payload and signs it
//! with ECDSA P-256. The daemon then runs the command only if the signature
//! verifies against a configured approver key, the approval is unexpired and
//! unused, and the retried command is byte-for-byte the one approved.

use std::{
    collections::HashMap,
    fmt,
    os::unix::ffi::OsStrExt,
    path::PathBuf,
    sync::{Mutex, PoisonError},
    time::{Duration, Instant, SystemTime},
};

use base64::Engine;
use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
use prost::Message;
use sha2::{Digest, Sha256};

use crate::{policy::Grants, proto::device_v1};

/// Domain separation: signatures cover `SIGNATURE_CONTEXT || payload`.
pub const SIGNATURE_CONTEXT: &[u8] = b"jarvis.device.v1.ApprovalPayload\0";

/// The exact command an approval is for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommandSpec {
    pub program: PathBuf,
    pub args: Vec<String>,
    pub working_dir: PathBuf,
    pub timeout: Duration,
    pub grants: Grants,
}

impl CommandSpec {
    /// SHA-256 over a length-prefixed encoding of every field.
    pub fn fingerprint(&self) -> [u8; 32] {
        fn field(hash: &mut Sha256, bytes: &[u8]) {
            hash.update((bytes.len() as u64).to_be_bytes());
            hash.update(bytes);
        }
        let mut hash = Sha256::new();
        field(&mut hash, self.program.as_os_str().as_bytes());
        hash.update((self.args.len() as u64).to_be_bytes());
        for arg in &self.args {
            field(&mut hash, arg.as_bytes());
        }
        field(&mut hash, self.working_dir.as_os_str().as_bytes());
        hash.update(self.timeout.as_millis().to_be_bytes());
        hash.update([
            u8::from(self.grants.writable),
            u8::from(self.grants.network),
            u8::from(self.grants.system_services),
        ]);
        hash.finalize().into()
    }
}

/// Public keys allowed to sign approvals, by approver id.
#[derive(Default)]
pub struct Approvers {
    keys: HashMap<String, VerifyingKey>,
}

impl fmt::Debug for Approvers {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_set().entries(self.keys.keys()).finish()
    }
}

impl Approvers {
    /// Adds a key given as base64 SEC1 (uncompressed, 65 bytes, or compressed).
    pub fn insert(&mut self, id: &str, public_key_base64: &str) -> Result<(), String> {
        if id.is_empty()
            || id.len() > 64
            || !id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
        {
            return Err("approver id must be 1 to 64 of A-Z a-z 0-9 - _ .".into());
        }
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(public_key_base64.trim())
            .map_err(|_| format!("approver {id}: public_key is not valid base64"))?;
        let key = VerifyingKey::from_sec1_bytes(&bytes)
            .map_err(|_| format!("approver {id}: public_key is not a P-256 SEC1 public key"))?;
        if self.keys.insert(id.to_owned(), key).is_some() {
            return Err(format!("approver {id} is listed more than once"));
        }
        Ok(())
    }

    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    pub fn len(&self) -> usize {
        self.keys.len()
    }

    fn verify(&self, approver_id: &str, payload: &[u8], signature: &[u8]) -> bool {
        let Some(key) = self.keys.get(approver_id) else {
            return false;
        };
        let Ok(signature) = Signature::from_slice(signature) else {
            return false;
        };
        key.verify(&signed_message(payload), &signature).is_ok()
    }
}

/// The bytes an approver signs for `payload`.
pub fn signed_message(payload: &[u8]) -> Vec<u8> {
    let mut message = Vec::with_capacity(SIGNATURE_CONTEXT.len() + payload.len());
    message.extend_from_slice(SIGNATURE_CONTEXT);
    message.extend_from_slice(payload);
    message
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ApprovalError {
    #[error("too many approvals are waiting for a signature")]
    TooManyPending,
    #[error("approval is unknown, already used or expired")]
    Expired,
    #[error("approval is invalid: {0}")]
    Invalid(&'static str),
}

/// An approval request handed to the orchestrator.
#[derive(Debug)]
pub struct Issued {
    pub approval_id: String,
    pub payload: Vec<u8>,
    pub expire_time: SystemTime,
}

struct Pending {
    fingerprint: [u8; 32],
    payload: Vec<u8>,
    expires_at: Instant,
}

/// Approvals issued and not yet redeemed. In memory only: a restart voids
/// every outstanding approval, which is the safe direction.
pub struct PendingApprovals {
    ttl: Duration,
    capacity: usize,
    entries: Mutex<HashMap<String, Pending>>,
}

impl fmt::Debug for PendingApprovals {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PendingApprovals")
            .field("ttl", &self.ttl)
            .field("capacity", &self.capacity)
            .finish_non_exhaustive()
    }
}

impl PendingApprovals {
    pub fn new(ttl: Duration, capacity: usize) -> Self {
        Self {
            ttl,
            capacity,
            entries: Mutex::new(HashMap::new()),
        }
    }

    pub fn issue(&self, device_name: &str, spec: &CommandSpec) -> Result<Issued, ApprovalError> {
        let now = Instant::now();
        let mut entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        entries.retain(|_, pending| pending.expires_at > now);
        if entries.len() >= self.capacity {
            return Err(ApprovalError::TooManyPending);
        }

        let approval_id = uuid::Uuid::new_v4().to_string();
        let issue_time = SystemTime::now();
        let expire_time = issue_time + self.ttl;
        let payload = device_v1::ApprovalPayload {
            approval_id: approval_id.clone(),
            device_name: device_name.to_owned(),
            program: spec.program.display().to_string(),
            args: spec.args.clone(),
            working_directory: spec.working_dir.display().to_string(),
            timeout: prost_types::Duration::try_from(spec.timeout).ok(),
            sandbox: Some(spec.grants.to_proto()),
            issue_time: Some(issue_time.into()),
            expire_time: Some(expire_time.into()),
        }
        .encode_to_vec();

        entries.insert(
            approval_id.clone(),
            Pending {
                fingerprint: spec.fingerprint(),
                payload: payload.clone(),
                expires_at: now + self.ttl,
            },
        );
        Ok(Issued {
            approval_id,
            payload,
            expire_time,
        })
    }

    /// Consumes the approval (single use, even when verification fails) and
    /// checks it covers exactly `spec`. Returns the approver id.
    pub fn redeem(
        &self,
        approvers: &Approvers,
        approval: &device_v1::Approval,
        spec: &CommandSpec,
    ) -> Result<String, ApprovalError> {
        let pending = self
            .entries
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&approval.approval_id)
            .ok_or(ApprovalError::Expired)?;
        if pending.expires_at <= Instant::now() {
            return Err(ApprovalError::Expired);
        }
        if pending.fingerprint != spec.fingerprint() {
            return Err(ApprovalError::Invalid(
                "it was issued for a different command",
            ));
        }
        if !approvers.verify(&approval.approver_id, &pending.payload, &approval.signature) {
            return Err(ApprovalError::Invalid(
                "signature does not verify for that approver",
            ));
        }
        Ok(approval.approver_id.clone())
    }

    pub fn pending_count(&self) -> usize {
        self.entries
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use p256::{
        ecdsa::{SigningKey, signature::Signer},
        elliptic_curve::Generate,
    };

    use super::*;

    fn spec(args: &[&str]) -> CommandSpec {
        CommandSpec {
            program: PathBuf::from("/bin/rm"),
            args: args.iter().map(|s| (*s).to_owned()).collect(),
            working_dir: PathBuf::from("/tmp/work"),
            timeout: Duration::from_secs(30),
            grants: Grants {
                writable: true,
                ..Grants::default()
            },
        }
    }

    fn approver() -> (SigningKey, Approvers) {
        let key = SigningKey::try_generate().unwrap();
        let public = key.verifying_key().to_sec1_bytes();
        let mut approvers = Approvers::default();
        approvers
            .insert(
                "phone",
                &base64::engine::general_purpose::STANDARD.encode(public),
            )
            .unwrap();
        (key, approvers)
    }

    fn sign(key: &SigningKey, issued: &Issued, approver_id: &str) -> device_v1::Approval {
        let signature: Signature = key.sign(&signed_message(&issued.payload));
        device_v1::Approval {
            approval_id: issued.approval_id.clone(),
            approver_id: approver_id.to_owned(),
            signature: signature.to_bytes().to_vec(),
        }
    }

    #[test]
    fn payload_describes_exactly_the_command() {
        let pending = PendingApprovals::new(Duration::from_secs(60), 8);
        let issued = pending
            .issue("Nick's MacBook", &spec(&["-rf", "build"]))
            .unwrap();
        let payload = device_v1::ApprovalPayload::decode(issued.payload.as_slice()).unwrap();
        assert_eq!(payload.approval_id, issued.approval_id);
        assert_eq!(payload.device_name, "Nick's MacBook");
        assert_eq!(payload.program, "/bin/rm");
        assert_eq!(payload.args, ["-rf", "build"]);
        assert_eq!(payload.working_directory, "/tmp/work");
        assert!(payload.sandbox.unwrap().writable);
    }

    #[test]
    fn a_valid_signature_is_accepted_once() {
        let (key, approvers) = approver();
        let pending = PendingApprovals::new(Duration::from_secs(60), 8);
        let command = spec(&["-rf", "build"]);
        let issued = pending.issue("mac", &command).unwrap();
        let approval = sign(&key, &issued, "phone");

        assert_eq!(
            pending.redeem(&approvers, &approval, &command).unwrap(),
            "phone"
        );
        assert_eq!(
            pending.redeem(&approvers, &approval, &command),
            Err(ApprovalError::Expired),
            "replay"
        );
    }

    #[test]
    fn approval_cannot_be_moved_to_another_command() {
        let (key, approvers) = approver();
        let pending = PendingApprovals::new(Duration::from_secs(60), 8);
        let issued = pending.issue("mac", &spec(&["-rf", "build"])).unwrap();
        let approval = sign(&key, &issued, "phone");

        let other = spec(&["-rf", "/"]);
        assert!(matches!(
            pending.redeem(&approvers, &approval, &other),
            Err(ApprovalError::Invalid(_))
        ));
    }

    #[test]
    fn signatures_from_unknown_keys_or_over_other_bytes_fail() {
        let (_, approvers) = approver();
        let (stranger, _) = approver();
        let pending = PendingApprovals::new(Duration::from_secs(60), 8);
        let command = spec(&["x"]);

        let issued = pending.issue("mac", &command).unwrap();
        let forged = sign(&stranger, &issued, "phone");
        assert!(matches!(
            pending.redeem(&approvers, &forged, &command),
            Err(ApprovalError::Invalid(_))
        ));

        // Signing the payload without the domain-separation prefix is rejected.
        let (key, approvers) = approver();
        let issued = pending.issue("mac", &command).unwrap();
        let raw: Signature = key.sign(&issued.payload);
        let approval = device_v1::Approval {
            approval_id: issued.approval_id.clone(),
            approver_id: "phone".into(),
            signature: raw.to_bytes().to_vec(),
        };
        assert!(matches!(
            pending.redeem(&approvers, &approval, &command),
            Err(ApprovalError::Invalid(_))
        ));

        let issued = pending.issue("mac", &command).unwrap();
        let unknown = sign(&key, &issued, "someone-else");
        assert!(matches!(
            pending.redeem(&approvers, &unknown, &command),
            Err(ApprovalError::Invalid(_))
        ));
    }

    #[test]
    fn approvals_expire_and_capacity_is_bounded() {
        let (key, approvers) = approver();
        let pending = PendingApprovals::new(Duration::from_millis(20), 2);
        let command = spec(&["x"]);
        let issued = pending.issue("mac", &command).unwrap();
        pending.issue("mac", &command).unwrap();
        assert_eq!(
            pending.issue("mac", &command).unwrap_err(),
            ApprovalError::TooManyPending
        );

        std::thread::sleep(Duration::from_millis(40));
        let approval = sign(&key, &issued, "phone");
        assert_eq!(
            pending.redeem(&approvers, &approval, &command),
            Err(ApprovalError::Expired)
        );
        assert!(
            pending.issue("mac", &command).is_ok(),
            "expired entries are evicted"
        );
    }

    #[test]
    fn fingerprint_distinguishes_argument_boundaries() {
        assert_ne!(
            spec(&["ab", "c"]).fingerprint(),
            spec(&["a", "bc"]).fingerprint()
        );
        let mut network = spec(&["x"]);
        network.grants.network = true;
        assert_ne!(network.fingerprint(), spec(&["x"]).fingerprint());
    }

    #[test]
    fn bad_approver_keys_are_rejected() {
        let mut approvers = Approvers::default();
        assert!(approvers.insert("a", "not base64!").is_err());
        assert!(approvers.insert("a", "AAAA").is_err());
        assert!(approvers.insert("", "AAAA").is_err());
        assert!(approvers.insert("bad\"id", "AAAA").is_err());
    }
}
