//! Envelope encryption for stored provider keys.
//!
//! Every secret gets its own random 256-bit data key (DEK) and is encrypted
//! with AES-256-GCM. The DEK is then encrypted ("wrapped") with the
//! key-encryption key (KEK), also AES-256-GCM. Both layers authenticate the
//! owner of the secret (tenant, key id, provider) as associated data, so a
//! ciphertext copied into another row fails to decrypt instead of leaking.
//!
//! The KEK is derived from an operator passphrase with Argon2id and never
//! leaves process memory. All buffers holding key material or plaintext are
//! zeroized when dropped.

use std::fmt;

use aes_gcm::{
    Aes256Gcm,
    aead::{Aead, AeadInOut, KeyInit, Payload},
};
use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::domain::Provider;

/// Length of the KEK and of every DEK, in bytes (AES-256).
pub const KEY_LEN: usize = 32;
pub const MIN_PASSPHRASE_LEN: usize = 32;
pub const MIN_SALT_LEN: usize = 16;

const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;

// Argon2id cost (RFC 9106 §4, second recommended option). Changing any of
// these changes the derived KEK; the KEK registry refuses to start against a
// database written under a different one.
const ARGON2_MEMORY_KIB: u32 = 64 * 1024;
const ARGON2_ITERATIONS: u32 = 3;
const ARGON2_PARALLELISM: u32 = 4;

// Domain-separation labels. Bumping a version makes old data unreadable, so
// they only change together with a migration.
const AAD_SECRET: &[u8] = b"jarvis-vault/v1/secret";
const AAD_DEK: &[u8] = b"jarvis-vault/v1/dek";
const AAD_DATA: &[u8] = b"jarvis-vault/v1/data";
const AAD_DATA_DEK: &[u8] = b"jarvis-vault/v1/data-dek";
/// Leading bytes of every sealed-data blob (format version 1).
const DATA_MAGIC: &[u8; 4] = b"JVD1";
const HKDF_KEK_ID: &[u8] = b"jarvis-vault/v1/kek-id";
const HKDF_FINGERPRINT: &[u8] = b"jarvis-vault/v1/request-fingerprint";

type Nonce = aes_gcm::aead::Nonce<Aes256Gcm>;

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("master passphrase must be at least {MIN_PASSPHRASE_LEN} bytes")]
    WeakPassphrase,
    #[error("master salt must be at least {MIN_SALT_LEN} bytes")]
    ShortSalt,
    #[error("key derivation failed")]
    KeyDerivation,
    #[error("operating system random number generator failed")]
    Rng,
    #[error("encryption failed")]
    Encrypt,
    #[error("decryption failed: ciphertext, key or owner binding do not match")]
    Decrypt,
    #[error("secret was sealed under KEK {found}, but the active KEK is {expected}")]
    KekMismatch { expected: String, found: String },
    #[error("malformed sealed secret: {0}")]
    Malformed(&'static str),
}

/// Who a secret belongs to. Authenticated (not encrypted) with every layer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SecretOwner {
    pub tenant_id: Uuid,
    pub key_id: Uuid,
    pub provider: Provider,
}

impl SecretOwner {
    /// `label || 0x00 || tenant_id (16 bytes) || key_id (16 bytes) || provider`.
    /// Labels contain no NUL and the ids are fixed-width, so the encoding is
    /// unambiguous.
    fn associated_data(&self, label: &[u8]) -> Vec<u8> {
        let provider = self.provider.as_str().as_bytes();
        let mut aad = Vec::with_capacity(label.len() + 1 + 32 + provider.len());
        aad.extend_from_slice(label);
        aad.push(0);
        aad.extend_from_slice(self.tenant_id.as_bytes());
        aad.extend_from_slice(self.key_id.as_bytes());
        aad.extend_from_slice(provider);
        aad
    }
}

/// Associated data for the two layers of one envelope.
struct Aad {
    dek: Vec<u8>,
    secret: Vec<u8>,
}

impl SecretOwner {
    fn aad(&self) -> Aad {
        Aad {
            dek: self.associated_data(AAD_DEK),
            secret: self.associated_data(AAD_SECRET),
        }
    }
}

/// What sealed data is bound to. Opening needs exactly the same binding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DataBinding<'a> {
    pub tenant_id: Uuid,
    pub purpose: &'a str,
    pub subject_id: &'a str,
}

impl DataBinding<'_> {
    /// `label || 0x00 || tenant (16) || len(purpose) u8 || purpose || len(subject) u16 || subject`.
    /// Callers bound purpose to 64 and subject to 128 bytes.
    fn aad(&self) -> Aad {
        let encode = |label: &[u8]| {
            let mut aad = Vec::with_capacity(
                label.len() + 1 + 16 + 1 + self.purpose.len() + 2 + self.subject_id.len(),
            );
            aad.extend_from_slice(label);
            aad.push(0);
            aad.extend_from_slice(self.tenant_id.as_bytes());
            aad.push(u8::try_from(self.purpose.len()).unwrap_or(u8::MAX));
            aad.extend_from_slice(self.purpose.as_bytes());
            aad.extend_from_slice(
                &u16::try_from(self.subject_id.len())
                    .unwrap_or(u16::MAX)
                    .to_be_bytes(),
            );
            aad.extend_from_slice(self.subject_id.as_bytes());
            aad
        };
        Aad {
            dek: encode(AAD_DATA_DEK),
            secret: encode(AAD_DATA),
        }
    }
}

/// An envelope-encrypted secret, exactly as persisted.
#[derive(Clone, PartialEq, Eq)]
pub struct SealedSecret {
    pub kek_id: String,
    pub wrapped_dek: Vec<u8>,
    pub dek_nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub nonce: Vec<u8>,
}

impl SealedSecret {
    /// Self-describing blob for data that callers store themselves:
    /// `JVD1 | kek_id_len u8 | kek_id | dek_nonce (12) | wrapped_dek_len u16 | wrapped_dek | nonce (12) | ciphertext`.
    fn to_blob(&self) -> Result<Vec<u8>, CryptoError> {
        let kek_id_len = u8::try_from(self.kek_id.len())
            .map_err(|_| CryptoError::Malformed("KEK id too long"))?;
        let dek_len = u16::try_from(self.wrapped_dek.len())
            .map_err(|_| CryptoError::Malformed("wrapped DEK too long"))?;
        let mut blob = Vec::with_capacity(
            4 + 1
                + self.kek_id.len()
                + NONCE_LEN
                + 2
                + self.wrapped_dek.len()
                + NONCE_LEN
                + self.ciphertext.len(),
        );
        blob.extend_from_slice(DATA_MAGIC);
        blob.push(kek_id_len);
        blob.extend_from_slice(self.kek_id.as_bytes());
        blob.extend_from_slice(&self.dek_nonce);
        blob.extend_from_slice(&dek_len.to_be_bytes());
        blob.extend_from_slice(&self.wrapped_dek);
        blob.extend_from_slice(&self.nonce);
        blob.extend_from_slice(&self.ciphertext);
        Ok(blob)
    }

    fn from_blob(blob: &[u8]) -> Result<Self, CryptoError> {
        fn take<'a>(rest: &mut &'a [u8], n: usize) -> Result<&'a [u8], CryptoError> {
            if rest.len() < n {
                return Err(CryptoError::Malformed("sealed data is truncated"));
            }
            let (head, tail) = rest.split_at(n);
            *rest = tail;
            Ok(head)
        }
        let mut rest = blob;
        if take(&mut rest, 4)? != DATA_MAGIC {
            return Err(CryptoError::Malformed("not sealed data (unknown format)"));
        }
        let kek_id_len = usize::from(take(&mut rest, 1)?[0]);
        let kek_id = std::str::from_utf8(take(&mut rest, kek_id_len)?)
            .map_err(|_| CryptoError::Malformed("KEK id is not UTF-8"))?
            .to_owned();
        let dek_nonce = take(&mut rest, NONCE_LEN)?.to_vec();
        let dek_len_bytes = take(&mut rest, 2)?;
        let dek_len = usize::from(u16::from_be_bytes([dek_len_bytes[0], dek_len_bytes[1]]));
        let wrapped_dek = take(&mut rest, dek_len)?.to_vec();
        let nonce = take(&mut rest, NONCE_LEN)?.to_vec();
        if rest.len() < TAG_LEN {
            return Err(CryptoError::Malformed("sealed data is truncated"));
        }
        Ok(Self {
            kek_id,
            wrapped_dek,
            dek_nonce,
            ciphertext: rest.to_vec(),
            nonce,
        })
    }
}

impl fmt::Debug for SealedSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SealedSecret")
            .field("kek_id", &self.kek_id)
            .field("ciphertext_len", &self.ciphertext.len())
            .finish_non_exhaustive()
    }
}

/// The key-encryption key and the subkeys derived from it.
pub struct MasterKey {
    kek: Aes256Gcm,
    kek_id: String,
    fingerprint_key: Zeroizing<[u8; KEY_LEN]>,
}

impl fmt::Debug for MasterKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MasterKey")
            .field("kek_id", &self.kek_id)
            .finish_non_exhaustive()
    }
}

impl MasterKey {
    /// Derives the KEK from an operator passphrase with Argon2id.
    ///
    /// Deliberately slow (about 64 MiB and a few hundred milliseconds); call
    /// it once at startup from a blocking thread.
    pub fn derive(passphrase: &[u8], salt: &[u8]) -> Result<Self, CryptoError> {
        if passphrase.len() < MIN_PASSPHRASE_LEN {
            return Err(CryptoError::WeakPassphrase);
        }
        if salt.len() < MIN_SALT_LEN {
            return Err(CryptoError::ShortSalt);
        }
        let params = Params::new(
            ARGON2_MEMORY_KIB,
            ARGON2_ITERATIONS,
            ARGON2_PARALLELISM,
            Some(KEY_LEN),
        )
        .map_err(|_| CryptoError::KeyDerivation)?;

        let mut kek = Zeroizing::new([0u8; KEY_LEN]);
        Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
            .hash_password_into(passphrase, salt, kek.as_mut())
            .map_err(|_| CryptoError::KeyDerivation)?;
        Self::from_key_bytes(&kek)
    }

    /// Builds a master key from raw KEK bytes (tests and future KMS backends).
    pub fn from_key_bytes(kek: &[u8; KEY_LEN]) -> Result<Self, CryptoError> {
        // The KEK is uniformly random, so HKDF needs no salt.
        let hkdf = Hkdf::<Sha256>::new(None, kek);

        let mut id = [0u8; 16];
        hkdf.expand(HKDF_KEK_ID, &mut id)
            .map_err(|_| CryptoError::KeyDerivation)?;

        let mut fingerprint_key = Zeroizing::new([0u8; KEY_LEN]);
        hkdf.expand(HKDF_FINGERPRINT, fingerprint_key.as_mut())
            .map_err(|_| CryptoError::KeyDerivation)?;

        Ok(Self {
            kek: Aes256Gcm::new_from_slice(kek).map_err(|_| CryptoError::KeyDerivation)?,
            kek_id: hex(&id),
            fingerprint_key,
        })
    }

    /// Public identifier of the KEK: a one-way HKDF output, safe to store and log.
    pub fn kek_id(&self) -> &str {
        &self.kek_id
    }

    pub fn seal(&self, plaintext: &[u8], owner: &SecretOwner) -> Result<SealedSecret, CryptoError> {
        self.seal_with(plaintext, &owner.aad())
    }

    pub fn open(
        &self,
        sealed: &SealedSecret,
        owner: &SecretOwner,
    ) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        self.open_with(sealed, &owner.aad())
    }

    /// Seals data a caller stores itself; returns an opaque, versioned blob.
    pub fn seal_data(
        &self,
        plaintext: &[u8],
        binding: &DataBinding<'_>,
    ) -> Result<Vec<u8>, CryptoError> {
        self.seal_with(plaintext, &binding.aad())?.to_blob()
    }

    /// Opens a blob from [`MasterKey::seal_data`] under the same binding.
    pub fn open_data(
        &self,
        blob: &[u8],
        binding: &DataBinding<'_>,
    ) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        self.open_with(&SealedSecret::from_blob(blob)?, &binding.aad())
    }

    fn seal_with(&self, plaintext: &[u8], aad: &Aad) -> Result<SealedSecret, CryptoError> {
        let dek = Zeroizing::new(random::<KEY_LEN>()?);
        let dek_cipher =
            Aes256Gcm::new_from_slice(dek.as_ref()).map_err(|_| CryptoError::Encrypt)?;

        let nonce = random::<NONCE_LEN>()?;
        // Encrypt in a zeroizing buffer so no plaintext copy survives a failure.
        let mut buffer = Zeroizing::new(Vec::with_capacity(plaintext.len() + TAG_LEN));
        buffer.extend_from_slice(plaintext);
        dek_cipher
            .encrypt_in_place(&Nonce::from(nonce), &aad.secret, &mut *buffer)
            .map_err(|_| CryptoError::Encrypt)?;
        let ciphertext = std::mem::take(&mut *buffer);

        let dek_nonce = random::<NONCE_LEN>()?;
        let wrapped_dek = self
            .kek
            .encrypt(
                &Nonce::from(dek_nonce),
                Payload {
                    msg: dek.as_ref(),
                    aad: &aad.dek,
                },
            )
            .map_err(|_| CryptoError::Encrypt)?;

        Ok(SealedSecret {
            kek_id: self.kek_id.clone(),
            wrapped_dek,
            dek_nonce: dek_nonce.to_vec(),
            ciphertext,
            nonce: nonce.to_vec(),
        })
    }

    fn open_with(
        &self,
        sealed: &SealedSecret,
        aad: &Aad,
    ) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        if sealed.kek_id != self.kek_id {
            return Err(CryptoError::KekMismatch {
                expected: self.kek_id.clone(),
                found: sealed.kek_id.clone(),
            });
        }
        let dek_nonce = Nonce::try_from(sealed.dek_nonce.as_slice())
            .map_err(|_| CryptoError::Malformed("DEK nonce has the wrong length"))?;
        let nonce = Nonce::try_from(sealed.nonce.as_slice())
            .map_err(|_| CryptoError::Malformed("nonce has the wrong length"))?;

        let mut dek = Zeroizing::new(sealed.wrapped_dek.clone());
        self.kek
            .decrypt_in_place(&dek_nonce, &aad.dek, &mut *dek)
            .map_err(|_| CryptoError::Decrypt)?;
        let dek_cipher = Aes256Gcm::new_from_slice(&dek)
            .map_err(|_| CryptoError::Malformed("DEK has the wrong length"))?;

        let mut plaintext = Zeroizing::new(sealed.ciphertext.clone());
        dek_cipher
            .decrypt_in_place(&nonce, &aad.secret, &mut *plaintext)
            .map_err(|_| CryptoError::Decrypt)?;
        Ok(plaintext)
    }

    /// Keyed fingerprint (HMAC-SHA256) of a request payload, used to detect
    /// `request_id` reuse without storing anything derivable from the secret.
    /// Fields are length-prefixed so different splits never collide.
    pub fn fingerprint(&self, fields: &[&[u8]]) -> [u8; 32] {
        let mut mac =
            <Hmac<Sha256> as hmac::KeyInit>::new_from_slice(self.fingerprint_key.as_ref())
                .unwrap_or_else(|_| unreachable!("HMAC accepts keys of any length"));
        for field in fields {
            mac.update(&(field.len() as u64).to_be_bytes());
            mac.update(field);
        }
        mac.finalize().into_bytes().into()
    }
}

/// Constant-time equality for fingerprints and other MACs.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.ct_eq(b).into()
}

fn random<const N: usize>() -> Result<[u8; N], CryptoError> {
    let mut bytes = [0u8; N];
    getrandom::fill(&mut bytes).map_err(|_| CryptoError::Rng)?;
    Ok(bytes)
}

fn hex(bytes: &[u8]) -> String {
    use fmt::Write;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut out, b| {
            let _ = write!(out, "{b:02x}");
            out
        })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    const SECRET: &[u8] = b"sk-proj-THIS-IS-A-TEST-KEY-0123456789";

    fn master(byte: u8) -> MasterKey {
        MasterKey::from_key_bytes(&[byte; KEY_LEN]).unwrap()
    }

    fn owner() -> SecretOwner {
        SecretOwner {
            tenant_id: Uuid::now_v7(),
            key_id: Uuid::now_v7(),
            provider: Provider::OpenAi,
        }
    }

    #[test]
    fn seal_then_open_round_trips() {
        let key = master(1);
        let owner = owner();
        let sealed = key.seal(SECRET, &owner).unwrap();
        assert_eq!(key.open(&sealed, &owner).unwrap().as_slice(), SECRET);
    }

    #[test]
    fn sealed_output_hides_the_plaintext_and_is_randomised() {
        let key = master(1);
        let owner = owner();
        let a = key.seal(SECRET, &owner).unwrap();
        let b = key.seal(SECRET, &owner).unwrap();

        assert_eq!(a.ciphertext.len(), SECRET.len() + TAG_LEN);
        assert!(
            !a.ciphertext
                .windows(8)
                .any(|w| SECRET.windows(8).any(|s| s == w))
        );
        assert_ne!(a.ciphertext, b.ciphertext, "fresh DEK and nonce per seal");
        assert_ne!(a.nonce, b.nonce);
        assert_ne!(a.wrapped_dek, b.wrapped_dek);
    }

    #[test]
    fn ciphertext_moved_to_another_owner_fails_to_open() {
        let key = master(1);
        let owner = owner();
        let sealed = key.seal(SECRET, &owner).unwrap();

        let other_tenant = SecretOwner {
            tenant_id: Uuid::now_v7(),
            ..owner
        };
        let other_key = SecretOwner {
            key_id: Uuid::now_v7(),
            ..owner
        };
        let other_provider = SecretOwner {
            provider: Provider::XAi,
            ..owner
        };

        for wrong in [other_tenant, other_key, other_provider] {
            assert!(matches!(
                key.open(&sealed, &wrong),
                Err(CryptoError::Decrypt)
            ));
        }
    }

    #[test]
    fn any_tampering_is_detected() {
        let key = master(1);
        let owner = owner();
        let sealed = key.seal(SECRET, &owner).unwrap();

        let mut flipped_ciphertext = sealed.clone();
        flipped_ciphertext.ciphertext[0] ^= 1;
        let mut flipped_dek = sealed.clone();
        flipped_dek.wrapped_dek[0] ^= 1;
        let mut flipped_nonce = sealed.clone();
        flipped_nonce.nonce[0] ^= 1;

        for bad in [flipped_ciphertext, flipped_dek, flipped_nonce] {
            assert!(matches!(key.open(&bad, &owner), Err(CryptoError::Decrypt)));
        }

        let mut short_nonce = sealed;
        short_nonce.nonce.pop();
        assert!(matches!(
            key.open(&short_nonce, &owner),
            Err(CryptoError::Malformed(_))
        ));
    }

    #[test]
    fn a_different_kek_cannot_open_and_is_reported_as_mismatch() {
        let owner = owner();
        let sealed = master(1).seal(SECRET, &owner).unwrap();

        let other = master(2);
        assert_ne!(other.kek_id(), master(1).kek_id());
        assert!(matches!(
            other.open(&sealed, &owner),
            Err(CryptoError::KekMismatch { .. })
        ));

        // Even if the kek_id label is forged, authentication still fails.
        let forged = SealedSecret {
            kek_id: other.kek_id().to_owned(),
            ..sealed
        };
        assert!(matches!(
            other.open(&forged, &owner),
            Err(CryptoError::Decrypt)
        ));
    }

    #[test]
    fn passphrase_derivation_is_deterministic_and_salted() {
        let passphrase = b"correct horse battery staple and then some";
        let a = MasterKey::derive(passphrase, b"salt-salt-salt-1").unwrap();
        let b = MasterKey::derive(passphrase, b"salt-salt-salt-1").unwrap();
        let c = MasterKey::derive(passphrase, b"salt-salt-salt-2").unwrap();

        assert_eq!(a.kek_id(), b.kek_id());
        assert_ne!(a.kek_id(), c.kek_id());
        assert_eq!(a.kek_id().len(), 32);

        let owner = owner();
        let sealed = a.seal(SECRET, &owner).unwrap();
        assert_eq!(b.open(&sealed, &owner).unwrap().as_slice(), SECRET);
    }

    #[test]
    fn weak_derivation_inputs_are_rejected() {
        assert!(matches!(
            MasterKey::derive(b"too short", b"salt-salt-salt-1"),
            Err(CryptoError::WeakPassphrase)
        ));
        assert!(matches!(
            MasterKey::derive(&[b'p'; MIN_PASSPHRASE_LEN], b"short"),
            Err(CryptoError::ShortSalt)
        ));
    }

    #[test]
    fn fingerprint_is_keyed_and_boundary_safe() {
        let key = master(1);
        assert_eq!(
            key.fingerprint(&[b"ab", b"c"]),
            key.fingerprint(&[b"ab", b"c"])
        );
        assert_ne!(
            key.fingerprint(&[b"ab", b"c"]),
            key.fingerprint(&[b"a", b"bc"])
        );
        assert_ne!(key.fingerprint(&[b"ab"]), master(2).fingerprint(&[b"ab"]));
    }

    #[test]
    fn debug_output_contains_no_key_material() {
        let key = master(7);
        let sealed = key.seal(SECRET, &owner()).unwrap();
        let rendered = format!("{key:?} {sealed:?}");
        assert!(rendered.contains(key.kek_id()));
        assert!(!rendered.contains("THIS-IS-A-TEST-KEY"));
        assert!(!rendered.contains(&format!("{:?}", &sealed.ciphertext[..4])));
    }

    fn binding(tenant: Uuid) -> DataBinding<'static> {
        DataBinding {
            tenant_id: tenant,
            purpose: "mcp.oauth-tokens",
            subject_id: "integration-1",
        }
    }

    #[test]
    fn sealed_data_round_trips_only_under_its_binding() {
        let key = master(1);
        let tenant = Uuid::now_v7();
        let blob = key
            .seal_data(b"refresh-token-value", &binding(tenant))
            .unwrap();
        assert!(
            !blob
                .windows(8)
                .any(|w| b"refresh-token-value".windows(8).any(|s| s == w))
        );
        assert_eq!(
            key.open_data(&blob, &binding(tenant)).unwrap().as_slice(),
            b"refresh-token-value"
        );

        let wrong = [
            DataBinding {
                tenant_id: Uuid::now_v7(),
                ..binding(tenant)
            },
            DataBinding {
                purpose: "mcp.other",
                ..binding(tenant)
            },
            DataBinding {
                subject_id: "integration-2",
                ..binding(tenant)
            },
        ];
        for binding in wrong {
            assert!(matches!(
                key.open_data(&blob, &binding),
                Err(CryptoError::Decrypt)
            ));
        }
    }

    #[test]
    fn sealed_data_and_provider_keys_are_not_interchangeable() {
        let key = master(1);
        let tenant = Uuid::now_v7();
        let blob = key.seal_data(b"x-secret-value", &binding(tenant)).unwrap();
        let sealed = SealedSecret::from_blob(&blob).unwrap();
        let owner = SecretOwner {
            tenant_id: tenant,
            key_id: Uuid::now_v7(),
            provider: Provider::OpenAi,
        };
        assert!(matches!(
            key.open(&sealed, &owner),
            Err(CryptoError::Decrypt)
        ));
    }

    #[test]
    fn malformed_or_foreign_blobs_are_rejected() {
        let key = master(1);
        let tenant = Uuid::now_v7();
        let blob = key.seal_data(b"secret-data", &binding(tenant)).unwrap();

        let mut tampered = blob.clone();
        *tampered.last_mut().unwrap() ^= 1;
        assert!(matches!(
            key.open_data(&tampered, &binding(tenant)),
            Err(CryptoError::Decrypt)
        ));

        for bad in [&b""[..], b"JVD1", b"XXXX\x00", &blob[..blob.len() - 20]] {
            assert!(
                matches!(
                    key.open_data(bad, &binding(tenant)),
                    Err(CryptoError::Malformed(_))
                ),
                "{bad:?}"
            );
        }
        assert!(matches!(
            master(2).open_data(&blob, &binding(tenant)),
            Err(CryptoError::KekMismatch { .. })
        ));
    }
}
