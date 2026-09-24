//! PostgreSQL persistence for provider keys. Only ciphertext and metadata are
//! stored; this module never sees plaintext.

use chrono::{DateTime, Utc};
use sqlx::{PgPool, migrate::Migrator};
use uuid::Uuid;

use crate::{
    crypto::{SealedSecret, constant_time_eq},
    domain::{KeyMetadata, KeyStatus, Provider, RevocationReason},
    error::VaultError,
};

pub static MIGRATOR: Migrator = sqlx::migrate!("./migrations");

macro_rules! metadata_columns {
    () => {
        "key_id, tenant_id, provider, label, key_hint, status, create_time, revoke_time, revocation_reason"
    };
}

macro_rules! revoke_assignments {
    () => {
        "status = 'revoked', revoke_time = now(), kek_id = NULL, wrapped_dek = NULL, \
         dek_nonce = NULL, ciphertext = NULL, nonce = NULL"
    };
}

/// Retry protection for CreateKey.
#[derive(Clone, Copy, Debug)]
pub struct Idempotency {
    pub request_id: Uuid,
    pub fingerprint: [u8; 32],
}

#[derive(Debug)]
pub struct NewKey<'a> {
    pub key_id: Uuid,
    pub tenant_id: Uuid,
    pub provider: Provider,
    pub label: &'a str,
    pub key_hint: &'a str,
    pub sealed: &'a SealedSecret,
    pub replace_active: bool,
    pub created_by: &'a str,
    pub idempotency: Option<Idempotency>,
}

#[derive(Debug)]
pub struct Created {
    pub key: KeyMetadata,
    pub replaced: Option<KeyMetadata>,
    /// True if this was a retry answered from the idempotency record.
    pub replayed: bool,
}

#[derive(Clone, Copy, Debug)]
pub enum KeySelector {
    Id(Uuid),
    /// The tenant's single ACTIVE key for this provider.
    ActiveFor(Provider),
}

#[derive(Debug)]
pub struct StoredSecret {
    pub key: KeyMetadata,
    pub sealed: SealedSecret,
}

#[derive(Debug, thiserror::Error)]
pub enum KekRegistryError {
    #[error(
        "database was initialised with a different master key (registered KEK ids: {registered}); \
         refusing to start with KEK {current}"
    )]
    Mismatch { current: String, registered: String },
    #[error(transparent)]
    Database(#[from] sqlx::Error),
}

#[derive(Clone, Debug)]
pub struct KeyStore {
    pool: PgPool,
}

impl KeyStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// Registers the active KEK on first start; afterwards refuses a KEK that
    /// differs from the one the database was written with.
    pub async fn register_kek(&self, kek_id: &str) -> Result<(), KekRegistryError> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("LOCK TABLE kek_registry IN EXCLUSIVE MODE")
            .execute(&mut *tx)
            .await?;
        let registered: Vec<String> =
            sqlx::query_scalar("SELECT kek_id FROM kek_registry ORDER BY create_time")
                .fetch_all(&mut *tx)
                .await?;

        if registered.iter().any(|id| id == kek_id) {
            return Ok(());
        }
        if !registered.is_empty() {
            return Err(KekRegistryError::Mismatch {
                current: kek_id.to_owned(),
                registered: registered.join(", "),
            });
        }
        sqlx::query("INSERT INTO kek_registry (kek_id) VALUES ($1)")
            .bind(kek_id)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(())
    }

    pub async fn create(&self, new: NewKey<'_>) -> Result<Created, VaultError> {
        let mut tx = self.pool.begin().await?;

        // Claim the request id first. A concurrent retry blocks here until the
        // first attempt commits (then replays it) or rolls back (then proceeds).
        if let Some(idem) = new.idempotency {
            let claimed = sqlx::query(
                "INSERT INTO create_key_requests (tenant_id, request_id, payload_fingerprint, key_id)
                 VALUES ($1, $2, $3, $4)
                 ON CONFLICT (tenant_id, request_id) DO NOTHING",
            )
            .bind(new.tenant_id)
            .bind(idem.request_id)
            .bind(idem.fingerprint.as_slice())
            .bind(new.key_id)
            .execute(&mut *tx)
            .await?
            .rows_affected()
                == 1;
            if !claimed {
                tx.rollback().await?;
                return self.replay_create(new.tenant_id, idem).await;
            }
        }

        // Serialise writers per (tenant, provider) so rotation is deterministic.
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
            .bind(format!(
                "provider_keys:{}:{}",
                new.tenant_id,
                new.provider.as_str()
            ))
            .execute(&mut *tx)
            .await?;

        let replaced = if new.replace_active {
            sqlx::query_as::<_, MetadataRow>(concat!(
                "UPDATE provider_keys SET ",
                revoke_assignments!(),
                ", revocation_reason = 'rotated', revoked_by = $3
                 WHERE tenant_id = $1 AND provider = $2 AND status = 'active'
                 RETURNING ",
                metadata_columns!()
            ))
            .bind(new.tenant_id)
            .bind(new.provider.as_str())
            .bind(new.created_by)
            .fetch_optional(&mut *tx)
            .await?
            .map(KeyMetadata::try_from)
            .transpose()?
        } else {
            let active_exists: bool = sqlx::query_scalar(
                "SELECT EXISTS (SELECT 1 FROM provider_keys
                  WHERE tenant_id = $1 AND provider = $2 AND status = 'active')",
            )
            .bind(new.tenant_id)
            .bind(new.provider.as_str())
            .fetch_one(&mut *tx)
            .await?;
            if active_exists {
                return Err(VaultError::ActiveKeyExists);
            }
            None
        };

        let key = sqlx::query_as::<_, MetadataRow>(concat!(
            "INSERT INTO provider_keys
               (key_id, tenant_id, provider, label, key_hint, status,
                kek_id, wrapped_dek, dek_nonce, ciphertext, nonce, created_by)
             VALUES ($1, $2, $3, $4, $5, 'active', $6, $7, $8, $9, $10, $11)
             RETURNING ",
            metadata_columns!()
        ))
        .bind(new.key_id)
        .bind(new.tenant_id)
        .bind(new.provider.as_str())
        .bind(new.label)
        .bind(new.key_hint)
        .bind(&new.sealed.kek_id)
        .bind(&new.sealed.wrapped_dek)
        .bind(&new.sealed.dek_nonce)
        .bind(&new.sealed.ciphertext)
        .bind(&new.sealed.nonce)
        .bind(new.created_by)
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| match &e {
            // Belt and braces: the advisory lock already rules this out.
            sqlx::Error::Database(db) if db.is_unique_violation() => VaultError::ActiveKeyExists,
            _ => VaultError::Database(e),
        })?;

        if let (Some(idem), Some(old)) = (new.idempotency, &replaced) {
            sqlx::query(
                "UPDATE create_key_requests SET replaced_key_id = $3
                 WHERE tenant_id = $1 AND request_id = $2",
            )
            .bind(new.tenant_id)
            .bind(idem.request_id)
            .bind(old.key_id)
            .execute(&mut *tx)
            .await?;
        }

        tx.commit().await?;
        Ok(Created {
            key: key.try_into()?,
            replaced,
            replayed: false,
        })
    }

    async fn replay_create(
        &self,
        tenant_id: Uuid,
        idem: Idempotency,
    ) -> Result<Created, VaultError> {
        let (fingerprint, key_id, replaced_key_id): (Vec<u8>, Uuid, Option<Uuid>) = sqlx::query_as(
            "SELECT payload_fingerprint, key_id, replaced_key_id FROM create_key_requests
             WHERE tenant_id = $1 AND request_id = $2",
        )
        .bind(tenant_id)
        .bind(idem.request_id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or_else(|| VaultError::DataIntegrity("idempotency record vanished".into()))?;

        if !constant_time_eq(&fingerprint, &idem.fingerprint) {
            return Err(VaultError::RequestIdConflict);
        }

        let key = self.metadata(tenant_id, key_id).await?;
        let replaced = match replaced_key_id {
            Some(id) => Some(self.metadata(tenant_id, id).await?),
            None => None,
        };
        Ok(Created {
            key,
            replaced,
            replayed: true,
        })
    }

    async fn metadata(&self, tenant_id: Uuid, key_id: Uuid) -> Result<KeyMetadata, VaultError> {
        sqlx::query_as::<_, MetadataRow>(concat!(
            "SELECT ",
            metadata_columns!(),
            " FROM provider_keys WHERE tenant_id = $1 AND key_id = $2"
        ))
        .bind(tenant_id)
        .bind(key_id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(VaultError::KeyNotFound)?
        .try_into()
    }

    /// Loads an ACTIVE key's ciphertext. A key of another tenant is
    /// indistinguishable from a missing one.
    pub async fn fetch_sealed(
        &self,
        tenant_id: Uuid,
        selector: KeySelector,
    ) -> Result<StoredSecret, VaultError> {
        let row = match selector {
            KeySelector::Id(key_id) => {
                sqlx::query_as::<_, SealedRow>(concat!(
                    "SELECT ",
                    metadata_columns!(),
                    ", kek_id, wrapped_dek, dek_nonce, ciphertext, nonce FROM provider_keys
                     WHERE tenant_id = $1 AND key_id = $2"
                ))
                .bind(tenant_id)
                .bind(key_id)
                .fetch_optional(&self.pool)
                .await?
            }
            KeySelector::ActiveFor(provider) => {
                sqlx::query_as::<_, SealedRow>(concat!(
                    "SELECT ",
                    metadata_columns!(),
                    ", kek_id, wrapped_dek, dek_nonce, ciphertext, nonce FROM provider_keys
                     WHERE tenant_id = $1 AND provider = $2 AND status = 'active'"
                ))
                .bind(tenant_id)
                .bind(provider.as_str())
                .fetch_optional(&self.pool)
                .await?
            }
        };
        let row = row.ok_or(VaultError::KeyNotFound)?;
        let key = KeyMetadata::try_from(row.meta)?;
        if key.status == KeyStatus::Revoked {
            return Err(VaultError::KeyRevoked);
        }

        let integrity = || {
            VaultError::DataIntegrity(format!("active key {} lacks crypto material", key.key_id))
        };
        let sealed = SealedSecret {
            kek_id: row.kek_id.ok_or_else(integrity)?,
            wrapped_dek: row.wrapped_dek.ok_or_else(integrity)?,
            dek_nonce: row.dek_nonce.ok_or_else(integrity)?,
            ciphertext: row.ciphertext.ok_or_else(integrity)?,
            nonce: row.nonce.ok_or_else(integrity)?,
        };
        Ok(StoredSecret { key, sealed })
    }

    /// Revokes a key and destroys its crypto material. Revoking an already
    /// revoked key returns its existing metadata unchanged.
    /// A tenant's keys, newest first (at most `limit`).
    pub async fn list(
        &self,
        tenant_id: Uuid,
        include_revoked: bool,
        limit: i64,
    ) -> Result<Vec<KeyMetadata>, VaultError> {
        sqlx::query_as::<_, MetadataRow>(concat!(
            "SELECT ",
            metadata_columns!(),
            " FROM provider_keys WHERE tenant_id = $1 AND ($2 OR status = 'active')
             ORDER BY create_time DESC, key_id DESC LIMIT $3"
        ))
        .bind(tenant_id)
        .bind(include_revoked)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?
        .into_iter()
        .map(TryInto::try_into)
        .collect()
    }

    pub async fn revoke(
        &self,
        tenant_id: Uuid,
        key_id: Uuid,
        reason: RevocationReason,
        revoked_by: &str,
    ) -> Result<KeyMetadata, VaultError> {
        let revoked = sqlx::query_as::<_, MetadataRow>(concat!(
            "UPDATE provider_keys SET ",
            revoke_assignments!(),
            ", revocation_reason = $3, revoked_by = $4
             WHERE tenant_id = $1 AND key_id = $2 AND status = 'active'
             RETURNING ",
            metadata_columns!()
        ))
        .bind(tenant_id)
        .bind(key_id)
        .bind(reason.as_str())
        .bind(revoked_by)
        .fetch_optional(&self.pool)
        .await?;

        match revoked {
            Some(row) => row.try_into(),
            None => self.metadata(tenant_id, key_id).await,
        }
    }
}

#[derive(sqlx::FromRow)]
struct MetadataRow {
    key_id: Uuid,
    tenant_id: Uuid,
    provider: String,
    label: String,
    key_hint: String,
    status: String,
    create_time: DateTime<Utc>,
    revoke_time: Option<DateTime<Utc>>,
    revocation_reason: Option<String>,
}

#[derive(sqlx::FromRow)]
struct SealedRow {
    #[sqlx(flatten)]
    meta: MetadataRow,
    kek_id: Option<String>,
    wrapped_dek: Option<Vec<u8>>,
    dek_nonce: Option<Vec<u8>>,
    ciphertext: Option<Vec<u8>>,
    nonce: Option<Vec<u8>>,
}

impl TryFrom<MetadataRow> for KeyMetadata {
    type Error = VaultError;

    fn try_from(row: MetadataRow) -> Result<Self, Self::Error> {
        let bad = |column: &str, value: &str| {
            VaultError::DataIntegrity(format!("key {}: unknown {column} {value:?}", row.key_id))
        };
        Ok(Self {
            provider: Provider::from_db(&row.provider)
                .ok_or_else(|| bad("provider", &row.provider))?,
            status: KeyStatus::from_db(&row.status).ok_or_else(|| bad("status", &row.status))?,
            revocation_reason: row
                .revocation_reason
                .as_deref()
                .map(|r| RevocationReason::from_db(r).ok_or_else(|| bad("revocation_reason", r)))
                .transpose()?,
            key_id: row.key_id,
            tenant_id: row.tenant_id,
            label: row.label,
            key_hint: row.key_hint,
            create_time: row.create_time,
            revoke_time: row.revoke_time,
        })
    }
}
