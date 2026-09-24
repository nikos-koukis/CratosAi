// Package store keeps pairing codes and app sessions in PostgreSQL. Secrets
// (pairing codes, refresh tokens) are only ever stored as SHA-256 hashes.
package store

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed migrations/*.sql
var migrations embed.FS

// ErrNotFound means no row matched (including rows of another tenant or user).
var ErrNotFound = errors.New("not found")

// Revocation reasons (logged and stored).
const (
	ReasonSignedOut = "signed out"
	ReasonRevoked   = "revoked by the user"
	ReasonReused    = "refresh token reused"
)

// Session is a paired app.
type Session struct {
	ID               uuid.UUID
	TenantID         uuid.UUID
	UserID           string
	DeviceName       string
	DeviceModel      string
	RefreshExpiresAt time.Time
	CreatedAt        time.Time
	LastUsedAt       time.Time
	RevokedAt        *time.Time
}

// Active reports whether the session may still be used.
func (s Session) Active(now time.Time) bool {
	return s.RevokedAt == nil && now.Before(s.RefreshExpiresAt)
}

// RefreshOutcome says what a refresh did.
type RefreshOutcome int

const (
	// Rotated: the current token was exchanged for a new one.
	Rotated RefreshOutcome = iota + 1
	// Retried: the previous token was presented within the grace period
	// (the app lost the last response); it was exchanged again.
	Retried
	// Reused: the previous token was presented after the grace period; the
	// session was ended.
	Reused
)

// Store is backed by a pgx pool.
type Store struct{ pool *pgxpool.Pool }

// New wraps a pool.
func New(pool *pgxpool.Pool) *Store { return &Store{pool: pool} }

// Ping checks the database.
func (s *Store) Ping(ctx context.Context) error { return s.pool.Ping(ctx) }

// Migrate applies pending migrations under an advisory lock.
func (s *Store) Migrate(ctx context.Context) error {
	conn, err := s.pool.Acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()
	if _, err := conn.Exec(ctx, `SELECT pg_advisory_lock(hashtext('app-api-migrations'))`); err != nil {
		return err
	}
	defer func() {
		_, _ = conn.Exec(context.Background(), `SELECT pg_advisory_unlock(hashtext('app-api-migrations'))`)
	}()
	if _, err := conn.Exec(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		version text PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())`); err != nil {
		return err
	}
	names, err := fs.Glob(migrations, "migrations/*.sql")
	if err != nil {
		return err
	}
	sort.Strings(names)
	for _, name := range names {
		version := strings.TrimSuffix(strings.TrimPrefix(name, "migrations/"), ".sql")
		var applied bool
		if err := conn.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM schema_migrations WHERE version = $1)`,
			version).Scan(&applied); err != nil {
			return err
		}
		if applied {
			continue
		}
		sql, err := migrations.ReadFile(name)
		if err != nil {
			return err
		}
		err = pgx.BeginFunc(ctx, conn, func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, string(sql)); err != nil {
				return fmt.Errorf("migration %s: %w", version, err)
			}
			_, err := tx.Exec(ctx, `INSERT INTO schema_migrations (version) VALUES ($1)`, version)
			return err
		})
		if err != nil {
			return err
		}
	}
	return nil
}

func notFound(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	return err
}

const sessionColumns = `id, tenant_id, user_id, device_name, device_model, refresh_expires_at, created_at,
	last_used_at, revoked_at`

func scanSession(row pgx.Row) (Session, error) {
	var s Session
	err := row.Scan(&s.ID, &s.TenantID, &s.UserID, &s.DeviceName, &s.DeviceModel, &s.RefreshExpiresAt,
		&s.CreatedAt, &s.LastUsedAt, &s.RevokedAt)
	return s, notFound(err)
}

// --- pairing -----------------------------------------------------------------------

// CreatePairingCode stores a code (by hash) for a user.
func (s *Store) CreatePairingCode(ctx context.Context, codeHash []byte, tenant uuid.UUID, user string, expires time.Time) error {
	_, err := s.pool.Exec(ctx, `INSERT INTO pairing_codes (code_hash, tenant_id, user_id, expires_at)
		VALUES ($1, $2, $3, $4)`, codeHash, tenant, user, expires)
	return err
}

// NewSession is a session about to be created.
type NewSession struct {
	ID               uuid.UUID
	DeviceName       string
	DeviceModel      string
	RefreshHash      []byte
	RefreshExpiresAt time.Time
}

// RedeemPairingCode uses up an unexpired code and creates the session, in
// one transaction. An unknown, used or expired code is ErrNotFound.
func (s *Store) RedeemPairingCode(ctx context.Context, codeHash []byte, n NewSession) (Session, error) {
	var out Session
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		var tenant uuid.UUID
		var user string
		err := tx.QueryRow(ctx, `UPDATE pairing_codes SET redeemed_at = now(), session_id = $2
			WHERE code_hash = $1 AND redeemed_at IS NULL AND expires_at > now()
			RETURNING tenant_id, user_id`, codeHash, n.ID).Scan(&tenant, &user)
		if err != nil {
			return notFound(err)
		}
		out, err = scanSession(tx.QueryRow(ctx, `INSERT INTO sessions (id, tenant_id, user_id, device_name,
			device_model, refresh_hash, refresh_expires_at) VALUES ($1, $2, $3, $4, $5, $6, $7)
			RETURNING `+sessionColumns, n.ID, tenant, user, n.DeviceName, n.DeviceModel, n.RefreshHash,
			n.RefreshExpiresAt))
		return err
	})
	return out, err
}

// --- sessions ----------------------------------------------------------------------

// Refresh exchanges a refresh token (by hash) for a new one, in one
// transaction:
//   - the current token rotates;
//   - the previous token within `grace` of its rotation rotates again (the
//     app lost the response);
//   - the previous token after that ends the session (Reused), since only
//     a copy of the token can explain it;
//   - anything else, or an ended or expired session, is ErrNotFound.
func (s *Store) Refresh(ctx context.Context, presented, next []byte, idleTTL, grace time.Duration) (Session, RefreshOutcome, error) {
	var out Session
	var outcome RefreshOutcome
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		var id uuid.UUID
		var current, inGrace bool
		err := tx.QueryRow(ctx, `SELECT id, refresh_hash = $1,
			  COALESCE(rotated_at > now() - make_interval(secs => $2), false)
			FROM sessions
			WHERE (refresh_hash = $1 OR previous_hash = $1) AND revoked_at IS NULL AND refresh_expires_at > now()
			FOR UPDATE`, presented, grace.Seconds()).Scan(&id, &current, &inGrace)
		if err != nil {
			return notFound(err)
		}
		switch {
		case current:
			outcome = Rotated
			out, err = scanSession(tx.QueryRow(ctx, `UPDATE sessions SET previous_hash = refresh_hash,
				refresh_hash = $2, rotated_at = now(), refresh_expires_at = now() + make_interval(secs => $3),
				last_used_at = now() WHERE id = $1 RETURNING `+sessionColumns, id, next, idleTTL.Seconds()))
			return err
		case inGrace:
			// The token the app never received is dropped; rotated_at stays,
			// so the grace period does not extend.
			outcome = Retried
			out, err = scanSession(tx.QueryRow(ctx, `UPDATE sessions SET refresh_hash = $2,
				last_used_at = now() WHERE id = $1 RETURNING `+sessionColumns, id, next))
			return err
		default:
			outcome = Reused
			out, err = scanSession(tx.QueryRow(ctx, `UPDATE sessions SET revoked_at = now(), revoke_reason = $2
				WHERE id = $1 RETURNING `+sessionColumns, id, ReasonReused))
			return err
		}
	})
	return out, outcome, err
}

// Session loads a session by id.
func (s *Store) Session(ctx context.Context, id uuid.UUID) (Session, error) {
	return scanSession(s.pool.QueryRow(ctx, `SELECT `+sessionColumns+` FROM sessions WHERE id = $1`, id))
}

// SignOut ends the session of a refresh token (current or previous);
// unknown tokens are ignored.
func (s *Store) SignOut(ctx context.Context, presented []byte) (Session, bool, error) {
	session, err := scanSession(s.pool.QueryRow(ctx, `UPDATE sessions SET revoked_at = now(), revoke_reason = $2
		WHERE (refresh_hash = $1 OR previous_hash = $1) AND revoked_at IS NULL RETURNING `+sessionColumns,
		presented, ReasonSignedOut))
	if errors.Is(err, ErrNotFound) {
		return Session{}, false, nil
	}
	return session, err == nil, err
}

// Sessions lists a user's active sessions, most recently used first.
func (s *Store) Sessions(ctx context.Context, tenant uuid.UUID, user string) ([]Session, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+sessionColumns+` FROM sessions
		WHERE tenant_id = $1 AND user_id = $2 AND revoked_at IS NULL AND refresh_expires_at > now()
		ORDER BY last_used_at DESC LIMIT 100`, tenant, user)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (Session, error) { return scanSession(row) })
}

// Revoke ends a user's session; it reports whether one was active.
func (s *Store) Revoke(ctx context.Context, tenant uuid.UUID, user string, id uuid.UUID, reason string) (bool, error) {
	tag, err := s.pool.Exec(ctx, `UPDATE sessions SET revoked_at = now(), revoke_reason = $4
		WHERE id = $1 AND tenant_id = $2 AND user_id = $3 AND revoked_at IS NULL`, id, tenant, user, reason)
	return tag.RowsAffected() == 1, err
}

// Purge deletes pairing codes and ended sessions older than `keep`.
func (s *Store) Purge(ctx context.Context, keep time.Duration) (int64, error) {
	var total int64
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		codes, err := tx.Exec(ctx, `DELETE FROM pairing_codes WHERE expires_at < now() - make_interval(secs => $1)`,
			keep.Seconds())
		if err != nil {
			return err
		}
		// Ended (revoked, or expired) longer than `keep` ago.
		sessions, err := tx.Exec(ctx, `DELETE FROM sessions
			WHERE COALESCE(revoked_at, refresh_expires_at) < now() - make_interval(secs => $1)`, keep.Seconds())
		total = codes.RowsAffected() + sessions.RowsAffected()
		return err
	})
	return total, err
}

// --- push tokens ---------------------------------------------------------------

// PushToken is where a session's push notifications go.
type PushToken struct {
	SessionID   uuid.UUID
	DeviceToken string
	Environment string // "sandbox" or "production"
}

// SetPushToken sets a session's device token. The token leaves any other
// session: a phone gets the notifications of its current session only.
func (s *Store) SetPushToken(ctx context.Context, session uuid.UUID, token, environment string) error {
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `DELETE FROM push_tokens WHERE device_token = $1 AND session_id <> $2`,
			token, session); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO push_tokens (session_id, device_token, environment) VALUES ($1, $2, $3)
			ON CONFLICT (session_id) DO UPDATE SET device_token = excluded.device_token,
			  environment = excluded.environment, updated_at = now()`, session, token, environment)
		return err
	})
}

// DeletePushToken removes a session's device token.
func (s *Store) DeletePushToken(ctx context.Context, session uuid.UUID) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM push_tokens WHERE session_id = $1`, session)
	return err
}

// ForgetDeviceToken removes a device token APNs no longer accepts.
func (s *Store) ForgetDeviceToken(ctx context.Context, token string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM push_tokens WHERE device_token = $1`, token)
	return err
}

// PushTokens returns the device tokens of a user's active sessions.
func (s *Store) PushTokens(ctx context.Context, tenant uuid.UUID, user string) ([]PushToken, error) {
	rows, err := s.pool.Query(ctx, `SELECT p.session_id, p.device_token, p.environment
		FROM push_tokens p JOIN sessions s ON s.id = p.session_id
		WHERE s.tenant_id = $1 AND s.user_id = $2 AND s.revoked_at IS NULL AND s.refresh_expires_at > now()`,
		tenant, user)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (PushToken, error) {
		var t PushToken
		err := row.Scan(&t.SessionID, &t.DeviceToken, &t.Environment)
		return t, err
	})
}
