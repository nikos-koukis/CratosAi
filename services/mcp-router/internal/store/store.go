// Package store persists integrations, OAuth client registrations and
// pending authorizations in PostgreSQL.
package store

import (
	"context"
	"crypto/sha256"
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

// Status of an integration.
type Status string

const (
	StatusPending     Status = "pending"
	StatusConnected   Status = "connected"
	StatusNeedsReauth Status = "needs_reauth"
)

// AuthKind of an integration.
type AuthKind string

const (
	AuthOAuth  AuthKind = "oauth"
	AuthBearer AuthKind = "bearer"
)

// Integration is a user's connection to one MCP server.
type Integration struct {
	ID                uuid.UUID
	TenantID          uuid.UUID
	UserID            string
	DisplayName       string
	ServerURL         string
	CatalogSlug       string
	Auth              AuthKind
	Status            Status
	StatusDetail      string
	Issuer            string
	TokenEndpoint     string
	RedirectURI       string
	CredentialsSealed []byte
	CreatedAt         time.Time
	UpdatedAt         time.Time
}

// OAuthClient is a client registration at an authorization server.
type OAuthClient struct {
	Issuer             string
	RedirectURI        string
	ClientID           string
	ClientSecretSealed []byte
	Registration       string
	// SecretExpiresAt is when a dynamic registration expires; zero is never.
	SecretExpiresAt time.Time
}

// Pending is an authorization waiting for the user.
type Pending struct {
	IntegrationID  uuid.UUID
	Issuer         string
	TokenEndpoint  string
	Resource       string
	RedirectURI    string
	IssRequired    bool
	VerifierSealed []byte
	ExpiresAt      time.Time
}

// Store is backed by a pgx pool.
type Store struct{ pool *pgxpool.Pool }

// New wraps a pool.
func New(pool *pgxpool.Pool) *Store { return &Store{pool: pool} }

// Migrate applies pending migrations under an advisory lock, so concurrent
// router instances cannot race.
func (s *Store) Migrate(ctx context.Context) error {
	conn, err := s.pool.Acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()
	if _, err := conn.Exec(ctx, `SELECT pg_advisory_lock(hashtext('mcp-router-migrations'))`); err != nil {
		return err
	}
	defer func() {
		_, _ = conn.Exec(context.Background(), `SELECT pg_advisory_unlock(hashtext('mcp-router-migrations'))`)
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
		if err := conn.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM schema_migrations WHERE version = $1)`, version).Scan(&applied); err != nil {
			return err
		}
		if applied {
			continue
		}
		sql, err := migrations.ReadFile(name)
		if err != nil {
			return err
		}
		tx, err := conn.Begin(ctx)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, string(sql)); err != nil {
			_ = tx.Rollback(ctx)
			return fmt.Errorf("migration %s: %w", version, err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO schema_migrations (version) VALUES ($1)`, version); err != nil {
			_ = tx.Rollback(ctx)
			return err
		}
		if err := tx.Commit(ctx); err != nil {
			return err
		}
	}
	return nil
}

const integrationColumns = `id, tenant_id, user_id, display_name, server_url, coalesce(catalog_slug, ''),
	auth_kind, status, status_detail, coalesce(issuer, ''), coalesce(token_endpoint, ''),
	coalesce(redirect_uri, ''), credentials_sealed, created_at, updated_at`

func scanIntegration(row pgx.Row) (Integration, error) {
	var i Integration
	err := row.Scan(&i.ID, &i.TenantID, &i.UserID, &i.DisplayName, &i.ServerURL, &i.CatalogSlug,
		&i.Auth, &i.Status, &i.StatusDetail, &i.Issuer, &i.TokenEndpoint, &i.RedirectURI,
		&i.CredentialsSealed, &i.CreatedAt, &i.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return i, ErrNotFound
	}
	return i, err
}

func nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// CreateIntegration inserts a new integration.
func (s *Store) CreateIntegration(ctx context.Context, i Integration) (Integration, error) {
	return scanIntegration(s.pool.QueryRow(ctx, `
		INSERT INTO integrations (id, tenant_id, user_id, display_name, server_url, catalog_slug, auth_kind, status, credentials_sealed)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		RETURNING `+integrationColumns,
		i.ID, i.TenantID, i.UserID, i.DisplayName, i.ServerURL, nullable(i.CatalogSlug), i.Auth, i.Status, i.CredentialsSealed))
}

// Integration loads one integration of a tenant and user.
func (s *Store) Integration(ctx context.Context, tenant uuid.UUID, user string, id uuid.UUID) (Integration, error) {
	return scanIntegration(s.pool.QueryRow(ctx,
		`SELECT `+integrationColumns+` FROM integrations WHERE id = $1 AND tenant_id = $2 AND user_id = $3`, id, tenant, user))
}

// IntegrationByID loads an integration for internal use (OAuth callbacks).
func (s *Store) IntegrationByID(ctx context.Context, id uuid.UUID) (Integration, error) {
	return scanIntegration(s.pool.QueryRow(ctx, `SELECT `+integrationColumns+` FROM integrations WHERE id = $1`, id))
}

// Integrations lists a user's integrations, newest first.
func (s *Store) Integrations(ctx context.Context, tenant uuid.UUID, user string) ([]Integration, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+integrationColumns+` FROM integrations
		WHERE tenant_id = $1 AND user_id = $2 ORDER BY created_at DESC`, tenant, user)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Integration
	for rows.Next() {
		i, err := scanIntegration(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, i)
	}
	return out, rows.Err()
}

// Connect stores credentials and marks the integration connected.
func (s *Store) Connect(ctx context.Context, id uuid.UUID, issuer, tokenEndpoint, redirectURI string, sealed []byte) (Integration, error) {
	return scanIntegration(s.pool.QueryRow(ctx, `
		UPDATE integrations SET status = 'connected', status_detail = '', issuer = $2, token_endpoint = $3,
			redirect_uri = $4, credentials_sealed = $5, updated_at = now()
		WHERE id = $1 RETURNING `+integrationColumns, id, nullable(issuer), nullable(tokenEndpoint), nullable(redirectURI), sealed))
}

// UpdateCredentials replaces sealed credentials (e.g. after a token refresh)
// and returns the new updated_at.
func (s *Store) UpdateCredentials(ctx context.Context, id uuid.UUID, sealed []byte) (time.Time, error) {
	var updated time.Time
	err := s.pool.QueryRow(ctx, `UPDATE integrations SET credentials_sealed = $2, updated_at = now() WHERE id = $1
		RETURNING updated_at`, id, sealed).Scan(&updated)
	if errors.Is(err, pgx.ErrNoRows) {
		return updated, ErrNotFound
	}
	return updated, err
}

// SetStatus records a status change with a reason.
func (s *Store) SetStatus(ctx context.Context, id uuid.UUID, status Status, detail string) error {
	_, err := s.pool.Exec(ctx, `UPDATE integrations SET status = $2, status_detail = $3, updated_at = now() WHERE id = $1`,
		id, status, detail)
	return err
}

// DeleteIntegration removes an integration (and its pending authorizations).
func (s *Store) DeleteIntegration(ctx context.Context, tenant uuid.UUID, user string, id uuid.UUID) (bool, error) {
	tag, err := s.pool.Exec(ctx, `DELETE FROM integrations WHERE id = $1 AND tenant_id = $2 AND user_id = $3`, id, tenant, user)
	return tag.RowsAffected() == 1, err
}

// OAuthClient returns the registration for an issuer and redirect URI.
func (s *Store) OAuthClient(ctx context.Context, issuer, redirectURI string) (OAuthClient, error) {
	var c OAuthClient
	var expires *time.Time
	err := s.pool.QueryRow(ctx, `SELECT issuer, redirect_uri, client_id, client_secret_sealed, registration, secret_expires_at
		FROM oauth_clients WHERE issuer = $1 AND redirect_uri = $2`, issuer, redirectURI).
		Scan(&c.Issuer, &c.RedirectURI, &c.ClientID, &c.ClientSecretSealed, &c.Registration, &expires)
	if errors.Is(err, pgx.ErrNoRows) {
		return c, ErrNotFound
	}
	if expires != nil {
		c.SecretExpiresAt = *expires
	}
	return c, err
}

// SaveOAuthClient stores a registration. An existing one wins (concurrent
// registrations are harmless; the first stored is used from then on) unless
// it expires before replaceBefore.
func (s *Store) SaveOAuthClient(ctx context.Context, c OAuthClient, replaceBefore time.Time) (OAuthClient, error) {
	var expires any
	if !c.SecretExpiresAt.IsZero() {
		expires = c.SecretExpiresAt
	}
	_, err := s.pool.Exec(ctx, `INSERT INTO oauth_clients (issuer, redirect_uri, client_id, client_secret_sealed, registration, secret_expires_at)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (issuer, redirect_uri) DO UPDATE SET client_id = excluded.client_id,
			client_secret_sealed = excluded.client_secret_sealed, registration = excluded.registration,
			secret_expires_at = excluded.secret_expires_at, created_at = now()
		WHERE oauth_clients.secret_expires_at IS NOT NULL AND oauth_clients.secret_expires_at <= $7`,
		c.Issuer, c.RedirectURI, c.ClientID, c.ClientSecretSealed, c.Registration, expires, replaceBefore)
	if err != nil {
		return c, err
	}
	return s.OAuthClient(ctx, c.Issuer, c.RedirectURI)
}

// DeleteDynamicClient forgets a dynamic registration the authorization
// server no longer accepts, so the next authorization registers again.
func (s *Store) DeleteDynamicClient(ctx context.Context, issuer, redirectURI, clientID string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM oauth_clients WHERE issuer = $1 AND redirect_uri = $2 AND client_id = $3
		AND registration = 'dynamic'`, issuer, redirectURI, clientID)
	return err
}

// StateHash is how a state value is stored and looked up.
func StateHash(state string) []byte {
	sum := sha256.Sum256([]byte(state))
	return sum[:]
}

// SavePending replaces any pending authorization of the integration.
func (s *Store) SavePending(ctx context.Context, state string, p Pending) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `DELETE FROM pending_authorizations WHERE integration_id = $1 OR expires_at < now()`, p.IntegrationID); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO pending_authorizations
		(state_hash, integration_id, issuer, token_endpoint, resource, redirect_uri, iss_required, verifier_sealed, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		StateHash(state), p.IntegrationID, p.Issuer, p.TokenEndpoint, p.Resource, p.RedirectURI, p.IssRequired, p.VerifierSealed, p.ExpiresAt); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// TakePending consumes a pending authorization (single use). Expired ones
// are reported as not found.
func (s *Store) TakePending(ctx context.Context, state string) (Pending, error) {
	var p Pending
	err := s.pool.QueryRow(ctx, `DELETE FROM pending_authorizations WHERE state_hash = $1
		RETURNING integration_id, issuer, token_endpoint, resource, redirect_uri, iss_required, verifier_sealed, expires_at`,
		StateHash(state)).Scan(&p.IntegrationID, &p.Issuer, &p.TokenEndpoint, &p.Resource, &p.RedirectURI,
		&p.IssRequired, &p.VerifierSealed, &p.ExpiresAt)
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && time.Now().After(p.ExpiresAt)) {
		return p, ErrNotFound
	}
	return p, err
}

// Ping checks the database.
func (s *Store) Ping(ctx context.Context) error { return s.pool.Ping(ctx) }
