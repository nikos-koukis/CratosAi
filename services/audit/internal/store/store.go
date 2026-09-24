// Package store keeps the audit trail in PostgreSQL: append-only events,
// each extending its tenant's hash chain.
package store

import (
	"bytes"
	"context"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"jarvis.internal/audit/internal/chain"
)

//go:embed migrations/*.sql
var migrations embed.FS

// Store is the audit database.
type Store struct {
	pool *pgxpool.Pool
	now  func() time.Time
}

// New wraps a connection pool.
func New(pool *pgxpool.Pool) *Store { return &Store{pool: pool, now: time.Now} }

// Ping checks the database.
func (s *Store) Ping(ctx context.Context) error { return s.pool.Ping(ctx) }

// Migrate applies pending migrations under an advisory lock.
func (s *Store) Migrate(ctx context.Context) error {
	conn, err := s.pool.Acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()
	if _, err := conn.Exec(ctx, `SELECT pg_advisory_lock(hashtext('audit-migrations'))`); err != nil {
		return err
	}
	defer func() {
		_, _ = conn.Exec(context.Background(), `SELECT pg_advisory_unlock(hashtext('audit-migrations'))`)
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

// Record is a stored event with its link in the chain.
type Record struct {
	chain.Event
	Hash []byte
}

// Append adds events recorded by source (its mTLS identity). Events must be
// valid, with canonical lowercase ids and times at chain.Precision. Events
// already recorded (same tenant and event id, also within the batch) are
// skipped and counted as duplicates.
func (s *Store) Append(ctx context.Context, source string, events []chain.Event) (recorded, duplicates int, err error) {
	byTenant := map[string][]chain.Event{}
	for _, e := range events {
		byTenant[e.TenantID] = append(byTenant[e.TenantID], e)
	}
	tenants := make([]string, 0, len(byTenant))
	for t := range byTenant {
		tenants = append(tenants, t)
	}
	// Chains are always locked in the same order, so concurrent batches
	// spanning several tenants cannot deadlock.
	sort.Strings(tenants)
	recordTime := s.now().UTC().Truncate(chain.Precision)

	err = pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		recorded, duplicates = 0, 0
		for _, tenant := range tenants {
			r, d, err := appendTenant(ctx, tx, tenant, source, recordTime, byTenant[tenant])
			if err != nil {
				return err
			}
			recorded += r
			duplicates += d
		}
		return nil
	})
	return recorded, duplicates, err
}

func appendTenant(ctx context.Context, tx pgx.Tx, tenant, source string, recordTime time.Time,
	events []chain.Event) (recorded, duplicates int, err error) {
	if _, err := tx.Exec(ctx, `INSERT INTO chains (tenant_id, last_sequence, last_hash) VALUES ($1, 0, '')
		ON CONFLICT (tenant_id) DO NOTHING`, tenant); err != nil {
		return 0, 0, err
	}
	var sequence int64
	var prev []byte
	if err := tx.QueryRow(ctx, `SELECT last_sequence, last_hash FROM chains WHERE tenant_id = $1 FOR UPDATE`,
		tenant).Scan(&sequence, &prev); err != nil {
		return 0, 0, err
	}
	ids := make([]string, len(events))
	for i, e := range events {
		ids[i] = e.EventID
	}
	rows, err := tx.Query(ctx, `SELECT event_id::text FROM events WHERE tenant_id = $1 AND event_id = ANY($2::uuid[])`,
		tenant, ids)
	if err != nil {
		return 0, 0, err
	}
	seen, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return 0, 0, err
	}

	batch := &pgx.Batch{}
	for _, e := range events {
		if slices.Contains(seen, e.EventID) {
			duplicates++
			continue
		}
		seen = append(seen, e.EventID)
		sequence++
		e.Sequence, e.Source, e.RecordTime = sequence, source, recordTime
		if e.Details == nil {
			e.Details = map[string]string{}
		}
		hash := chain.Hash(prev, e)
		batch.Queue(`INSERT INTO events (tenant_id, sequence, event_id, occur_time, record_time, actor_kind,
			actor_id, on_behalf_of, action, target_type, target_id, outcome, reason, request_id, details, source,
			prev_hash, hash) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18)`,
			e.TenantID, e.Sequence, e.EventID, e.OccurTime, e.RecordTime, e.ActorKind, e.ActorID, e.OnBehalfOf,
			e.Action, e.TargetType, e.TargetID, e.Outcome, e.Reason, e.RequestID, e.Details, e.Source, prev, hash)
		prev = hash
		recorded++
	}
	if recorded == 0 {
		return 0, duplicates, nil
	}
	batch.Queue(`UPDATE chains SET last_sequence = $2, last_hash = $3 WHERE tenant_id = $1`, tenant, sequence, prev)
	if err := tx.SendBatch(ctx, batch).Close(); err != nil {
		return 0, 0, err
	}
	return recorded, duplicates, nil
}

// Cursor is where a page of events ended.
type Cursor struct {
	OccurTime time.Time
	Sequence  int64
}

// Filter selects a tenant's events.
type Filter struct {
	TenantID uuid.UUID
	// Events the user did or that were done for them; empty: all.
	UserID       string
	ActionPrefix string
	Since, Until time.Time // zero: unbounded
	PageSize     int
	After        *Cursor
}

const columns = `tenant_id::text, sequence, event_id::text, occur_time, record_time, actor_kind, actor_id,
	on_behalf_of, action, target_type, target_id, outcome, reason, request_id, details, source, hash`

func scan(row pgx.Row) (Record, error) {
	var r Record
	err := row.Scan(&r.TenantID, &r.Sequence, &r.EventID, &r.OccurTime, &r.RecordTime, &r.ActorKind, &r.ActorID,
		&r.OnBehalfOf, &r.Action, &r.TargetType, &r.TargetID, &r.Outcome, &r.Reason, &r.RequestID, &r.Details,
		&r.Source, &r.Hash)
	return r, err
}

// likePrefix escapes a prefix for LIKE ... ESCAPE '\'.
func likePrefix(prefix string) string {
	return strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(prefix) + "%"
}

// List returns a page of a tenant's events, newest first, and the cursor of
// the next page (nil on the last one).
func (s *Store) List(ctx context.Context, f Filter) ([]Record, *Cursor, error) {
	var since, until, afterTime *time.Time
	var afterSeq int64
	if !f.Since.IsZero() {
		since = &f.Since
	}
	if !f.Until.IsZero() {
		until = &f.Until
	}
	if f.After != nil {
		afterTime, afterSeq = &f.After.OccurTime, f.After.Sequence
	}
	rows, err := s.pool.Query(ctx, `SELECT `+columns+` FROM events
		WHERE tenant_id = $1
		  AND ($2 = '' OR actor_id = $2 OR on_behalf_of = $2)
		  AND ($3 = '' OR action LIKE $4 ESCAPE '\')
		  AND ($5::timestamptz IS NULL OR occur_time >= $5)
		  AND ($6::timestamptz IS NULL OR occur_time < $6)
		  AND ($7::timestamptz IS NULL OR (occur_time, sequence) < ($7, $8))
		ORDER BY occur_time DESC, sequence DESC
		LIMIT $9`,
		f.TenantID, f.UserID, f.ActionPrefix, likePrefix(f.ActionPrefix), since, until, afterTime, afterSeq,
		f.PageSize+1)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	var records []Record
	for rows.Next() {
		r, err := scan(rows)
		if err != nil {
			return nil, nil, err
		}
		records = append(records, r)
	}
	if err := rows.Err(); err != nil {
		return nil, nil, err
	}
	if len(records) <= f.PageSize {
		return records, nil, nil
	}
	records = records[:f.PageSize]
	last := records[len(records)-1]
	return records, &Cursor{OccurTime: last.OccurTime, Sequence: last.Sequence}, nil
}

// Verification is the result of recomputing a tenant's chain.
type Verification struct {
	Intact      bool
	Events      int64
	FirstBroken int64 // 0 when intact
	Head        []byte
}

const verifyPage = 1000

// Verify recomputes a tenant's chain from its first event, in one snapshot.
// It finds changed, removed, inserted and reordered events, and events cut
// off the end (the chain's head remembers the last one).
func (s *Store) Verify(ctx context.Context, tenant uuid.UUID) (Verification, error) {
	var v Verification
	err := pgx.BeginTxFunc(ctx, s.pool, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly},
		func(tx pgx.Tx) error {
			var headSequence int64
			var headHash []byte
			err := tx.QueryRow(ctx, `SELECT last_sequence, last_hash FROM chains WHERE tenant_id = $1`, tenant).
				Scan(&headSequence, &headHash)
			if errors.Is(err, pgx.ErrNoRows) {
				headSequence, headHash = 0, nil
			} else if err != nil {
				return err
			}

			var prev []byte
			v = Verification{Intact: true}
			broken := func(sequence int64) {
				if v.Intact {
					v.Intact, v.FirstBroken = false, sequence
				}
			}
			for {
				rows, err := tx.Query(ctx, `SELECT `+columns+`, prev_hash FROM events
					WHERE tenant_id = $1 AND sequence > $2 ORDER BY sequence LIMIT $3`, tenant, v.Events, verifyPage)
				if err != nil {
					return err
				}
				n := 0
				for rows.Next() {
					var r Record
					var storedPrev []byte
					if err := rows.Scan(&r.TenantID, &r.Sequence, &r.EventID, &r.OccurTime, &r.RecordTime,
						&r.ActorKind, &r.ActorID, &r.OnBehalfOf, &r.Action, &r.TargetType, &r.TargetID, &r.Outcome,
						&r.Reason, &r.RequestID, &r.Details, &r.Source, &r.Hash, &storedPrev); err != nil {
						rows.Close()
						return err
					}
					n++
					expected := v.Events + 1
					if r.Sequence != expected {
						broken(expected) // a gap: events were removed
					}
					computed := chain.Hash(prev, r.Event)
					if !bytes.Equal(storedPrev, prev) || !bytes.Equal(r.Hash, computed) {
						broken(r.Sequence)
					}
					prev = computed
					v.Events = r.Sequence
				}
				rows.Close()
				if err := rows.Err(); err != nil {
					return err
				}
				if n < verifyPage {
					break
				}
			}
			if headSequence != v.Events || !bytes.Equal(headHash, prev) {
				broken(v.Events + 1) // the head names events that are gone
			}
			v.Head = prev
			return nil
		})
	return v, err
}

// Head is the end of a tenant's chain.
type Head struct {
	TenantID string
	Sequence int64
	Hash     []byte
}

// Heads returns every tenant's chain head. Logged regularly, they anchor the
// chains outside the database: a rewritten trail would not match them.
func (s *Store) Heads(ctx context.Context) ([]Head, error) {
	rows, err := s.pool.Query(ctx, `SELECT tenant_id::text, last_sequence, last_hash FROM chains ORDER BY tenant_id`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (Head, error) {
		var h Head
		err := row.Scan(&h.TenantID, &h.Sequence, &h.Hash)
		return h, err
	})
}
