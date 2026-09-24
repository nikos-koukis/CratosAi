// Package store persists the orchestrator's state in PostgreSQL.
package store

import (
	"bytes"
	"context"
	"embed"
	"encoding/json"
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

// Task states.
const (
	TaskQueued               = "queued"
	TaskRunning              = "running"
	TaskAwaitingConfirmation = "awaiting_confirmation"
	TaskAwaitingApproval     = "awaiting_approval"
	TaskSucceeded            = "succeeded"
	TaskFailed               = "failed"
	TaskCancelled            = "cancelled"
)

// Task kinds.
const (
	KindAgent   = "agent"
	KindCommand = "command"
)

// Target is what a tool name runs.
type Target struct {
	// Kind: a built-in tool name, "mcp" or "device".
	Kind          string `json:"kind"`
	IntegrationID string `json:"integration_id,omitempty"`
	Integration   string `json:"integration,omitempty"`
	Tool          string `json:"tool,omitempty"`
	Title         string `json:"title,omitempty"`
	ReadOnly      bool   `json:"read_only,omitempty"`
	// How the tool was declared to the model (tasks replay it every step).
	Description string          `json:"description,omitempty"`
	Parameters  json.RawMessage `json:"parameters,omitempty"`
}

// Conversation is a voice session.
type Conversation struct {
	ID        uuid.UUID
	TenantID  uuid.UUID
	UserID    string
	SessionID string
	Provider  int32
	Locale    string
	Tools     map[string]Target
	UserTurn  int64
	ClosedAt  *time.Time
	CreatedAt time.Time
}

// Turn is one speaker turn of a conversation.
type Turn struct {
	Role      string
	ItemID    string
	UserTurn  int64
	Text      string
	CreatedAt time.Time
}

// Task is background work.
type Task struct {
	ID             uuid.UUID
	TenantID       uuid.UUID
	UserID         string
	ConversationID uuid.NullUUID
	Kind           string
	Provider       int32
	Goal           string
	State          string
	Result         string
	Steps          int
	Tools          map[string]Target
	History        json.RawMessage
	Pending        json.RawMessage
	Deadline       time.Time
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

// Terminal reports whether the task has finished for good.
func (t Task) Terminal() bool {
	return t.State == TaskSucceeded || t.State == TaskFailed || t.State == TaskCancelled
}

// Confirmation is an action waiting for the user's consent.
type Confirmation struct {
	ID             uuid.UUID
	ConversationID uuid.UUID
	TaskID         uuid.NullUUID
	CallID         string
	Action         json.RawMessage
	Summary        string
	AskedTurn      *int64
	State          string
	ExpiresAt      time.Time
}

// Event is something to tell the user.
type Event struct {
	ID        int64
	Payload   []byte
	CreatedAt time.Time
}

// Device is a user's computer running the local daemon.
type Device struct {
	ID              uuid.UUID
	TenantID        uuid.UUID
	UserID          string
	Name            string
	Address         string
	ServerName      string
	CAPEM           string
	ClientCertPEM   string
	ClientKeySealed []byte
	CreatedAt       time.Time
}

// DeviceApproval is a device command waiting for a signed approval.
type DeviceApproval struct {
	ApprovalID string
	DeviceID   uuid.UUID
	TaskID     uuid.UUID
	CallID     string
	Command    json.RawMessage
	Payload    []byte
	ExpiresAt  time.Time
}

// PendingApproval is an unexpired approval with the name of its device.
type PendingApproval struct {
	DeviceApproval
	DeviceName string
}

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
	if _, err := conn.Exec(ctx, `SELECT pg_advisory_lock(hashtext('orchestrator-migrations'))`); err != nil {
		return err
	}
	defer func() {
		_, _ = conn.Exec(context.Background(), `SELECT pg_advisory_unlock(hashtext('orchestrator-migrations'))`)
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

// --- conversations -----------------------------------------------------------------

// CreateConversation inserts a conversation.
func (s *Store) CreateConversation(ctx context.Context, c Conversation) error {
	tools, err := json.Marshal(c.Tools)
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx, `INSERT INTO conversations (id, tenant_id, user_id, session_id, provider, locale, tools)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`, c.ID, c.TenantID, c.UserID, c.SessionID, c.Provider, c.Locale, tools)
	return err
}

// Conversation loads a conversation.
func (s *Store) Conversation(ctx context.Context, id uuid.UUID) (Conversation, error) {
	var c Conversation
	var tools []byte
	err := s.pool.QueryRow(ctx, `SELECT id, tenant_id, user_id, session_id, provider, locale, tools, user_turn,
		closed_at, created_at FROM conversations WHERE id = $1`, id).
		Scan(&c.ID, &c.TenantID, &c.UserID, &c.SessionID, &c.Provider, &c.Locale, &tools, &c.UserTurn, &c.ClosedAt, &c.CreatedAt)
	if err != nil {
		return c, notFound(err)
	}
	return c, json.Unmarshal(tools, &c.Tools)
}

// AdvanceTurn raises the conversation's user turn (it never decreases).
func (s *Store) AdvanceTurn(ctx context.Context, id uuid.UUID, turn int64) error {
	_, err := s.pool.Exec(ctx, `UPDATE conversations SET user_turn = GREATEST(user_turn, $2) WHERE id = $1`, id, turn)
	return err
}

// RecordTurn stores a turn; a later call with text fills in the transcript.
func (s *Store) RecordTurn(ctx context.Context, id uuid.UUID, role, itemID string, turn int64, text string) error {
	_, err := s.pool.Exec(ctx, `INSERT INTO turns (conversation_id, role, item_id, user_turn, text)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (conversation_id, role, item_id) DO UPDATE
		SET text = CASE WHEN excluded.text <> '' THEN excluded.text ELSE turns.text END,
		    user_turn = GREATEST(turns.user_turn, excluded.user_turn)`, id, role, itemID, turn, text)
	return err
}

// CloseConversation marks a conversation closed; reports whether it was open.
func (s *Store) CloseConversation(ctx context.Context, id uuid.UUID) (bool, error) {
	tag, err := s.pool.Exec(ctx, `UPDATE conversations SET closed_at = now() WHERE id = $1 AND closed_at IS NULL`, id)
	return tag.RowsAffected() == 1, err
}

// Transcript returns a conversation's turns with text, in order.
func (s *Store) Transcript(ctx context.Context, id uuid.UUID) ([]Turn, error) {
	rows, err := s.pool.Query(ctx, `SELECT role, item_id, user_turn, text, created_at FROM turns
		WHERE conversation_id = $1 AND text <> '' ORDER BY created_at, user_turn`, id)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (Turn, error) {
		var t Turn
		err := row.Scan(&t.Role, &t.ItemID, &t.UserTurn, &t.Text, &t.CreatedAt)
		return t, err
	})
}

// PurgeTranscripts deletes the turns of conversations closed before the
// retention period (their memory has been extracted by then).
func (s *Store) PurgeTranscripts(ctx context.Context, retention time.Duration) (int64, error) {
	tag, err := s.pool.Exec(ctx, `DELETE FROM turns WHERE conversation_id IN (
		SELECT id FROM conversations WHERE closed_at < now() - make_interval(secs => $1))`, retention.Seconds())
	return tag.RowsAffected(), err
}

// --- tool calls ----------------------------------------------------------------------

// CallResult is the stored result of a voice function call.
type CallResult struct {
	Output  string
	IsError bool
	// AckRequired: the output asks the user a question; the gateway reports
	// when it reaches the user (AckToolOutput).
	AckRequired bool
}

// ToolCall returns a stored call result.
func (s *Store) ToolCall(ctx context.Context, conversation uuid.UUID, callID string) (CallResult, error) {
	var r CallResult
	err := s.pool.QueryRow(ctx, `SELECT output, is_error, ack_required FROM tool_calls
		WHERE conversation_id = $1 AND call_id = $2`, conversation, callID).Scan(&r.Output, &r.IsError, &r.AckRequired)
	return r, notFound(err)
}

// SaveToolCall stores a call's result (the first stored wins).
func (s *Store) SaveToolCall(ctx context.Context, conversation uuid.UUID, callID, name string, r CallResult) error {
	_, err := s.pool.Exec(ctx, `INSERT INTO tool_calls (conversation_id, call_id, name, output, is_error, ack_required)
		VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT DO NOTHING`, conversation, callID, name, r.Output, r.IsError, r.AckRequired)
	return err
}

// --- tasks -------------------------------------------------------------------------------

const taskColumns = `id, tenant_id, user_id, conversation_id, kind, provider, goal, state, result, steps, tools,
	history, pending, deadline, created_at, updated_at`

func scanTask(row pgx.Row) (Task, error) {
	var t Task
	var tools []byte
	err := row.Scan(&t.ID, &t.TenantID, &t.UserID, &t.ConversationID, &t.Kind, &t.Provider, &t.Goal, &t.State,
		&t.Result, &t.Steps, &tools, &t.History, &t.Pending, &t.Deadline, &t.CreatedAt, &t.UpdatedAt)
	if err != nil {
		return t, notFound(err)
	}
	return t, json.Unmarshal(tools, &t.Tools)
}

// CreateTask inserts a task.
func (s *Store) CreateTask(ctx context.Context, t Task) error {
	tools, err := json.Marshal(t.Tools)
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx, `INSERT INTO tasks (id, tenant_id, user_id, conversation_id, kind, provider, goal, state,
		result, tools, history, pending, deadline) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)`,
		t.ID, t.TenantID, t.UserID, t.ConversationID, t.Kind, t.Provider, t.Goal, t.State, t.Result, tools,
		orEmpty(t.History), orEmpty(t.Pending), t.Deadline)
	return err
}

func orEmpty(raw json.RawMessage) json.RawMessage {
	if len(raw) == 0 {
		return json.RawMessage("[]")
	}
	return raw
}

// Task loads a task of a tenant and user.
func (s *Store) Task(ctx context.Context, tenant uuid.UUID, user string, id uuid.UUID) (Task, error) {
	return scanTask(s.pool.QueryRow(ctx, `SELECT `+taskColumns+` FROM tasks WHERE id = $1 AND tenant_id = $2 AND user_id = $3`,
		id, tenant, user))
}

// TaskByID loads a task for internal use.
func (s *Store) TaskByID(ctx context.Context, id uuid.UUID) (Task, error) {
	return scanTask(s.pool.QueryRow(ctx, `SELECT `+taskColumns+` FROM tasks WHERE id = $1`, id))
}

// Tasks lists a user's tasks, newest first.
func (s *Store) Tasks(ctx context.Context, tenant uuid.UUID, user string, limit int) ([]Task, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+taskColumns+` FROM tasks WHERE tenant_id = $1 AND user_id = $2
		ORDER BY created_at DESC LIMIT $3`, tenant, user, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Task
	for rows.Next() {
		t, err := scanTask(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// LeaseTask takes a runnable task: queued, or running with an expired lease
// (its worker died). Concurrent workers never take the same task.
func (s *Store) LeaseTask(ctx context.Context, owner string, lease time.Duration) (Task, error) {
	return scanTask(s.pool.QueryRow(ctx, `UPDATE tasks SET state = 'running', lease_owner = $1,
		lease_until = now() + make_interval(secs => $2), updated_at = now()
		WHERE id = (SELECT id FROM tasks WHERE state = 'queued' OR (state = 'running' AND lease_until < now())
		            ORDER BY updated_at FOR UPDATE SKIP LOCKED LIMIT 1)
		RETURNING `+taskColumns, owner, lease.Seconds()))
}

// RenewLease extends a lease; false means the task is no longer this worker's.
func (s *Store) RenewLease(ctx context.Context, id uuid.UUID, owner string, lease time.Duration) (bool, error) {
	tag, err := s.pool.Exec(ctx, `UPDATE tasks SET lease_until = now() + make_interval(secs => $3)
		WHERE id = $1 AND lease_owner = $2 AND state = 'running'`, id, owner, lease.Seconds())
	return tag.RowsAffected() == 1, err
}

// SaveProgress stores a running task's history and pending calls.
func (s *Store) SaveProgress(ctx context.Context, t Task, owner string) (bool, error) {
	tag, err := s.pool.Exec(ctx, `UPDATE tasks SET history = $3, pending = $4, steps = $5, updated_at = now()
		WHERE id = $1 AND lease_owner = $2 AND state = 'running'`, t.ID, owner, orEmpty(t.History), orEmpty(t.Pending), t.Steps)
	return tag.RowsAffected() == 1, err
}

// SetTaskState moves a task this worker runs to another state (terminal or
// waiting) and releases its lease.
func (s *Store) SetTaskState(ctx context.Context, t Task, owner, state, result string) (bool, error) {
	tag, err := s.pool.Exec(ctx, `UPDATE tasks SET state = $3, result = $4, history = $5, pending = $6, steps = $7,
		lease_owner = NULL, lease_until = NULL, updated_at = now()
		WHERE id = $1 AND lease_owner = $2 AND state = 'running'`,
		t.ID, owner, state, result, orEmpty(t.History), orEmpty(t.Pending), t.Steps)
	return tag.RowsAffected() == 1, err
}

// ResumeTask updates a waiting task (from awaiting_confirmation or
// awaiting_approval) and queues it again, in one transaction with `update`.
func (s *Store) ResumeTask(ctx context.Context, id uuid.UUID, update func(*Task) error) (Task, error) {
	var out Task
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		t, err := scanTask(tx.QueryRow(ctx, `SELECT `+taskColumns+` FROM tasks WHERE id = $1 FOR UPDATE`, id))
		if err != nil {
			return err
		}
		if t.State != TaskAwaitingConfirmation && t.State != TaskAwaitingApproval {
			return fmt.Errorf("%w: task is %s", ErrNotFound, t.State)
		}
		if err := update(&t); err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `UPDATE tasks SET state = $2, result = $3, history = $4, pending = $5, updated_at = now()
			WHERE id = $1`, t.ID, t.State, t.Result, orEmpty(t.History), orEmpty(t.Pending))
		out = t
		return err
	})
	return out, err
}

// CancelTask cancels an unfinished task and its pending confirmations.
func (s *Store) CancelTask(ctx context.Context, tenant uuid.UUID, user string, id uuid.UUID) (Task, error) {
	var out Task
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		t, err := scanTask(tx.QueryRow(ctx, `UPDATE tasks SET state = 'cancelled', result = 'Cancelled by the user.',
			lease_owner = NULL, lease_until = NULL, updated_at = now()
			WHERE id = $1 AND tenant_id = $2 AND user_id = $3 AND state NOT IN ('succeeded', 'failed', 'cancelled')
			RETURNING `+taskColumns, id, tenant, user))
		if errors.Is(err, ErrNotFound) {
			out, err = scanTask(tx.QueryRow(ctx, `SELECT `+taskColumns+` FROM tasks WHERE id = $1 AND tenant_id = $2 AND user_id = $3`,
				id, tenant, user))
			return err
		}
		if err != nil {
			return err
		}
		out = t
		_, err = tx.Exec(ctx, `UPDATE confirmations SET state = 'cancelled' WHERE task_id = $1 AND state = 'pending'`, id)
		return err
	})
	return out, err
}

// TaskState returns a task's current state.
func (s *Store) TaskState(ctx context.Context, id uuid.UUID) (string, error) {
	var state string
	err := s.pool.QueryRow(ctx, `SELECT state FROM tasks WHERE id = $1`, id).Scan(&state)
	return state, notFound(err)
}

// --- confirmations ------------------------------------------------------------------

const confirmationColumns = `id, conversation_id, task_id, call_id, action, summary, asked_turn, state, expires_at`

func scanConfirmation(row pgx.Row) (Confirmation, error) {
	var c Confirmation
	err := row.Scan(&c.ID, &c.ConversationID, &c.TaskID, &c.CallID, &c.Action, &c.Summary, &c.AskedTurn, &c.State, &c.ExpiresAt)
	return c, notFound(err)
}

// CreateConfirmation inserts a pending confirmation.
func (s *Store) CreateConfirmation(ctx context.Context, c Confirmation) error {
	_, err := s.pool.Exec(ctx, `INSERT INTO confirmations (id, conversation_id, task_id, call_id, action, summary,
		asked_turn, state, expires_at) VALUES ($1, $2, $3, $4, $5, $6, $7, 'pending', $8)`,
		c.ID, c.ConversationID, c.TaskID, c.CallID, c.Action, c.Summary, c.AskedTurn, c.ExpiresAt)
	return err
}

// Confirmation loads a confirmation of a conversation.
func (s *Store) Confirmation(ctx context.Context, conversation, id uuid.UUID) (Confirmation, error) {
	return scanConfirmation(s.pool.QueryRow(ctx, `SELECT `+confirmationColumns+` FROM confirmations
		WHERE id = $1 AND conversation_id = $2`, id, conversation))
}

// Settle confirms or cancels a pending confirmation, atomically. A
// confirmation only counts in a user turn later than the one in which the
// question was asked; a cancellation always counts.
func (s *Store) Settle(ctx context.Context, conversation, id uuid.UUID, turn int64, confirm bool) (Confirmation, error) {
	state := "cancelled"
	if confirm {
		state = "confirmed"
	}
	return scanConfirmation(s.pool.QueryRow(ctx, `UPDATE confirmations SET state = $4
		WHERE id = $1 AND conversation_id = $2 AND state = 'pending' AND expires_at > now()
		  AND ($4 = 'cancelled' OR (asked_turn IS NOT NULL AND asked_turn < $3))
		RETURNING `+confirmationColumns, id, conversation, turn, state))
}

// MarkAsked records the user turn at which a question reached the user (the
// first time only).
func (s *Store) MarkAsked(ctx context.Context, id uuid.UUID, turn int64) error {
	_, err := s.pool.Exec(ctx, `UPDATE confirmations SET asked_turn = COALESCE(asked_turn, $2) WHERE id = $1`, id, turn)
	return err
}

// MarkCallAsked records the user turn at which the question asked by a voice
// call reached the user (the first time only); it reports whether the call
// asked one.
func (s *Store) MarkCallAsked(ctx context.Context, conversation uuid.UUID, callID string, turn int64) (bool, error) {
	tag, err := s.pool.Exec(ctx, `UPDATE confirmations SET asked_turn = COALESCE(asked_turn, $3)
		WHERE conversation_id = $1 AND call_id = $2 AND task_id IS NULL`, conversation, callID, turn)
	return tag.RowsAffected() > 0, err
}

// ExpireConfirmations expires overdue confirmations and returns them.
func (s *Store) ExpireConfirmations(ctx context.Context) ([]Confirmation, error) {
	rows, err := s.pool.Query(ctx, `UPDATE confirmations SET state = 'expired'
		WHERE state = 'pending' AND expires_at <= now() RETURNING `+confirmationColumns)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (Confirmation, error) { return scanConfirmation(row) })
}

// --- events -------------------------------------------------------------------------

// AddEvent appends an event to a conversation.
//
// When the conversation has ended, the event goes to the user's newest live
// conversation instead, with the confirmation it asks about, so a result or a
// question is still told; without one it waits for CarryOverEvents. It
// returns the conversation that got the event and whether it is live (someone
// will hear it now).
func (s *Store) AddEvent(ctx context.Context, conversation uuid.UUID, payload []byte, confirmation uuid.NullUUID) (uuid.UUID, bool, error) {
	target, live := conversation, false
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx, `(SELECT id FROM conversations WHERE id = $1 AND closed_at IS NULL)
			UNION ALL
			(SELECT o.id FROM conversations c JOIN conversations o ON o.tenant_id = c.tenant_id AND o.user_id = c.user_id
			  WHERE c.id = $1 AND o.closed_at IS NULL AND o.created_at > now() - make_interval(secs => $2)
			  ORDER BY o.created_at DESC LIMIT 1)
			LIMIT 1`, conversation, ConversationLifetime.Seconds()).Scan(&target)
		switch {
		case err == nil:
			live = true
		case errors.Is(err, pgx.ErrNoRows):
			target = conversation
		default:
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO events (conversation_id, event, confirmation_id) VALUES ($1, $2, $3)`,
			target, payload, confirmation); err != nil {
			return err
		}
		if target == conversation || !confirmation.Valid {
			return nil
		}
		_, err = tx.Exec(ctx, `UPDATE confirmations SET conversation_id = $1, asked_turn = NULL
			WHERE id = $2 AND state = 'pending'`, target, confirmation)
		return err
	})
	return target, live, err
}

// ConversationLifetime bounds how long a conversation can be live: voice
// sessions last at most an hour, so one open for longer was abandoned (e.g.
// its gateway crashed) and is closed by CloseAbandoned.
const ConversationLifetime = 2 * time.Hour

// CarryOverEvents moves the events a user never heard (their conversation
// ended first) from the last `window` into a new conversation, with the
// pending confirmations they ask about. It returns how many moved.
func (s *Store) CarryOverEvents(ctx context.Context, conversation, tenant uuid.UUID, user string, window time.Duration) (int, error) {
	moved := 0
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `UPDATE events e SET conversation_id = $1
			FROM conversations c
			WHERE e.conversation_id = c.id AND c.tenant_id = $2 AND c.user_id = $3 AND c.id <> $1
			  AND c.closed_at IS NOT NULL AND e.acked_turn IS NULL AND e.created_at > now() - make_interval(secs => $4)
			RETURNING e.confirmation_id`, conversation, tenant, user, window.Seconds())
		if err != nil {
			return err
		}
		confirmations, err := pgx.CollectRows(rows, pgx.RowTo[uuid.NullUUID])
		if err != nil {
			return err
		}
		moved = len(confirmations)
		var ids []uuid.UUID
		for _, c := range confirmations {
			if c.Valid {
				ids = append(ids, c.UUID)
			}
		}
		if len(ids) == 0 {
			return nil
		}
		_, err = tx.Exec(ctx, `UPDATE confirmations SET conversation_id = $1, asked_turn = NULL
			WHERE id = ANY($2) AND state = 'pending'`, conversation, ids)
		return err
	})
	return moved, err
}

// CloseAbandoned closes conversations open for longer than
// ConversationLifetime and returns them.
func (s *Store) CloseAbandoned(ctx context.Context) ([]uuid.UUID, error) {
	rows, err := s.pool.Query(ctx, `UPDATE conversations SET closed_at = now()
		WHERE closed_at IS NULL AND created_at < now() - make_interval(secs => $1) RETURNING id`,
		ConversationLifetime.Seconds())
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
}

// Events returns events after an id, oldest first.
func (s *Store) Events(ctx context.Context, conversation uuid.UUID, after int64, limit int) ([]Event, error) {
	rows, err := s.pool.Query(ctx, `SELECT id, event, created_at FROM events WHERE conversation_id = $1 AND id > $2
		ORDER BY id LIMIT $3`, conversation, after, limit)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (Event, error) {
		var e Event
		err := row.Scan(&e.ID, &e.Payload, &e.CreatedAt)
		return e, err
	})
}

// LastAcked is the id of the conversation's last acknowledged event (0 if none).
func (s *Store) LastAcked(ctx context.Context, conversation uuid.UUID) (int64, error) {
	var id int64
	err := s.pool.QueryRow(ctx, `SELECT COALESCE(MAX(id), 0) FROM events WHERE conversation_id = $1 AND acked_turn IS NOT NULL`,
		conversation).Scan(&id)
	return id, err
}

// AckEvent records the user turn at which an event reached the conversation
// and returns the confirmation it asks about, if any.
func (s *Store) AckEvent(ctx context.Context, conversation uuid.UUID, id, turn int64) (uuid.NullUUID, error) {
	var confirmation uuid.NullUUID
	err := s.pool.QueryRow(ctx, `UPDATE events SET acked_turn = COALESCE(acked_turn, $3)
		WHERE id = $2 AND conversation_id = $1 RETURNING confirmation_id`, conversation, id, turn).Scan(&confirmation)
	return confirmation, notFound(err)
}

// --- devices ---------------------------------------------------------------------------

const deviceColumns = `id, tenant_id, user_id, name, address, server_name, ca_pem, client_cert_pem, client_key_sealed, created_at`

func scanDevice(row pgx.Row) (Device, error) {
	var d Device
	err := row.Scan(&d.ID, &d.TenantID, &d.UserID, &d.Name, &d.Address, &d.ServerName, &d.CAPEM, &d.ClientCertPEM,
		&d.ClientKeySealed, &d.CreatedAt)
	return d, notFound(err)
}

// UpsertDevice adds a device, or replaces the one with the same name (keeping its id).
func (s *Store) UpsertDevice(ctx context.Context, d Device) (Device, error) {
	return scanDevice(s.pool.QueryRow(ctx, `INSERT INTO devices (id, tenant_id, user_id, name, address, server_name,
		ca_pem, client_cert_pem, client_key_sealed) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		ON CONFLICT (tenant_id, user_id, name) DO UPDATE SET address = excluded.address,
		  server_name = excluded.server_name, ca_pem = excluded.ca_pem, client_cert_pem = excluded.client_cert_pem,
		  client_key_sealed = excluded.client_key_sealed
		RETURNING `+deviceColumns, d.ID, d.TenantID, d.UserID, d.Name, d.Address, d.ServerName, d.CAPEM, d.ClientCertPEM,
		d.ClientKeySealed))
}

// Devices lists a user's devices by name.
func (s *Store) Devices(ctx context.Context, tenant uuid.UUID, user string) ([]Device, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+deviceColumns+` FROM devices WHERE tenant_id = $1 AND user_id = $2 ORDER BY name`,
		tenant, user)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (Device, error) { return scanDevice(row) })
}

// DeviceByID loads a device for internal use.
func (s *Store) DeviceByID(ctx context.Context, id uuid.UUID) (Device, error) {
	return scanDevice(s.pool.QueryRow(ctx, `SELECT `+deviceColumns+` FROM devices WHERE id = $1`, id))
}

// DeleteDevice removes a user's device.
func (s *Store) DeleteDevice(ctx context.Context, tenant uuid.UUID, user string, id uuid.UUID) (bool, error) {
	tag, err := s.pool.Exec(ctx, `DELETE FROM devices WHERE id = $1 AND tenant_id = $2 AND user_id = $3`, id, tenant, user)
	return tag.RowsAffected() == 1, err
}

// SaveApproval stores a pending device approval.
func (s *Store) SaveApproval(ctx context.Context, a DeviceApproval) error {
	_, err := s.pool.Exec(ctx, `INSERT INTO device_approvals (approval_id, device_id, task_id, call_id, command,
		payload, expires_at) VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		a.ApprovalID, a.DeviceID, a.TaskID, a.CallID, a.Command, a.Payload, a.ExpiresAt)
	return err
}

// PendingApprovals returns the unexpired approvals of the given tasks, by task.
func (s *Store) PendingApprovals(ctx context.Context, tasks []uuid.UUID) (map[uuid.UUID]PendingApproval, error) {
	rows, err := s.pool.Query(ctx, `SELECT a.approval_id, a.device_id, a.task_id, a.call_id, a.command, a.payload,
		a.expires_at, d.name FROM device_approvals a JOIN devices d ON d.id = a.device_id
		WHERE a.task_id = ANY($1) AND a.expires_at > now()`, tasks)
	if err != nil {
		return nil, err
	}
	out := map[uuid.UUID]PendingApproval{}
	var p PendingApproval
	_, err = pgx.ForEachRow(rows, []any{&p.ApprovalID, &p.DeviceID, &p.TaskID, &p.CallID, &p.Command, &p.Payload,
		&p.ExpiresAt, &p.DeviceName}, func() error {
		p.Payload, p.Command = bytes.Clone(p.Payload), bytes.Clone(p.Command)
		out[p.TaskID] = p
		return nil
	})
	return out, err
}

// Approval loads a pending approval of a tenant's user.
func (s *Store) Approval(ctx context.Context, tenant uuid.UUID, user, approvalID string) (DeviceApproval, error) {
	var a DeviceApproval
	err := s.pool.QueryRow(ctx, `SELECT a.approval_id, a.device_id, a.task_id, a.call_id, a.command, a.expires_at
		FROM device_approvals a JOIN tasks t ON t.id = a.task_id
		WHERE a.approval_id = $1 AND t.tenant_id = $2 AND t.user_id = $3 AND a.expires_at > now()`,
		approvalID, tenant, user).Scan(&a.ApprovalID, &a.DeviceID, &a.TaskID, &a.CallID, &a.Command, &a.ExpiresAt)
	return a, notFound(err)
}

// DeleteApproval removes a used approval.
// ExpireApprovals deletes approvals past their expiry and returns them.
func (s *Store) ExpireApprovals(ctx context.Context) ([]DeviceApproval, error) {
	rows, err := s.pool.Query(ctx, `DELETE FROM device_approvals WHERE expires_at < now()
		RETURNING approval_id, device_id, task_id, call_id, command, payload, expires_at`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (DeviceApproval, error) {
		var a DeviceApproval
		err := row.Scan(&a.ApprovalID, &a.DeviceID, &a.TaskID, &a.CallID, &a.Command, &a.Payload, &a.ExpiresAt)
		return a, err
	})
}

func (s *Store) DeleteApproval(ctx context.Context, approvalID string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM device_approvals WHERE approval_id = $1`, approvalID)
	return err
}

// --- memory jobs ------------------------------------------------------------------------

// QueueMemoryJob schedules a conversation's memory extraction (once).
func (s *Store) QueueMemoryJob(ctx context.Context, conversation uuid.UUID) error {
	_, err := s.pool.Exec(ctx, `INSERT INTO memory_jobs (conversation_id, state) VALUES ($1, 'queued') ON CONFLICT DO NOTHING`,
		conversation)
	return err
}

// LeaseMemoryJob takes a due job; returns its conversation and attempt count.
func (s *Store) LeaseMemoryJob(ctx context.Context, lease time.Duration) (uuid.UUID, int, error) {
	var id uuid.UUID
	var attempts int
	err := s.pool.QueryRow(ctx, `UPDATE memory_jobs SET state = 'running', attempts = attempts + 1,
		lease_until = now() + make_interval(secs => $1), updated_at = now()
		WHERE conversation_id = (SELECT conversation_id FROM memory_jobs
		  WHERE (state = 'queued' OR (state = 'running' AND lease_until < now())) AND not_before <= now()
		  ORDER BY not_before FOR UPDATE SKIP LOCKED LIMIT 1)
		RETURNING conversation_id, attempts`, lease.Seconds()).Scan(&id, &attempts)
	return id, attempts, notFound(err)
}

// FinishMemoryJob marks a job done, retries it later, or gives up.
func (s *Store) FinishMemoryJob(ctx context.Context, conversation uuid.UUID, state string, retryAfter time.Duration, lastError string) error {
	_, err := s.pool.Exec(ctx, `UPDATE memory_jobs SET state = $2, lease_until = NULL, last_error = $4, updated_at = now(),
		not_before = now() + make_interval(secs => $3) WHERE conversation_id = $1`,
		conversation, state, retryAfter.Seconds(), lastError)
	return err
}

// --- notifications ----------------------------------------------------------------

// Notification kinds.
const (
	NotifyApproval     = "approval_needed"
	NotifyConfirmation = "confirmation_needed"
	NotifyFinished     = "task_finished"
)

// Notification is something to tell a user on their phone.
type Notification struct {
	ID        int64
	TenantID  uuid.UUID
	UserID    string
	Kind      string
	TaskID    uuid.UUID
	TaskState string
	CreatedAt time.Time
}

// AddNotification queues a notification.
func (s *Store) AddNotification(ctx context.Context, n Notification) error {
	_, err := s.pool.Exec(ctx, `INSERT INTO notifications (tenant_id, user_id, kind, task_id, task_state)
		VALUES ($1, $2, $3, $4, $5)`, n.TenantID, n.UserID, n.Kind, n.TaskID, n.TaskState)
	return err
}

// ClaimNotifications hands out up to max pending notifications for `lease`.
// Those claimed maxAttempts times already, or older than maxAge, are skipped.
func (s *Store) ClaimNotifications(ctx context.Context, consumer string, max int, lease time.Duration,
	maxAttempts int, maxAge time.Duration) ([]Notification, error) {
	rows, err := s.pool.Query(ctx, `UPDATE notifications SET claimed_by = $1,
		  claimed_until = now() + make_interval(secs => $3), attempts = attempts + 1
		WHERE id IN (SELECT id FROM notifications
		  WHERE done_at IS NULL AND (claimed_until IS NULL OR claimed_until < now())
		    AND attempts < $4 AND created_at > now() - make_interval(secs => $5)
		  ORDER BY id LIMIT $2 FOR UPDATE SKIP LOCKED)
		RETURNING id, tenant_id, user_id, kind, task_id, task_state, created_at`,
		consumer, max, lease.Seconds(), maxAttempts, maxAge.Seconds())
	if err != nil {
		return nil, err
	}
	out, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (Notification, error) {
		var n Notification
		err := row.Scan(&n.ID, &n.TenantID, &n.UserID, &n.Kind, &n.TaskID, &n.TaskState, &n.CreatedAt)
		return n, err
	})
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, err
}

// CompleteNotifications marks notifications handled.
func (s *Store) CompleteNotifications(ctx context.Context, ids []int64) error {
	_, err := s.pool.Exec(ctx, `UPDATE notifications SET done_at = now() WHERE id = ANY($1) AND done_at IS NULL`, ids)
	return err
}

// PurgeNotifications deletes notifications older than keep.
func (s *Store) PurgeNotifications(ctx context.Context, keep time.Duration) (int64, error) {
	tag, err := s.pool.Exec(ctx, `DELETE FROM notifications WHERE created_at < now() - make_interval(secs => $1)`,
		keep.Seconds())
	return tag.RowsAffected(), err
}
