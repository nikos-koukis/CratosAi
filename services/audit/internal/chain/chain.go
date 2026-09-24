// Package chain computes the audit trail's per-tenant hash chain.
//
// Each event's hash is
//
//	SHA-256("jarvis.audit.v1\x00" || previous hash || fields)
//
// where the previous hash is empty for a tenant's first event, and fields
// are the stored event in a fixed order, each written as its length (an
// unsigned varint) followed by its bytes:
//
//	tenant id, sequence, event id, occur time, record time, actor kind,
//	actor id, on behalf of, action, target type, target id, outcome,
//	reason, request id, source, the number of details, then each detail's
//	key and value in key order.
//
// Ids are lowercase canonical UUIDs, numbers are decimal, times are Unix
// microseconds (decimal), and kinds and outcomes are their protobuf names.
// The encoding is unambiguous (length-prefixed) and independent of protobuf
// serialization, so anyone with the stored rows can recompute the chain.
package chain

import (
	"crypto/sha256"
	"encoding/binary"
	"sort"
	"strconv"
	"time"
)

const domain = "jarvis.audit.v1\x00"

// Event is a stored event, as hashed.
type Event struct {
	TenantID   string // lowercase canonical UUID
	Sequence   int64
	EventID    string // lowercase canonical UUID
	OccurTime  time.Time
	RecordTime time.Time
	ActorKind  string // e.g. ACTOR_KIND_USER
	ActorID    string
	OnBehalfOf string
	Action     string
	TargetType string
	TargetID   string
	Outcome    string // e.g. OUTCOME_SUCCESS
	Reason     string
	RequestID  string
	Source     string
	Details    map[string]string
}

// Precision is the resolution times are stored and hashed with (PostgreSQL's).
const Precision = time.Microsecond

// Hash is the event's link in the chain after prev.
func Hash(prev []byte, e Event) []byte {
	h := sha256.New()
	h.Write([]byte(domain))
	h.Write(prev)
	var buf [binary.MaxVarintLen64]byte
	field := func(s string) {
		n := binary.PutUvarint(buf[:], uint64(len(s)))
		h.Write(buf[:n])
		h.Write([]byte(s))
	}
	micros := func(t time.Time) string { return strconv.FormatInt(t.UnixMicro(), 10) }

	field(e.TenantID)
	field(strconv.FormatInt(e.Sequence, 10))
	field(e.EventID)
	field(micros(e.OccurTime))
	field(micros(e.RecordTime))
	field(e.ActorKind)
	field(e.ActorID)
	field(e.OnBehalfOf)
	field(e.Action)
	field(e.TargetType)
	field(e.TargetID)
	field(e.Outcome)
	field(e.Reason)
	field(e.RequestID)
	field(e.Source)
	keys := make([]string, 0, len(e.Details))
	for k := range e.Details {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	field(strconv.Itoa(len(keys)))
	for _, k := range keys {
		field(k)
		field(e.Details[k])
	}
	return h.Sum(nil)
}
