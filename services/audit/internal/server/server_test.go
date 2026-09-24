package server_test

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	auditv1 "jarvis.internal/gen/go/jarvis/audit/v1"
)

var ctx = context.Background()

func event(tenant string, action string, mutate ...func(*auditv1.Event)) *auditv1.Event {
	e := &auditv1.Event{
		EventId:   uuid.Must(uuid.NewV7()).String(),
		TenantId:  tenant,
		OccurTime: timestamppb.Now(),
		Actor:     &auditv1.Actor{Kind: auditv1.ActorKind_ACTOR_KIND_USER, Id: "ana"},
		Action:    action,
		Outcome:   auditv1.Outcome_OUTCOME_SUCCESS,
	}
	for _, m := range mutate {
		m(e)
	}
	return e
}

func record(t *testing.T, c auditv1.AuditServiceClient, events ...*auditv1.Event) *auditv1.RecordResponse {
	t.Helper()
	resp, err := c.Record(ctx, &auditv1.RecordRequest{Events: events})
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func list(t *testing.T, c auditv1.AuditServiceClient, req *auditv1.ListEventsRequest) *auditv1.ListEventsResponse {
	t.Helper()
	resp, err := c.ListEvents(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func verify(t *testing.T, c auditv1.AuditServiceClient, tenant string) *auditv1.VerifyChainResponse {
	t.Helper()
	resp, err := c.VerifyChain(ctx, &auditv1.VerifyChainRequest{TenantId: tenant})
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func tenant() string { return uuid.NewString() }

func TestEventsCarryTheCallersIdentityAndExtendTheChain(t *testing.T) {
	vault, dashboard := client(t, "vault"), client(t, "dashboard-api")
	tn := tenant()
	first := event(tn, "key.read", func(e *auditv1.Event) {
		e.Source = "spiffe://jarvis.test/dashboard-api" // a producer cannot choose its source
		e.Sequence, e.Hash = 99, []byte("forged")
		e.Details = map[string]string{"provider": "openai"}
	})
	if resp := record(t, vault, first, event(tn, "key.read")); resp.GetRecorded() != 2 {
		t.Fatalf("recorded %v", resp)
	}
	events := list(t, dashboard, &auditv1.ListEventsRequest{TenantId: tn}).GetEvents()
	if len(events) != 2 {
		t.Fatalf("listed %d", len(events))
	}
	oldest := events[1]
	if oldest.GetSource() != "spiffe://jarvis.test/vault" || oldest.GetSequence() != 1 ||
		len(oldest.GetHash()) != 32 || oldest.GetRecordTime() == nil || oldest.GetDetails()["provider"] != "openai" {
		t.Fatalf("stored %+v", oldest)
	}
	if events[0].GetSequence() != 2 {
		t.Fatalf("newest first: %+v", events)
	}
	v := verify(t, dashboard, tn)
	if !v.GetIntact() || v.GetEvents() != 2 || string(v.GetHeadHash()) != string(events[0].GetHash()) {
		t.Fatalf("verification %+v", v)
	}
}

func TestRetriesRecordNothingTwice(t *testing.T) {
	vault, dashboard := client(t, "vault"), client(t, "dashboard-api")
	tn := tenant()
	batch := []*auditv1.Event{event(tn, "key.read"), event(tn, "key.read")}
	record(t, vault, batch...)
	again := record(t, vault, append(batch, batch[0], event(tn, "key.revoked"))...)
	if again.GetRecorded() != 1 || again.GetDuplicates() != 3 {
		t.Fatalf("retry: %v", again)
	}
	if n := len(list(t, dashboard, &auditv1.ListEventsRequest{TenantId: tn}).GetEvents()); n != 3 {
		t.Fatalf("stored %d events", n)
	}
	if !verify(t, dashboard, tn).GetIntact() {
		t.Fatal("chain broken by a retry")
	}
}

func TestMalformedEventsRefuseTheWholeBatch(t *testing.T) {
	vault, dashboard := client(t, "vault"), client(t, "dashboard-api")
	tn := tenant()
	bad := map[string]func(*auditv1.Event){
		"event id":        func(e *auditv1.Event) { e.EventId = "nope" },
		"tenant":          func(e *auditv1.Event) { e.TenantId = "" },
		"time":            func(e *auditv1.Event) { e.OccurTime = nil },
		"future":          func(e *auditv1.Event) { e.OccurTime = timestamppb.New(time.Now().Add(time.Hour)) },
		"actor":           func(e *auditv1.Event) { e.Actor = nil },
		"actor id":        func(e *auditv1.Event) { e.Actor.Id = "has space" },
		"action":          func(e *auditv1.Event) { e.Action = "Key Revoked" },
		"outcome":         func(e *auditv1.Event) { e.Outcome = auditv1.Outcome_OUTCOME_UNSPECIFIED },
		"target":          func(e *auditv1.Event) { e.TargetId = strings.Repeat("x", 129) },
		"detail key":      func(e *auditv1.Event) { e.Details = map[string]string{"Bad-Key": "x"} },
		"detail value":    func(e *auditv1.Event) { e.Details = map[string]string{"note": strings.Repeat("é", 257)} },
		"control":         func(e *auditv1.Event) { e.Details = map[string]string{"note": "line\nbreak"} },
		"too many detail": func(e *auditv1.Event) { e.Details = manyDetails(17) },
	}
	for name, mutate := range bad {
		_, err := vault.Record(ctx, &auditv1.RecordRequest{Events: []*auditv1.Event{event(tn, "key.read"), event(tn, "key.read", mutate)}})
		if status.Code(err) != codes.InvalidArgument {
			t.Errorf("%s: %v", name, err)
		}
	}
	_, err := vault.Record(ctx, &auditv1.RecordRequest{})
	if status.Code(err) != codes.InvalidArgument {
		t.Errorf("empty batch: %v", err)
	}
	if n := len(list(t, dashboard, &auditv1.ListEventsRequest{TenantId: tn}).GetEvents()); n != 0 {
		t.Fatalf("a refused batch stored %d events", n)
	}
	// Unicode within the limits is fine.
	record(t, vault, event(tn, "key.read", func(e *auditv1.Event) {
		e.Details = map[string]string{"label": strings.Repeat("é", 256)}
	}))
}

func manyDetails(n int) map[string]string {
	d := map[string]string{}
	for i := range n {
		d[fmt.Sprintf("k%d", i)] = "v"
	}
	return d
}

func TestOnlyTheDashboardReadsTheTrail(t *testing.T) {
	vault := client(t, "vault")
	tn := tenant()
	if _, err := vault.ListEvents(ctx, &auditv1.ListEventsRequest{TenantId: tn}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("vault listed: %v", err)
	}
	if _, err := vault.VerifyChain(ctx, &auditv1.VerifyChainRequest{TenantId: tn}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("vault verified: %v", err)
	}
	stranger := client(t, "stranger")
	if _, err := stranger.Record(ctx, &auditv1.RecordRequest{Events: []*auditv1.Event{event(tn, "key.read")}}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("stranger recorded: %v", err)
	}
}

func TestListingFiltersAndPages(t *testing.T) {
	vault, dashboard := client(t, "vault"), client(t, "dashboard-api")
	tn, other := tenant(), tenant()
	base := time.Now().Add(-time.Hour).Truncate(time.Second)
	at := func(minutes int) func(*auditv1.Event) {
		return func(e *auditv1.Event) { e.OccurTime = timestamppb.New(base.Add(time.Duration(minutes) * time.Minute)) }
	}
	as := func(id string) func(*auditv1.Event) { return func(e *auditv1.Event) { e.Actor.Id = id } }
	forUser := func(id string) func(*auditv1.Event) {
		return func(e *auditv1.Event) {
			e.Actor = &auditv1.Actor{Kind: auditv1.ActorKind_ACTOR_KIND_ASSISTANT, Id: "jarvis"}
			e.OnBehalfOf = id
		}
	}
	record(t, vault,
		event(tn, "key.created", at(1), as("ana")),
		event(tn, "key.revoked", at(2), as("bob")),
		event(tn, "tool.called", at(3), forUser("ana")),
		event(tn, "keyring.opened", at(4), as("ana")), // "key." must not match "keyring."
		event(tn, "member.joined", at(5), as("bob")),
		event(tn, "key_x.test", at(6), as("bob")), // "key_" must be literal, not a wildcard
		event(other, "key.created", at(7), as("ana")),
	)
	names := func(events []*auditv1.Event) string {
		var out []string
		for _, e := range events {
			out = append(out, e.GetAction())
		}
		return strings.Join(out, ",")
	}

	all := list(t, dashboard, &auditv1.ListEventsRequest{TenantId: tn}).GetEvents()
	if got := names(all); got != "key_x.test,member.joined,keyring.opened,tool.called,key.revoked,key.created" {
		t.Fatalf("all, newest first: %s", got)
	}
	if got := names(list(t, dashboard, &auditv1.ListEventsRequest{TenantId: tn, UserId: "ana"}).GetEvents()); got != "keyring.opened,tool.called,key.created" {
		t.Fatalf("ana's (hers and done for her): %s", got)
	}
	if got := names(list(t, dashboard, &auditv1.ListEventsRequest{TenantId: tn, ActionPrefix: "key."}).GetEvents()); got != "key.revoked,key.created" {
		t.Fatalf("key.*: %s", got)
	}
	if got := names(list(t, dashboard, &auditv1.ListEventsRequest{TenantId: tn, ActionPrefix: "key_"}).GetEvents()); got != "key_x.test" {
		t.Fatalf("key_*: %s", got)
	}
	window := &auditv1.ListEventsRequest{TenantId: tn, Since: timestamppb.New(base.Add(2 * time.Minute)),
		Until: timestamppb.New(base.Add(4 * time.Minute))}
	if got := names(list(t, dashboard, window).GetEvents()); got != "tool.called,key.revoked" {
		t.Fatalf("window: %s", got)
	}

	// Pages of 4: the second continues where the first ended.
	first := list(t, dashboard, &auditv1.ListEventsRequest{TenantId: tn, PageSize: 4})
	if len(first.GetEvents()) != 4 || first.GetNextPageToken() == "" {
		t.Fatalf("first page %d %q", len(first.GetEvents()), first.GetNextPageToken())
	}
	second := list(t, dashboard, &auditv1.ListEventsRequest{TenantId: tn, PageSize: 4, PageToken: first.GetNextPageToken()})
	if got := names(second.GetEvents()); got != "key.revoked,key.created" || second.GetNextPageToken() != "" {
		t.Fatalf("second page %s %q", got, second.GetNextPageToken())
	}
	for _, req := range []*auditv1.ListEventsRequest{
		{TenantId: tn, PageToken: "garbage"},
		{TenantId: tn, PageSize: 201},
		{TenantId: tn, ActionPrefix: "Key%"},
		{TenantId: "nope"},
	} {
		if _, err := dashboard.ListEvents(ctx, req); status.Code(err) != codes.InvalidArgument {
			t.Errorf("%v: %v", req, err)
		}
	}
}

func TestConcurrentProducersKeepAGaplessChain(t *testing.T) {
	vault, dashboard := client(t, "vault"), client(t, "dashboard-api")
	tn, other := tenant(), tenant()
	var wg sync.WaitGroup
	errs := make(chan error, 20)
	for range 20 {
		wg.Go(func() {
			// Batches spanning two tenants, in both orders: no deadlocks.
			_, err := vault.Record(ctx, &auditv1.RecordRequest{Events: []*auditv1.Event{
				event(tn, "tool.called"), event(other, "tool.called"), event(tn, "tool.called"),
				event(tn, "tool.called"), event(tn, "tool.called"),
			}})
			errs <- err
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	v := verify(t, dashboard, tn)
	if !v.GetIntact() || v.GetEvents() != 80 {
		t.Fatalf("%+v", v)
	}
	var sequences []int64
	for page := ""; ; {
		resp := list(t, dashboard, &auditv1.ListEventsRequest{TenantId: tn, PageSize: 200, PageToken: page})
		for _, e := range resp.GetEvents() {
			sequences = append(sequences, e.GetSequence())
		}
		if page = resp.GetNextPageToken(); page == "" {
			break
		}
	}
	seen := map[int64]bool{}
	for _, s := range sequences {
		seen[s] = true
	}
	for s := int64(1); s <= 80; s++ {
		if !seen[s] {
			t.Fatalf("sequence %d missing", s)
		}
	}
}

// tamper changes the stored trail behind the service's back, as someone with
// database access could, with the append-only triggers disabled.
func tamper(t *testing.T, sql string, args ...any) {
	t.Helper()
	for _, stmt := range []string{
		`ALTER TABLE events DISABLE TRIGGER events_no_update_or_delete`,
	} {
		if _, err := admin.Exec(ctx, stmt); err != nil {
			t.Fatal(err)
		}
	}
	defer func() {
		_, _ = admin.Exec(ctx, `ALTER TABLE events ENABLE TRIGGER events_no_update_or_delete`)
	}()
	if _, err := admin.Exec(ctx, sql, args...); err != nil {
		t.Fatal(err)
	}
}

func TestVerificationFindsTampering(t *testing.T) {
	vault, dashboard := client(t, "vault"), client(t, "dashboard-api")
	cases := []struct {
		name   string
		change string
		broken int64
	}{
		{"a changed field", `UPDATE events SET target_id = 'other' WHERE tenant_id = $1 AND sequence = 3`, 3},
		{"changed details", `UPDATE events SET details = '{"provider": "xai"}' WHERE tenant_id = $1 AND sequence = 2`, 2},
		{"a changed time", `UPDATE events SET occur_time = occur_time - interval '1 day' WHERE tenant_id = $1 AND sequence = 4`, 4},
		{"a removed event", `DELETE FROM events WHERE tenant_id = $1 AND sequence = 2`, 2},
		{"events cut off the end", `DELETE FROM events WHERE tenant_id = $1 AND sequence >= 4`, 4},
		{"a recomputed hash", `UPDATE events SET action = 'key.read', hash = sha256(hash) WHERE tenant_id = $1 AND sequence = 3`, 3},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tn := tenant()
			for range 5 {
				record(t, vault, event(tn, "key.created", func(e *auditv1.Event) {
					e.TargetType, e.TargetId, e.Details = "provider_key", "k1", map[string]string{"provider": "openai"}
				}))
			}
			if !verify(t, dashboard, tn).GetIntact() {
				t.Fatal("broken before tampering")
			}
			tamper(t, c.change, tn)
			v := verify(t, dashboard, tn)
			if v.GetIntact() || v.GetFirstBrokenSequence() != c.broken {
				t.Fatalf("after %s: %+v", c.name, v)
			}
		})
	}
}

func TestStoredEventsCannotBeChangedOrRemoved(t *testing.T) {
	vault := client(t, "vault")
	tn := tenant()
	record(t, vault, event(tn, "key.created"))
	for _, sql := range []string{
		`UPDATE events SET action = 'key.read' WHERE tenant_id = $1`,
		`DELETE FROM events WHERE tenant_id = $1`,
	} {
		if _, err := admin.Exec(ctx, sql, tn); err == nil || !strings.Contains(err.Error(), "append-only") {
			t.Fatalf("%s: %v", sql, err)
		}
	}
	if _, err := admin.Exec(ctx, `TRUNCATE events`); err == nil {
		t.Fatal("TRUNCATE allowed")
	}
}

func TestTenantsWithoutEventsVerify(t *testing.T) {
	v := verify(t, client(t, "dashboard-api"), tenant())
	if !v.GetIntact() || v.GetEvents() != 0 || len(v.GetHeadHash()) != 0 {
		t.Fatalf("%+v", v)
	}
}
