package engine

import (
	"context"

	auditv1 "jarvis.internal/gen/go/jarvis/audit/v1"
	"jarvis.internal/libs/go/auditlog"
	"jarvis.internal/orchestrator/internal/store"
)

// What Jarvis does for a user, recorded in the tenant's audit trail. Events
// name tools, devices and programs, never what a user said or asked for
// (goals, action summaries, command arguments): owners read every member's
// trail.

func (e *Engine) audit(ctx context.Context, tenant, user string, actor auditlog.Actor, action, targetType,
	targetID string, outcome auditv1.Outcome, reason string, details map[string]string) {
	e.Audit.Record(auditlog.Event{TenantID: tenant, Actor: actor, OnBehalfOf: user, Action: action,
		TargetType: targetType, TargetID: targetID, Outcome: outcome, Reason: reason, RequestID: requestID(ctx),
		Details: details})
}

// actionDetails names what an action would do, without its arguments.
func actionDetails(a *action) map[string]string {
	if a == nil {
		return nil
	}
	details := map[string]string{"kind": a.Kind}
	if a.Tool != "" {
		details["tool"] = a.Tool
	}
	if a.Integration != "" {
		details["integration"] = a.Integration
	}
	return details
}

// taskOutcome maps a finished task's state; ok is false for states that are
// not an ending (or recorded elsewhere, like a cancellation by the user).
func taskOutcome(state string) (auditv1.Outcome, bool) {
	switch state {
	case store.TaskSucceeded:
		return auditlog.Success, true
	case store.TaskFailed:
		return auditlog.Failure, true
	}
	return 0, false
}
