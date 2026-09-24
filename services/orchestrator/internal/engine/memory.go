package engine

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "jarvis.internal/gen/go/jarvis/agent/v1"
	commonv1 "jarvis.internal/gen/go/jarvis/common/v1"
	knowledgev1 "jarvis.internal/gen/go/jarvis/knowledge/v1"
	"jarvis.internal/libs/go/vaultclient"
	"jarvis.internal/orchestrator/internal/store"
)

const (
	memoryLease       = 5 * time.Minute
	maxMemoryAttempts = 5
	extractTimeout    = 3 * time.Minute
)

func (e *Engine) memoryWorker(ctx context.Context) {
	for ctx.Err() == nil {
		id, attempts, err := e.Store.LeaseMemoryJob(ctx, memoryLease)
		if err != nil {
			if !errors.Is(err, store.ErrNotFound) && ctx.Err() == nil {
				e.Log.Error("cannot lease a memory job", "error", err)
			}
			select {
			case <-ctx.Done():
			case <-time.After(e.opts.PollInterval * 2):
			}
			continue
		}
		jobCtx := WithRequestID(ctx, "memory-"+id.String())
		err = e.extractMemory(jobCtx, id)
		var permanent permanentError
		switch {
		case err == nil:
			e.Metrics.MemoryJobs.WithLabelValues("done").Inc()
			_ = e.Store.FinishMemoryJob(context.WithoutCancel(ctx), id, "done", 0, "")
		case errors.As(err, &permanent) || attempts >= maxMemoryAttempts:
			e.Metrics.MemoryJobs.WithLabelValues("failed").Inc()
			e.Log.Warn("memory extraction failed", "conversation_id", id, "attempts", attempts, "error", err)
			_ = e.Store.FinishMemoryJob(context.WithoutCancel(ctx), id, "failed", 0, truncate(err.Error(), 500))
		default:
			e.Metrics.MemoryJobs.WithLabelValues("retry").Inc()
			backoff := time.Duration(1<<attempts) * time.Minute
			_ = e.Store.FinishMemoryJob(context.WithoutCancel(ctx), id, "queued", backoff, truncate(err.Error(), 500))
		}
	}
}

// extractMemory turns a closed conversation's transcript into knowledge.
func (e *Engine) extractMemory(ctx context.Context, id uuid.UUID) error {
	conv, err := e.Store.Conversation(ctx, id)
	if err != nil {
		return err
	}
	turns, err := e.Store.Transcript(ctx, id)
	if err != nil {
		return err
	}
	var transcript []*agentv1.TranscriptTurn
	spoke := false
	for _, t := range turns {
		transcript = append(transcript, &agentv1.TranscriptTurn{Speaker: t.Role, Text: t.Text})
		spoke = spoke || t.Role == "user"
	}
	if !spoke {
		return nil // nothing the user said
	}
	provider := commonv1.Provider(conv.Provider)
	key, err := e.Keys.ProviderKey(ctx, requestID(ctx), conv.TenantID.String(), provider)
	if errors.Is(err, vaultclient.ErrNoKey) {
		return permanentError{"no provider key"}
	}
	if err != nil {
		return err
	}
	defer clear(key)
	started := time.Now()
	extractCtx, cancel := context.WithTimeout(ctx, extractTimeout)
	defer cancel()
	resp, err := e.Agent.ExtractKnowledge(outgoing(extractCtx), &agentv1.ExtractKnowledgeRequest{
		Model:            &agentv1.Model{Provider: provider, Model: e.model(conv.Provider), ApiKey: key},
		Turns:            transcript,
		Locale:           conv.Locale,
		ConversationTime: conv.CreatedAt.UTC().Format(time.RFC3339),
	})
	e.Metrics.AgentSeconds.WithLabelValues("ExtractKnowledge").Observe(time.Since(started).Seconds())
	if err != nil {
		if code := status.Code(err); code == codes.Unauthenticated || code == codes.InvalidArgument {
			return permanentError{"the provider refused: " + code.String()}
		}
		return err
	}
	if len(resp.GetEntities())+len(resp.GetRelations())+len(resp.GetPassages()) == 0 {
		return nil
	}
	upsertCtx, cancelUpsert := context.WithTimeout(ctx, time.Minute)
	defer cancelUpsert()
	_, err = e.Knowledge.UpsertKnowledge(outgoing(upsertCtx), &knowledgev1.UpsertKnowledgeRequest{
		TenantId: conv.TenantID.String(), UserId: conv.UserID, Scope: knowledgev1.Scope_SCOPE_USER,
		Source: &knowledgev1.Source{Id: "conversation:" + id.String(), Kind: "conversation",
			Title: "Voice conversation " + conv.CreatedAt.UTC().Format("2006-01-02 15:04"), OccurredTime: timestamppb.New(conv.CreatedAt)},
		Entities: resp.GetEntities(), Relations: resp.GetRelations(), Passages: resp.GetPassages(),
	})
	if status.Code(err) == codes.InvalidArgument {
		return permanentError{"the knowledge service refused the extraction"}
	}
	if err == nil {
		e.Log.Info("conversation remembered", "conversation_id", id, "entities", len(resp.GetEntities()),
			"relations", len(resp.GetRelations()), "passages", len(resp.GetPassages()))
	}
	return err
}

// maintenance expires unanswered confirmations and purges old transcripts.
func (e *Engine) maintenance(ctx context.Context) {
	ticker := time.NewTicker(10 * e.opts.PollInterval)
	defer ticker.Stop()
	lastPurge := time.Time{}
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		e.closeAbandoned(ctx)
		e.expireApprovals(ctx)
		expired, err := e.Store.ExpireConfirmations(ctx)
		if err != nil && ctx.Err() == nil {
			e.Log.Error("cannot expire confirmations", "error", err)
		}
		for _, c := range expired {
			e.Metrics.Confirmations.WithLabelValues("expired").Inc()
			if !c.TaskID.Valid {
				continue
			}
			if _, err := e.Store.ResumeTask(ctx, c.TaskID.UUID, func(t *store.Task) error {
				return completePending(t, c.CallID, output(map[string]string{
					"error": "The user did not confirm in time; the action was not done."}))
			}); err != nil {
				e.Log.Warn("cannot resume task after expiry", "task_id", c.TaskID.UUID, "error", err)
			}
			e.signal()
		}
		if time.Since(lastPurge) > time.Hour {
			if _, err := e.Store.PurgeNotifications(ctx, 24*time.Hour); err != nil {
				e.Log.Error("cannot purge notifications", "error", err)
			}
			if n, err := e.Store.PurgeTranscripts(ctx, e.opts.TranscriptRetention); err != nil {
				e.Log.Error("cannot purge transcripts", "error", err)
			} else if n > 0 {
				e.Log.Info("old transcripts purged", "turns", n)
			}
			lastPurge = time.Now()
		}
	}
}

// closeAbandoned closes conversations whose gateway never closed them (it
// crashed), so they still become memory.
func (e *Engine) closeAbandoned(ctx context.Context) {
	abandoned, err := e.Store.CloseAbandoned(ctx)
	if err != nil {
		if ctx.Err() == nil {
			e.Log.Error("cannot close abandoned conversations", "error", err)
		}
		return
	}
	for _, id := range abandoned {
		e.broker.notify(id)
		if err := e.Store.QueueMemoryJob(ctx, id); err != nil {
			e.Log.Error("cannot queue memory for an abandoned conversation", "conversation_id", id, "error", err)
			continue
		}
		e.Log.Warn("closed an abandoned conversation", "conversation_id", id)
	}
}

// expireApprovals ends device approvals nobody signed in time.
func (e *Engine) expireApprovals(ctx context.Context) {
	expired, err := e.Store.ExpireApprovals(ctx)
	if err != nil {
		if ctx.Err() == nil {
			e.Log.Error("cannot expire device approvals", "error", err)
		}
		return
	}
	for _, a := range expired {
		e.dropApproval(ctx, a, "Nobody approved the command in time, so it did not run.", "approval_expired")
	}
}
