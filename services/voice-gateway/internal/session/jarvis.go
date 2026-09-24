package session

// Jarvis tools: the orchestrator gives the realtime model its tools
// (memory, integrations, the user's Mac, background tasks) and executes the
// calls. This file bridges the two for one session.
//
// Everything that decides what the model sees runs on the provider loop
// goroutine, without locks: function calls run on goroutines whose results
// come back on a channel, and events to tell the user (a background task
// finished, a question) arrive from a watcher goroutine the same way.
//
// A response's function outputs are delivered together once the response is
// done and all its calls have returned; then one response.create lets the
// model speak about them (never while the user is talking or another
// response is in progress). Transcripts are recorded in order in the
// background; the orchestrator turns them into memory when the session ends.
//
// Confirmations. The orchestrator runs a state-changing action only when the
// model calls confirm_action in a user turn LATER than the one in which the
// question reached the user. The session counts user turns (one per end of
// user speech; injected text, tool results and the model never count) and:
//   - stamps each function call with the turn at which its response was
//     created, so a response started before the user spoke cannot confirm;
//   - reports each question (a call output with ack_required, or an injected
//     event) with the turn of the first response created after it was given
//     to the model, which is the response that speaks it. A response the
//     gateway had already asked for when the item was added does not count:
//     the provider created it from the conversation before the item. Function
//     calls wait until those reports are stored.
// So confirming always needs a user turn that ended after the model had the
// question and had started answering; instructions hidden in tool results or
// documents cannot supply one.

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	commonv1 "jarvis.internal/gen/go/jarvis/common/v1"
	orchv1 "jarvis.internal/gen/go/jarvis/orchestrator/v1"
	"jarvis.internal/voice-gateway/internal/realtime"
)

const (
	openTimeout      = 3 * time.Second
	recordTimeout    = 3 * time.Second
	ackTimeout       = 2 * time.Second
	ackAttempts      = 3
	ackRetryDelay    = 200 * time.Millisecond
	drainTimeout     = 3 * time.Second
	closeTimeout     = 5 * time.Second
	maxCallsInFlight = 8
	recordBacklog    = 256
	noticeBacklog    = 16
	maxTrackedItems  = 256
	maxCreateRetries = 2
	watchBackoffMin  = 500 * time.Millisecond
	watchBackoffMax  = 10 * time.Second
)

var toolNamePattern = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,64}$`)

// jarvis is the orchestrator side of one session.
type jarvis struct {
	client       orchv1.OrchestratorServiceClient
	conversation string
	instructions string
	tools        []realtime.Tool

	results  chan toolResult
	notices  chan *orchv1.ConversationEvent
	records  chan *orchv1.RecordTurnRequest
	recorded chan struct{} // closed when the recorder has drained

	// Owned by the provider loop goroutine.
	userTurn       int64
	speaking       bool
	itemTurns      map[string]int64 // user speech item → its turn
	responseTurns  map[string]int64 // response in progress → turn at creation
	lastResponse   string
	responding     map[string]bool
	unspoken       delivered // for the next response
	afterRequest   delivered // added while a requested response was being created
	requested      bool      // response.create sent, response.created not seen yet
	createFailures int
	barrier        chan struct{} // closed when the latest acks are stored
	batches        map[string]*callBatch
	callResponse   map[string]string // running call id → response id
	inFlight       int
}

// ack reports at which user turn a question reached the user.
type ack func(ctx context.Context, turn int64) error

// delivered is what was put into the conversation for the model to speak.
type delivered struct {
	want bool
	acks []ack // questions among it
}

func (d *delivered) add(other delivered) {
	d.want = d.want || other.want
	d.acks = append(d.acks, other.acks...)
}

// callBatch is the function calls of one response.
type callBatch struct {
	outstanding int
	done        bool // response.done seen
	results     []toolResult
}

type toolResult struct {
	responseID  string
	callID      string
	output      string
	ackRequired bool
}

// openJarvis starts the orchestrator conversation. Without an orchestrator,
// or when it fails, the session runs without tools (nil).
func (s *session) openJarvis(parent context.Context, kind commonv1.Provider) *jarvis {
	client := s.deps.Orchestrator
	if client == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(parent, openTimeout)
	defer cancel()
	resp, err := client.OpenConversation(s.outgoing(ctx), &orchv1.OpenConversationRequest{
		TenantId:  s.identity.TenantID,
		UserId:    s.identity.UserID,
		SessionId: s.id,
		Provider:  kind,
		Locale:    s.locale,
	})
	if err != nil {
		s.deps.Metrics.OrchestratorErrors.WithLabelValues("OpenConversation").Inc()
		s.log.Warn("jarvis tools unavailable; continuing without them", "error", err)
		return nil
	}
	j := &jarvis{
		client:        client,
		conversation:  resp.GetConversationId(),
		instructions:  resp.GetInstructions(),
		results:       make(chan toolResult, maxCallsInFlight),
		notices:       make(chan *orchv1.ConversationEvent, noticeBacklog),
		records:       make(chan *orchv1.RecordTurnRequest, recordBacklog),
		recorded:      make(chan struct{}),
		itemTurns:     map[string]int64{},
		responseTurns: map[string]int64{},
		responding:    map[string]bool{},
		batches:       map[string]*callBatch{},
		callResponse:  map[string]string{},
	}
	for _, t := range resp.GetTools() {
		if !toolNamePattern.MatchString(t.GetName()) || !json.Valid([]byte(t.GetParametersJson())) {
			s.log.Warn("skipping malformed tool", "tool", t.GetName())
			continue
		}
		j.tools = append(j.tools, realtime.Tool{Name: t.GetName(), Description: t.GetDescription(),
			Parameters: json.RawMessage(t.GetParametersJson())})
	}
	s.log = s.log.With("conversation_id", j.conversation)
	go s.recorder(j)
	return j
}

// closeJarvis records what is left of the transcript and closes the
// conversation, which turns it into memory. Call it after the provider loop
// has stopped.
func (s *session) closeJarvis() {
	j := s.jarvis
	if j == nil {
		return
	}
	close(j.records)
	select {
	case <-j.recorded:
	case <-time.After(drainTimeout):
		s.log.Warn("transcript not fully recorded before close")
	}
	ctx, cancel := context.WithTimeout(context.Background(), closeTimeout)
	defer cancel()
	if _, err := j.client.CloseConversation(s.outgoing(ctx),
		&orchv1.CloseConversationRequest{ConversationId: j.conversation}); err != nil {
		s.deps.Metrics.OrchestratorErrors.WithLabelValues("CloseConversation").Inc()
		s.log.Warn("cannot close the conversation", "error", err)
	}
}

// outgoing tags orchestrator calls with the session id for log correlation.
func (s *session) outgoing(ctx context.Context) context.Context {
	return metadata.AppendToOutgoingContext(ctx, "x-request-id", s.id)
}

// --- transcript --------------------------------------------------------------------

// record queues a turn for the orchestrator; it never blocks the audio path.
func (s *session) record(role orchv1.Role, turn int64, itemID, text string) {
	j := s.jarvis
	if itemID == "" {
		return
	}
	select {
	case j.records <- &orchv1.RecordTurnRequest{ConversationId: j.conversation, Role: role, UserTurn: turn,
		ItemId: itemID, Text: text}:
	default:
		s.deps.Metrics.OrchestratorErrors.WithLabelValues("RecordTurn").Inc()
		s.log.Warn("transcript backlog full; a turn was not recorded", "item_id", itemID)
	}
}

func (s *session) recorder(j *jarvis) {
	defer close(j.recorded)
	for req := range j.records {
		ctx, cancel := context.WithTimeout(context.Background(), recordTimeout)
		_, err := j.client.RecordTurn(s.outgoing(ctx), req)
		cancel()
		if err != nil {
			s.deps.Metrics.OrchestratorErrors.WithLabelValues("RecordTurn").Inc()
			s.log.Warn("cannot record a turn", "error", err)
		}
	}
}

// --- provider events -----------------------------------------------------------------

func (s *session) jarvisSpeechStarted() {
	if j := s.jarvis; j != nil {
		j.speaking = true
	}
}

// jarvisSpeechStopped counts a user turn.
func (s *session) jarvisSpeechStopped(itemID string) {
	j := s.jarvis
	if j == nil {
		return
	}
	j.speaking = false
	j.userTurn++
	if len(j.itemTurns) >= maxTrackedItems {
		clear(j.itemTurns) // transcripts that never came
	}
	j.itemTurns[itemID] = j.userTurn
	s.record(orchv1.Role_ROLE_USER, j.userTurn, itemID, "")
}

func (s *session) jarvisTranscript(e realtime.TranscriptDelta) {
	j := s.jarvis
	if j == nil || !e.Final {
		return
	}
	if e.Role == realtime.RoleUser {
		turn, ok := j.itemTurns[e.ItemID]
		if !ok {
			turn = j.userTurn
		}
		delete(j.itemTurns, e.ItemID)
		s.record(orchv1.Role_ROLE_USER, turn, e.ItemID, e.Text)
		return
	}
	s.record(orchv1.Role_ROLE_ASSISTANT, j.userTurn, e.ItemID, e.Text)
}

func (s *session) jarvisResponseCreated(responseID string) {
	j := s.jarvis
	if j == nil {
		return
	}
	j.responding[responseID] = true
	j.responseTurns[responseID] = j.userTurn
	j.lastResponse = responseID
	// This response speaks what was delivered before it was asked for (or,
	// when the provider started it because the user spoke, everything).
	spoken := j.unspoken
	j.unspoken, j.afterRequest = j.afterRequest, delivered{}
	j.requested, j.createFailures = false, 0
	if len(spoken.acks) > 0 {
		s.startAcks(spoken.acks, j.userTurn)
	}
}

func (s *session) jarvisResponseDone(ctx context.Context, e realtime.ResponseDone) {
	j := s.jarvis
	if j == nil {
		return
	}
	// Calls the provider did not announce separately.
	for _, call := range e.Calls {
		s.jarvisFunctionCall(ctx, call)
	}
	delete(j.responding, e.ResponseID)
	delete(j.responseTurns, e.ResponseID)
	if batch, ok := j.batches[e.ResponseID]; ok {
		batch.done = true
	}
	s.deliver(ctx)
}

// jarvisProviderError: a failed response.create is retried when possible.
func (s *session) jarvisProviderError(ctx context.Context) {
	j := s.jarvis
	if j == nil || !j.requested {
		return
	}
	j.requested = false
	j.unspoken.add(j.afterRequest)
	j.afterRequest = delivered{}
	j.createFailures++
	if j.createFailures > maxCreateRetries {
		j.unspoken.want = false // the questions wait for the next response
		return
	}
	s.respond(ctx)
}

// jarvisFunctionCall starts a call on the orchestrator.
func (s *session) jarvisFunctionCall(ctx context.Context, call realtime.FunctionCall) {
	j := s.jarvis
	if j == nil {
		return
	}
	if _, running := j.callResponse[call.CallID]; running {
		return // announced twice (arguments.done and response.done)
	}
	responseID := call.ResponseID
	if responseID == "" {
		responseID = j.lastResponse
	}
	turn, ok := j.responseTurns[responseID]
	if !ok {
		turn = j.userTurn
	}
	batch := j.batches[responseID]
	if batch == nil {
		batch = &callBatch{}
		j.batches[responseID] = batch
	}
	batch.outstanding++
	j.callResponse[call.CallID] = responseID

	if j.inFlight >= maxCallsInFlight {
		s.deps.Metrics.ToolCalls.WithLabelValues("busy").Inc()
		s.completeCall(ctx, toolResult{responseID: responseID, callID: call.CallID,
			output: `{"error":"Too many tools are running at once; wait for them before calling more."}`})
		return
	}
	j.inFlight++
	go s.runCall(ctx, j.barrier, call, responseID, turn)
}

func (s *session) runCall(ctx context.Context, barrier <-chan struct{}, call realtime.FunctionCall, responseID string, turn int64) {
	j := s.jarvis
	result := toolResult{responseID: responseID, callID: call.CallID}
	if barrier != nil {
		select {
		case <-barrier:
		case <-ctx.Done():
			return
		}
	}
	started := time.Now()
	callCtx, cancel := context.WithTimeout(ctx, s.cfg.ToolTimeout)
	resp, err := j.client.CallTool(s.outgoing(callCtx), &orchv1.CallToolRequest{
		ConversationId: j.conversation,
		CallId:         call.CallID,
		Name:           call.Name,
		ArgumentsJson:  call.Arguments,
		UserTurn:       turn,
	})
	cancel()
	outcome := "ok"
	switch {
	case ctx.Err() != nil:
		return // the session is ending
	case err != nil:
		outcome = "failed"
		s.deps.Metrics.OrchestratorErrors.WithLabelValues("CallTool").Inc()
		s.log.Warn("tool call failed", "tool", call.Name, "call_id", call.CallID, "error", err)
		result.output = toolFailure(err)
	default:
		result.output, result.ackRequired = resp.GetOutput(), resp.GetAckRequired()
		if resp.GetIsError() {
			outcome = "tool_error"
		}
	}
	s.deps.Metrics.ToolCalls.WithLabelValues(outcome).Inc()
	s.deps.Metrics.ToolSeconds.Observe(time.Since(started).Seconds())
	s.log.Debug("tool call finished", "tool", call.Name, "call_id", call.CallID, "outcome", outcome,
		"duration_ms", time.Since(started).Milliseconds())
	select {
	case j.results <- result:
	case <-ctx.Done():
	}
}

func toolFailure(err error) string {
	if status.Code(err) == codes.DeadlineExceeded {
		return `{"error":"The tool took too long and did not report back; tell the user it may not have finished."}`
	}
	return `{"error":"Jarvis could not run this tool right now; tell the user and try again later."}`
}

// jarvisResult takes a finished call from the results channel.
func (s *session) jarvisResult(ctx context.Context, r toolResult) {
	s.jarvis.inFlight--
	s.completeCall(ctx, r)
}

func (s *session) completeCall(ctx context.Context, r toolResult) {
	j := s.jarvis
	if batch, ok := j.batches[r.responseID]; ok {
		batch.outstanding--
		batch.results = append(batch.results, r)
	}
	s.deliver(ctx)
}

// deliver sends the outputs of responses that are done and whose calls have
// all returned, then lets the model speak.
func (s *session) deliver(ctx context.Context) {
	j := s.jarvis
	for responseID, batch := range j.batches {
		if !batch.done || batch.outstanding > 0 {
			continue
		}
		delete(j.batches, responseID)
		for _, r := range batch.results {
			delete(j.callResponse, r.callID)
			writeCtx, cancel := context.WithTimeout(ctx, providerTimeout)
			err := s.conn.SendFunctionOutput(writeCtx, r.callID, r.output)
			cancel()
			if err != nil {
				s.providerFailed(ctx, err)
				return
			}
			var question ack
			if r.ackRequired {
				question = s.toolAck(r.callID)
			}
			s.added(question)
		}
	}
	s.respond(ctx)
}

// jarvisNotice puts an orchestrator event into the conversation.
func (s *session) jarvisNotice(ctx context.Context, e *orchv1.ConversationEvent) {
	writeCtx, cancel := context.WithTimeout(ctx, providerTimeout)
	err := s.conn.InjectMessage(writeCtx, e.GetMessage())
	cancel()
	if err != nil {
		s.providerFailed(ctx, err)
		return
	}
	s.deps.Metrics.Notices.Inc()
	s.log.Info("event put into the conversation", "event_id", e.GetEventId())
	s.added(s.eventAck(e.GetEventId()))
	s.respond(ctx)
}

// added records an item put into the conversation for the model to speak,
// with its ack if it asks the user something.
func (s *session) added(question ack) {
	j := s.jarvis
	target := &j.unspoken
	if j.requested {
		target = &j.afterRequest
	}
	target.want = true
	if question != nil {
		target.acks = append(target.acks, question)
	}
}

// respond asks the model to speak about what was delivered, unless the user
// is talking (their turn will start a response) or a response is running.
func (s *session) respond(ctx context.Context) {
	j := s.jarvis
	if !j.unspoken.want || j.requested || j.speaking || len(j.responding) > 0 {
		return
	}
	writeCtx, cancel := context.WithTimeout(ctx, providerTimeout)
	err := s.conn.CreateResponse(writeCtx)
	cancel()
	if err != nil {
		s.providerFailed(ctx, err)
		return
	}
	j.requested = true
}

// --- question acknowledgements ------------------------------------------------------------

func (s *session) toolAck(callID string) ack {
	j := s.jarvis
	return func(ctx context.Context, turn int64) error {
		_, err := j.client.AckToolOutput(ctx, &orchv1.AckToolOutputRequest{ConversationId: j.conversation,
			CallId: callID, UserTurn: turn})
		return err
	}
}

func (s *session) eventAck(eventID int64) ack {
	j := s.jarvis
	return func(ctx context.Context, turn int64) error {
		_, err := j.client.AckEvent(ctx, &orchv1.AckEventRequest{ConversationId: j.conversation,
			EventId: eventID, UserTurn: turn})
		return err
	}
}

// startAcks stores the acks in the background; function calls dispatched
// from now on wait for them (and for any earlier ones).
func (s *session) startAcks(acks []ack, turn int64) {
	j := s.jarvis
	previous, done := j.barrier, make(chan struct{})
	j.barrier = done
	go func() {
		defer close(done)
		if previous != nil {
			<-previous
		}
		for _, a := range acks {
			s.sendAck(a, turn)
		}
	}()
}

func (s *session) sendAck(a ack, turn int64) {
	var err error
	for attempt := range ackAttempts {
		if attempt > 0 {
			time.Sleep(ackRetryDelay)
		}
		ctx, cancel := context.WithTimeout(context.Background(), ackTimeout)
		err = a(s.outgoing(ctx), turn)
		cancel()
		if err == nil || status.Code(err) == codes.InvalidArgument || status.Code(err) == codes.NotFound {
			break
		}
	}
	if err != nil {
		// The question stays unanswerable; the orchestrator refuses to
		// confirm it and it expires. Safe, but worth an alert.
		s.deps.Metrics.OrchestratorErrors.WithLabelValues("Ack").Inc()
		s.log.Error("cannot acknowledge a question; it cannot be confirmed", "error", err)
	}
}

// --- events -------------------------------------------------------------------------------

// watchLoop streams orchestrator events for this conversation to the
// provider loop, reconnecting after failures.
func (s *session) watchLoop(ctx context.Context) {
	var after int64
	backoff := watchBackoffMin
	for {
		err := s.watchOnce(ctx, &after, &backoff)
		switch {
		case ctx.Err() != nil:
			return
		case err == nil, errors.Is(err, io.EOF):
			return // the conversation was closed
		case status.Code(err) == codes.NotFound || status.Code(err) == codes.FailedPrecondition ||
			status.Code(err) == codes.PermissionDenied:
			s.log.Warn("stopped watching orchestrator events", "error", err)
			return
		}
		s.deps.Metrics.OrchestratorErrors.WithLabelValues("WatchConversation").Inc()
		s.log.Warn("orchestrator event stream failed; reconnecting", "error", err, "backoff_ms", backoff.Milliseconds())
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		backoff = min(2*backoff, watchBackoffMax)
	}
}

func (s *session) watchOnce(ctx context.Context, after *int64, backoff *time.Duration) error {
	j := s.jarvis
	stream, err := j.client.WatchConversation(s.outgoing(ctx), &orchv1.WatchConversationRequest{
		ConversationId: j.conversation, AfterEventId: *after,
	})
	if err != nil {
		return err
	}
	for {
		resp, err := stream.Recv()
		if err != nil {
			return err
		}
		*backoff = watchBackoffMin
		event := resp.GetEvent()
		if event.GetEventId() <= *after || event.GetMessage() == "" {
			continue
		}
		*after = event.GetEventId()
		select {
		case j.notices <- event:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}
