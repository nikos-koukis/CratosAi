package router

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"

	mcpv1 "jarvis.internal/gen/go/jarvis/mcp/v1"
	"jarvis.internal/libs/go/auditlog"
	"jarvis.internal/mcp-router/internal/store"
)

const (
	maxToolsPerIntegration = 500
	maxDescriptionBytes    = 8 << 10
	maxSchemaBytes         = 64 << 10
	maxArgumentsBytes      = 256 << 10
	maxResultBytes         = 1 << 20
	// Tool definitions per integration and per ListTools response (the
	// latter fits gRPC's default 4 MiB client receive limit).
	maxIntegrationToolBytes = 1 << 20
	maxListBytes            = 3 << 20
	listTimeout             = 15 * time.Second
	listConcurrency         = 16
)

var defaultInputSchema = `{"type":"object"}`

// ListTools implements McpRouterServiceServer.
func (s *Service) ListTools(ctx context.Context, req *mcpv1.ListToolsRequest) (*mcpv1.ListToolsResponse, error) {
	o, err := parseOwner(req.GetTenantId(), req.GetUserId())
	if err != nil {
		return nil, err
	}
	integrations, err := s.Store.Integrations(ctx, o.tenant, o.user)
	if err != nil {
		return nil, s.internal(ctx, "list integrations", err)
	}

	type result struct {
		tools   []*mcpv1.Tool
		failure *mcpv1.IntegrationError
	}
	results := make([]result, len(integrations))
	slots := make(chan struct{}, listConcurrency)
	var wg sync.WaitGroup
	for i, integration := range integrations {
		switch integration.Status {
		case store.StatusPending:
			results[i].failure = integrationError(integration, failure{
				reason: mcpv1.ErrorReason_ERROR_REASON_NOT_CONNECTED, message: "waiting for the user's authorization"})
			continue
		case store.StatusNeedsReauth:
			results[i].failure = integrationError(integration, failure{
				reason: mcpv1.ErrorReason_ERROR_REASON_NEEDS_REAUTHORIZATION, message: integration.StatusDetail})
			continue
		}
		wg.Go(func() {
			slots <- struct{}{}
			defer func() { <-slots }()
			tools, err := s.integrationTools(ctx, integration, req.GetRefresh())
			if err != nil {
				f := classify(ctx, err)
				s.logFailure(ctx, "cannot list tools", integration, f, err)
				s.Metrics.ToolLists.WithLabelValues("error").Inc()
				results[i].failure = integrationError(integration, f)
				return
			}
			results[i].tools = tools
		})
	}
	wg.Wait()

	resp := &mcpv1.ListToolsResponse{}
	size := 0
	for i, r := range results {
		if r.failure != nil {
			resp.Unavailable = append(resp.Unavailable, r.failure)
			continue
		}
		n := 0
		for _, tool := range r.tools {
			n += proto.Size(tool)
		}
		if size+n > maxListBytes {
			resp.Unavailable = append(resp.Unavailable, integrationError(integrations[i], failure{
				reason:  mcpv1.ErrorReason_ERROR_REASON_UPSTREAM_ERROR,
				message: "the combined tool list exceeds the router's size limit",
			}))
			continue
		}
		size += n
		resp.Tools = append(resp.Tools, r.tools...)
	}
	return resp, nil
}

func (s *Service) integrationTools(ctx context.Context, integration store.Integration, refresh bool) ([]*mcpv1.Tool, error) {
	key := integration.ID.String()
	if !refresh {
		if data, ok := s.Limits.Tools(ctx, key); ok {
			var cached mcpv1.ListToolsResponse
			if err := proto.Unmarshal(data, &cached); err == nil {
				s.Metrics.ToolLists.WithLabelValues("cache").Inc()
				return cached.Tools, nil
			}
		}
	}

	ctx, cancel := context.WithTimeout(ctx, listTimeout)
	defer cancel()
	session, release, err := s.session(ctx, integration)
	if err != nil {
		return nil, err
	}
	defer release()
	var tools []*mcpv1.Tool
	skipped, size := 0, 0
	for tool, err := range session.Tools(ctx, nil) {
		if err != nil {
			s.dropBrokenSession(ctx, integration, err)
			return nil, err
		}
		converted, ok := convertTool(integration, tool)
		if !ok {
			skipped++
			continue
		}
		if size += proto.Size(converted); len(tools) == maxToolsPerIntegration || size > maxIntegrationToolBytes {
			s.Log.Warn("server lists too many tools; keeping the first ones",
				"integration_id", integration.ID, "kept", len(tools))
			break
		}
		tools = append(tools, converted)
	}
	if skipped > 0 {
		s.Log.Warn("skipped tools with invalid names or oversized schemas", "integration_id", integration.ID, "skipped", skipped)
	}
	s.Metrics.ToolLists.WithLabelValues("server").Inc()
	if data, err := proto.Marshal(&mcpv1.ListToolsResponse{Tools: tools}); err == nil {
		s.Limits.SetTools(context.WithoutCancel(ctx), key, data)
	}
	return tools, nil
}

// convertTool maps a server's tool. Annotations are hints from an untrusted
// server; absent ones take the MCP defaults (destructive, open world).
func convertTool(integration store.Integration, t *mcp.Tool) (*mcpv1.Tool, bool) {
	if t == nil || !validToolName(t.Name) {
		return nil, false
	}
	input := []byte(defaultInputSchema)
	if t.InputSchema != nil {
		var err error
		if input, err = json.Marshal(t.InputSchema); err != nil || len(input) > maxSchemaBytes {
			return nil, false
		}
	}
	var output []byte
	if t.OutputSchema != nil {
		var err error
		if output, err = json.Marshal(t.OutputSchema); err != nil || len(output) > maxSchemaBytes {
			return nil, false
		}
	}
	annotations := &mcpv1.ToolAnnotations{Destructive: true, OpenWorld: true}
	title := t.Title
	if a := t.Annotations; a != nil {
		annotations.ReadOnly = a.ReadOnlyHint
		annotations.Idempotent = a.IdempotentHint
		if a.DestructiveHint != nil {
			annotations.Destructive = *a.DestructiveHint
		}
		if a.OpenWorldHint != nil {
			annotations.OpenWorld = *a.OpenWorldHint
		}
		if title == "" {
			title = a.Title
		}
	}
	return &mcpv1.Tool{
		IntegrationId:    integration.ID.String(),
		IntegrationName:  integration.DisplayName,
		Name:             t.Name,
		Title:            sanitize(title),
		Description:      truncateUTF8(t.Description, maxDescriptionBytes),
		InputSchemaJson:  string(input),
		OutputSchemaJson: string(output),
		Annotations:      annotations,
	}, true
}

// CallTool implements McpRouterServiceServer.
func (s *Service) CallTool(ctx context.Context, req *mcpv1.CallToolRequest) (*mcpv1.CallToolResponse, error) {
	start := time.Now()
	var integration store.Integration
	resp, err := s.callTool(ctx, req, start, &integration)
	outcome := "ok"
	switch {
	case err != nil:
		outcome = codeOf(err).String()
	case resp.GetIsError():
		outcome = "tool_error"
	}
	s.Metrics.ToolCalls.WithLabelValues(outcome).Inc()
	s.Metrics.ToolCallTime.Observe(time.Since(start).Seconds())
	if integration.ID != uuid.Nil { // calls of integrations that were found
		s.auditToolCall(ctx, integration, req.GetToolName(), outcome, time.Since(start))
	}
	return resp, err
}

// auditToolCall records what Jarvis did in the user's account: the tool, not
// its arguments or results (they may hold anything).
func (s *Service) auditToolCall(ctx context.Context, i store.Integration, tool, outcome string, took time.Duration) {
	result, reason := auditlog.Success, ""
	switch outcome {
	case "ok":
	case "tool_error":
		result, reason = auditlog.Failure, "tool_error"
	case codes.ResourceExhausted.String(), codes.FailedPrecondition.String():
		result, reason = auditlog.Denied, strings.ToLower(outcome)
	default:
		result, reason = auditlog.Failure, strings.ToLower(outcome)
	}
	s.Audit.Record(auditlog.Event{TenantID: i.TenantID.String(), Actor: auditlog.Assistant(), OnBehalfOf: i.UserID,
		Action: "tool.called", TargetType: "integration", TargetID: i.ID.String(), Outcome: result, Reason: reason,
		RequestID: RequestID(ctx), Details: map[string]string{"tool": tool, "integration": i.DisplayName,
			"duration_ms": strconv.FormatInt(took.Milliseconds(), 10)}})
}

func (s *Service) callTool(ctx context.Context, req *mcpv1.CallToolRequest, start time.Time,
	found *store.Integration) (*mcpv1.CallToolResponse, error) {
	if !validToolName(req.GetToolName()) {
		return nil, invalid("tool_name must be 1 to 128 visible ASCII characters")
	}
	arguments, err := parseArguments(req.GetArgumentsJson())
	if err != nil {
		return nil, err
	}
	timeout := s.opts.DefaultCallTimeout
	if d := req.GetTimeout(); d != nil {
		if err := d.CheckValid(); err != nil || d.AsDuration() < 0 {
			return nil, invalid("timeout must be a non-negative duration")
		}
		if d.AsDuration() > 0 {
			timeout = min(d.AsDuration(), s.opts.MaxCallTimeout)
		}
	}
	integration, err := s.owned(ctx, req.GetTenantId(), req.GetUserId(), req.GetIntegrationId())
	if err != nil {
		return nil, err
	}
	*found = integration
	switch integration.Status {
	case store.StatusPending:
		return nil, reasonError(codes.FailedPrecondition, mcpv1.ErrorReason_ERROR_REASON_NOT_CONNECTED,
			"the integration is waiting for the user's authorization")
	case store.StatusNeedsReauth:
		return nil, reasonError(codes.FailedPrecondition, mcpv1.ErrorReason_ERROR_REASON_NEEDS_REAUTHORIZATION,
			"the integration must be reauthorized")
	}
	if ok, retryAfter := s.Limits.Allow(ctx, integration.TenantID.String(), integration.ID.String()); !ok {
		s.Metrics.RateLimited.Inc()
		return nil, rateLimited(retryAfter)
	}

	callCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	result, err := s.call(callCtx, integration, req.GetToolName(), arguments)
	if err != nil {
		f := classify(callCtx, err)
		s.logFailure(ctx, "tool call failed", integration, f, err)
		return nil, f.err()
	}

	resp := &mcpv1.CallToolResponse{IsError: result.IsError}
	if result.NeedsInput() {
		// Multi-round-trip input (elicitation) is not relayed yet.
		resp.IsError = true
		resp.Content = []*mcpv1.Content{textContent("The tool asked for additional input, which Jarvis cannot provide yet.")}
	} else {
		budget := maxResultBytes
		resp.StructuredContentJson, resp.Truncated = structured(result.StructuredContent, &budget)
		var truncated bool
		resp.Content, truncated = convertContent(result.Content, &budget)
		resp.Truncated = resp.Truncated || truncated
	}
	resp.Duration = durationpb.New(time.Since(start))
	s.Log.Info("tool called", "request_id", RequestID(ctx), "tenant_id", integration.TenantID,
		"integration_id", integration.ID, "tool", req.GetToolName(), "is_error", resp.IsError,
		"truncated", resp.Truncated, "duration_ms", time.Since(start).Milliseconds())
	return resp, nil
}

// call runs the tool, reconnecting once if the server lost the session (the
// request was then never processed, so retrying is safe).
func (s *Service) call(ctx context.Context, integration store.Integration, name string, arguments json.RawMessage) (*mcp.CallToolResult, error) {
	for attempt := 0; ; attempt++ {
		session, release, err := s.session(ctx, integration)
		if err != nil {
			return nil, err
		}
		result, err := session.CallTool(ctx, &mcp.CallToolParams{Name: name, Arguments: arguments})
		release()
		if err == nil {
			return result, nil
		}
		s.dropBrokenSession(ctx, integration, err)
		if attempt == 0 && errors.Is(err, mcp.ErrSessionMissing) {
			continue
		}
		return nil, err
	}
}

// dropBrokenSession discards a session after a transport failure, so the
// next call reconnects. Protocol errors (the server answered) keep it.
func (s *Service) dropBrokenSession(ctx context.Context, integration store.Integration, err error) {
	if f := classify(ctx, err); f.reason != mcpv1.ErrorReason_ERROR_REASON_UPSTREAM_ERROR && f.code != codes.Canceled {
		s.Pool.Invalidate(integration.ID)
	}
}

func (s *Service) logFailure(ctx context.Context, msg string, integration store.Integration, f failure, err error) {
	attrs := []any{"request_id", RequestID(ctx), "integration_id", integration.ID, "code", f.code.String(),
		"reason", f.reason.String(), "error", err}
	if f.internal {
		s.Log.Error(msg, attrs...)
		return
	}
	s.Log.Warn(msg, attrs...)
}

func integrationError(integration store.Integration, f failure) *mcpv1.IntegrationError {
	reason := f.reason
	if reason == mcpv1.ErrorReason_ERROR_REASON_UNSPECIFIED {
		reason = mcpv1.ErrorReason_ERROR_REASON_UPSTREAM_UNAVAILABLE
	}
	return &mcpv1.IntegrationError{
		IntegrationId:   integration.ID.String(),
		IntegrationName: integration.DisplayName,
		Reason:          reason,
		Message:         f.message,
	}
}

func parseArguments(raw string) (json.RawMessage, error) {
	if raw == "" {
		return json.RawMessage(`{}`), nil
	}
	if len(raw) > maxArgumentsBytes {
		return nil, invalid("arguments_json is larger than 256 KiB")
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal([]byte(raw), &object); err != nil || object == nil {
		return nil, invalid("arguments_json must be a JSON object")
	}
	return json.RawMessage(raw), nil
}

// structured encodes the structured result if it fits the budget.
func structured(value any, budget *int) (string, bool) {
	if value == nil {
		return "", false
	}
	data, err := json.Marshal(value)
	if err != nil || len(data) > *budget {
		return "", true
	}
	*budget -= len(data)
	return string(data), false
}

// convertContent maps result blocks within the byte budget: text is cut at a
// character boundary, other blocks that do not fit are dropped.
func convertContent(blocks []mcp.Content, budget *int) ([]*mcpv1.Content, bool) {
	out := make([]*mcpv1.Content, 0, len(blocks))
	truncated := false
	take := func(n int) bool {
		if n > *budget {
			truncated = true
			return false
		}
		*budget -= n
		return true
	}
	for _, block := range blocks {
		switch c := block.(type) {
		case *mcp.TextContent:
			text := c.Text
			if len(text) > *budget {
				text, truncated = truncateUTF8(text, *budget), true
			}
			*budget -= len(text)
			if text != "" || c.Text == "" {
				out = append(out, textContent(text))
			}
		case *mcp.ImageContent:
			if take(len(c.Data) + len(c.MIMEType)) {
				out = append(out, &mcpv1.Content{Content: &mcpv1.Content_Image{
					Image: &mcpv1.BinaryContent{MimeType: c.MIMEType, Data: c.Data}}})
			}
		case *mcp.AudioContent:
			if take(len(c.Data) + len(c.MIMEType)) {
				out = append(out, &mcpv1.Content{Content: &mcpv1.Content_Audio{
					Audio: &mcpv1.BinaryContent{MimeType: c.MIMEType, Data: c.Data}}})
			}
		case *mcp.ResourceLink:
			if take(len(c.URI) + len(c.Name) + len(c.MIMEType) + len(c.Description)) {
				out = append(out, &mcpv1.Content{Content: &mcpv1.Content_ResourceLink{ResourceLink: &mcpv1.ResourceLink{
					Uri: c.URI, Name: c.Name, MimeType: c.MIMEType, Description: c.Description}}})
			}
		case *mcp.EmbeddedResource:
			if r := c.Resource; r != nil && take(len(r.URI)+len(r.MIMEType)+len(r.Text)+len(r.Blob)) {
				out = append(out, &mcpv1.Content{Content: &mcpv1.Content_Resource{Resource: &mcpv1.EmbeddedResource{
					Uri: r.URI, MimeType: r.MIMEType, Text: r.Text, Blob: r.Blob}}})
			}
		default:
			// Not a tool-result block type; ignore.
		}
	}
	return out, truncated
}

func textContent(text string) *mcpv1.Content {
	return &mcpv1.Content{Content: &mcpv1.Content_Text{Text: &mcpv1.TextContent{Text: text}}}
}
