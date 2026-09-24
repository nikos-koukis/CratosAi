// Package router implements jarvis.mcp.v1.McpRouterService.
package router

import (
	"context"
	"errors"
	"log/slog"
	"net/url"
	"time"

	"github.com/google/uuid"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	auditv1 "jarvis.internal/gen/go/jarvis/audit/v1"
	mcpv1 "jarvis.internal/gen/go/jarvis/mcp/v1"
	"jarvis.internal/libs/go/auditlog"
	"jarvis.internal/mcp-router/internal/catalog"
	"jarvis.internal/mcp-router/internal/limits"
	"jarvis.internal/mcp-router/internal/metrics"
	"jarvis.internal/mcp-router/internal/netguard"
	"jarvis.internal/mcp-router/internal/oauthflow"
	"jarvis.internal/mcp-router/internal/store"
	"jarvis.internal/mcp-router/internal/upstream"
)

const (
	maxIntegrationsPerUser = 50
	maxServerURLBytes      = 2048
)

// Options are the router's policies.
type Options struct {
	AllowCustomServers bool
	DefaultCallTimeout time.Duration
	MaxCallTimeout     time.Duration
}

// Deps are the router's collaborators.
type Deps struct {
	Store   *store.Store
	Flow    *oauthflow.Flow
	Catalog *catalog.Catalog
	Pool    *upstream.Pool
	Limits  *limits.Limits
	Guard   netguard.Guard
	Metrics *metrics.Metrics
	Log     *slog.Logger
	// Audit records connections and tool calls (nil: nothing is recorded).
	Audit *auditlog.Recorder
}

// auditIntegration records a change to an integration, done by its user.
func (s *Service) auditIntegration(ctx context.Context, i store.Integration, action string,
	outcome auditv1.Outcome, reason string) {
	server := i.CatalogSlug
	if server == "" {
		server = hostOf(i.ServerURL)
	}
	s.Audit.Record(auditlog.Event{TenantID: i.TenantID.String(), Actor: auditlog.User(i.UserID), Action: action,
		TargetType: "integration", TargetID: i.ID.String(), Outcome: outcome, Reason: reason,
		RequestID: RequestID(ctx), Details: map[string]string{"name": i.DisplayName, "server": server,
			"auth": string(i.Auth)}})
}

func hostOf(raw string) string {
	if u, err := url.Parse(raw); err == nil {
		return u.Host
	}
	return ""
}

// Service implements McpRouterServiceServer.
type Service struct {
	mcpv1.UnimplementedMcpRouterServiceServer
	Deps
	opts Options
}

// New creates the service.
func New(deps Deps, opts Options) *Service {
	return &Service{Deps: deps, opts: opts}
}

// ListCatalog implements McpRouterServiceServer.
func (s *Service) ListCatalog(context.Context, *mcpv1.ListCatalogRequest) (*mcpv1.ListCatalogResponse, error) {
	resp := &mcpv1.ListCatalogResponse{}
	for _, entry := range s.Catalog.Entries() {
		auth := mcpv1.AuthKind_AUTH_KIND_OAUTH
		if entry.Auth == catalog.Bearer {
			auth = mcpv1.AuthKind_AUTH_KIND_BEARER_TOKEN
		}
		resp.Servers = append(resp.Servers, &mcpv1.CatalogServer{
			Slug: entry.Slug, Name: entry.Name, Url: entry.URL, Auth: auth,
			Available: s.Catalog.Available(entry), Notes: entry.Notes,
		})
	}
	return resp, nil
}

// CreateIntegration implements McpRouterServiceServer.
func (s *Service) CreateIntegration(ctx context.Context, req *mcpv1.CreateIntegrationRequest) (*mcpv1.CreateIntegrationResponse, error) {
	token := req.GetBearerToken()
	defer clear(token)
	o, err := parseOwner(req.GetTenantId(), req.GetUserId())
	if err != nil {
		return nil, err
	}

	integration := store.Integration{ID: uuid.New(), TenantID: o.tenant, UserID: o.user, Status: store.StatusPending}
	var defaultName string
	switch server := req.GetServer().(type) {
	case *mcpv1.CreateIntegrationRequest_CatalogSlug:
		entry, ok := s.Catalog.Get(server.CatalogSlug)
		if !ok {
			return nil, invalid("unknown catalog_slug")
		}
		if !s.Catalog.Available(entry) {
			return nil, reasonError(codes.FailedPrecondition, mcpv1.ErrorReason_ERROR_REASON_CATALOG_NOT_CONFIGURED,
				entry.Name+" needs OAuth client credentials that are not configured")
		}
		integration.ServerURL, integration.CatalogSlug, defaultName = entry.URL, entry.Slug, entry.Name
		integration.Auth = store.AuthOAuth
		if entry.Auth == catalog.Bearer {
			integration.Auth = store.AuthBearer
		}
	case *mcpv1.CreateIntegrationRequest_ServerUrl:
		if !s.opts.AllowCustomServers {
			return nil, reasonError(codes.PermissionDenied, mcpv1.ErrorReason_ERROR_REASON_SERVER_NOT_ALLOWED,
				"custom servers are disabled; choose a catalog server")
		}
		u, err := s.checkServerURL(server.ServerUrl)
		if err != nil {
			return nil, err
		}
		integration.ServerURL, defaultName = u.String(), truncateUTF8(u.Hostname(), 64)
		integration.Auth = store.AuthOAuth
		if len(token) > 0 {
			integration.Auth = store.AuthBearer
		}
	default:
		return nil, invalid("catalog_slug or server_url is required")
	}

	integration.DisplayName = req.GetDisplayName()
	if integration.DisplayName == "" {
		integration.DisplayName = defaultName
	}
	if !validDisplayName(integration.DisplayName) {
		return nil, invalid("display_name must be 1 to 64 characters without control characters or surrounding spaces")
	}
	switch {
	case integration.Auth == store.AuthBearer && !validBearerToken(token):
		return nil, invalid("this server needs bearer_token: 1 to 8192 visible ASCII characters")
	case integration.Auth == store.AuthOAuth && len(token) > 0:
		return nil, invalid("this server uses OAuth; leave bearer_token empty")
	}

	existing, err := s.Store.Integrations(ctx, o.tenant, o.user)
	if err != nil {
		return nil, s.internal(ctx, "list integrations", err)
	}
	if len(existing) >= maxIntegrationsPerUser {
		return nil, status.Errorf(codes.ResourceExhausted, "a user can have at most %d integrations", maxIntegrationsPerUser)
	}

	if integration.Auth == store.AuthBearer {
		sealed, err := s.Flow.SealBearer(ctx, RequestID(ctx), integration, token)
		if err != nil {
			return nil, s.dependencyError(ctx, "seal bearer token", err)
		}
		integration.Status, integration.CredentialsSealed = store.StatusConnected, sealed
	}
	created, err := s.Store.CreateIntegration(ctx, integration)
	if err != nil {
		return nil, s.internal(ctx, "create integration", err)
	}
	s.Log.Info("integration created", "request_id", RequestID(ctx), "integration_id", created.ID,
		"tenant_id", created.TenantID, "catalog_slug", created.CatalogSlug, "auth", created.Auth)
	if created.Auth == store.AuthBearer {
		s.auditIntegration(ctx, created, "integration.connected", auditlog.Success, "")
		return &mcpv1.CreateIntegrationResponse{Integration: toProto(created)}, nil
	}

	authURL, err := s.Flow.Begin(ctx, RequestID(ctx), created)
	if err != nil {
		// Leave nothing half-created behind.
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		if _, delErr := s.Store.DeleteIntegration(cleanup, created.TenantID, created.UserID, created.ID); delErr != nil {
			s.Log.Error("cannot delete integration after failed authorization start", "integration_id", created.ID, "error", delErr)
		}
		return nil, s.beginError(ctx, err)
	}
	s.Metrics.Authorizations.WithLabelValues("begin", "ok").Inc()
	s.auditIntegration(ctx, created, "integration.created", auditlog.Success, "")
	return &mcpv1.CreateIntegrationResponse{Integration: toProto(created), AuthorizationUrl: authURL}, nil
}

// CompleteAuthorization implements McpRouterServiceServer.
func (s *Service) CompleteAuthorization(ctx context.Context, req *mcpv1.CompleteAuthorizationRequest) (*mcpv1.CompleteAuthorizationResponse, error) {
	switch {
	case !printableASCII(req.GetState(), 1, 512):
		return nil, invalid("state must be 1 to 512 printable ASCII characters")
	case len(req.GetCode()) > 4096, len(req.GetIss()) > maxServerURLBytes, len(req.GetError()) > 256:
		return nil, invalid("code, iss or error is too long")
	}
	id, err := s.Flow.Complete(ctx, RequestID(ctx), req.GetState(), req.GetCode(), req.GetIss(), req.GetError())
	if err != nil {
		s.Metrics.Authorizations.WithLabelValues("complete", "failed").Inc()
		if errors.Is(err, oauthflow.ErrAuthorization) {
			s.Log.Info("authorization not completed", "request_id", RequestID(ctx), "integration_id", id, "reason", err.Error())
			if integration, loadErr := s.Store.IntegrationByID(ctx, id); id != uuid.Nil && loadErr == nil {
				outcome, reason := auditlog.Failure, "authorization_failed"
				if req.GetError() != "" {
					outcome, reason = auditlog.Denied, "access_denied_by_user"
				}
				s.auditIntegration(ctx, integration, "integration.authorization_failed", outcome, reason)
			}
			return nil, reasonError(codes.FailedPrecondition, mcpv1.ErrorReason_ERROR_REASON_AUTHORIZATION_FAILED, sanitize(err.Error()))
		}
		return nil, s.dependencyError(ctx, "complete authorization", err)
	}
	s.Metrics.Authorizations.WithLabelValues("complete", "ok").Inc()
	s.forget(ctx, id)
	integration, err := s.Store.IntegrationByID(ctx, id)
	if err != nil {
		return nil, s.internal(ctx, "load integration", err)
	}
	s.Log.Info("integration connected", "request_id", RequestID(ctx), "integration_id", id, "tenant_id", integration.TenantID)
	s.auditIntegration(ctx, integration, "integration.connected", auditlog.Success, "")
	return &mcpv1.CompleteAuthorizationResponse{Integration: toProto(integration)}, nil
}

// ReauthorizeIntegration implements McpRouterServiceServer.
func (s *Service) ReauthorizeIntegration(ctx context.Context, req *mcpv1.ReauthorizeIntegrationRequest) (*mcpv1.ReauthorizeIntegrationResponse, error) {
	integration, err := s.owned(ctx, req.GetTenantId(), req.GetUserId(), req.GetIntegrationId())
	if err != nil {
		return nil, err
	}
	if integration.Auth == store.AuthBearer {
		return nil, status.Error(codes.FailedPrecondition,
			"bearer-token integrations cannot be reauthorized; delete the integration and create it with a new token")
	}
	authURL, err := s.Flow.Begin(ctx, RequestID(ctx), integration)
	if err != nil {
		return nil, s.beginError(ctx, err)
	}
	s.Metrics.Authorizations.WithLabelValues("begin", "ok").Inc()
	return &mcpv1.ReauthorizeIntegrationResponse{AuthorizationUrl: authURL}, nil
}

// ListIntegrations implements McpRouterServiceServer.
func (s *Service) ListIntegrations(ctx context.Context, req *mcpv1.ListIntegrationsRequest) (*mcpv1.ListIntegrationsResponse, error) {
	o, err := parseOwner(req.GetTenantId(), req.GetUserId())
	if err != nil {
		return nil, err
	}
	integrations, err := s.Store.Integrations(ctx, o.tenant, o.user)
	if err != nil {
		return nil, s.internal(ctx, "list integrations", err)
	}
	resp := &mcpv1.ListIntegrationsResponse{Integrations: make([]*mcpv1.Integration, 0, len(integrations))}
	for _, integration := range integrations {
		resp.Integrations = append(resp.Integrations, toProto(integration))
	}
	return resp, nil
}

// DeleteIntegration implements McpRouterServiceServer.
func (s *Service) DeleteIntegration(ctx context.Context, req *mcpv1.DeleteIntegrationRequest) (*mcpv1.DeleteIntegrationResponse, error) {
	o, err := parseOwner(req.GetTenantId(), req.GetUserId())
	if err != nil {
		return nil, err
	}
	id, err := parseIntegrationID(req.GetIntegrationId())
	if err != nil {
		return nil, err
	}
	before, lookupErr := s.Store.IntegrationByID(ctx, id)
	deleted, err := s.Store.DeleteIntegration(ctx, o.tenant, o.user, id)
	if err != nil {
		return nil, s.internal(ctx, "delete integration", err)
	}
	if deleted {
		if lookupErr == nil {
			s.auditIntegration(ctx, before, "integration.deleted", auditlog.Success, "")
		}
		s.forget(ctx, id)
		s.Log.Info("integration deleted", "request_id", RequestID(ctx), "integration_id", id, "tenant_id", o.tenant)
	}
	return &mcpv1.DeleteIntegrationResponse{}, nil
}

// --- helpers ---------------------------------------------------------------------

// owned loads an integration of the caller's tenant and user; anything else
// is NOT_FOUND.
func (s *Service) owned(ctx context.Context, tenantID, userID, integrationID string) (store.Integration, error) {
	o, err := parseOwner(tenantID, userID)
	if err != nil {
		return store.Integration{}, err
	}
	id, err := parseIntegrationID(integrationID)
	if err != nil {
		return store.Integration{}, err
	}
	integration, err := s.Store.Integration(ctx, o.tenant, o.user, id)
	if errors.Is(err, store.ErrNotFound) {
		return store.Integration{}, notFound()
	}
	if err != nil {
		return store.Integration{}, s.internal(ctx, "load integration", err)
	}
	return integration, nil
}

func (s *Service) checkServerURL(raw string) (*url.URL, error) {
	notAllowed := func(message string) error {
		return reasonError(codes.PermissionDenied, mcpv1.ErrorReason_ERROR_REASON_SERVER_NOT_ALLOWED, message)
	}
	if len(raw) > maxServerURLBytes {
		return nil, invalid("server_url is too long")
	}
	u, err := s.Guard.CheckURL(raw)
	if err != nil {
		return nil, notAllowed(sanitize(err.Error()))
	}
	if u.Fragment != "" || u.RawFragment != "" {
		return nil, invalid("server_url must not have a fragment")
	}
	return u, nil
}

// session opens (or reuses) the integration's MCP session.
func (s *Service) session(ctx context.Context, integration store.Integration) (*mcp.ClientSession, func(), error) {
	requestID := RequestID(ctx)
	return s.Pool.Session(ctx, integration.ID, integration.ServerURL,
		func(ctx context.Context) (upstream.Source, error) {
			return s.Flow.TokenSource(ctx, requestID, integration)
		},
		func() {
			s.Log.Warn("server rejected the stored authorization", "integration_id", integration.ID)
			s.Audit.Record(auditlog.Event{TenantID: integration.TenantID.String(), Actor: auditlog.Service("mcp-router"),
				OnBehalfOf: integration.UserID, Action: "integration.needs_reauthorization", TargetType: "integration",
				TargetID: integration.ID.String(), Outcome: auditlog.Failure, Reason: "authorization_rejected",
				RequestID: requestID, Details: map[string]string{"name": integration.DisplayName}})
			s.Flow.MarkNeedsReauth(context.WithoutCancel(ctx), integration.ID, "the server rejected the stored authorization")
			s.forget(ctx, integration.ID)
		})
}

// forget drops everything cached for an integration.
func (s *Service) forget(ctx context.Context, id uuid.UUID) {
	s.Pool.Invalidate(id)
	s.Flow.Forget(id)
	s.Limits.ForgetTools(context.WithoutCancel(ctx), id.String())
}

func (s *Service) beginError(ctx context.Context, err error) error {
	s.Metrics.Authorizations.WithLabelValues("begin", "failed").Inc()
	switch {
	case errors.Is(err, oauthflow.ErrNotConfigured):
		return reasonError(codes.FailedPrecondition, mcpv1.ErrorReason_ERROR_REASON_CATALOG_NOT_CONFIGURED, err.Error())
	case errors.Is(err, netguard.ErrNotAllowed):
		return reasonError(codes.PermissionDenied, mcpv1.ErrorReason_ERROR_REASON_SERVER_NOT_ALLOWED, sanitize(err.Error()))
	case errors.Is(err, oauthflow.ErrAuthorization):
		s.Log.Info("authorization could not start", "request_id", RequestID(ctx), "reason", err.Error())
		return reasonError(codes.FailedPrecondition, mcpv1.ErrorReason_ERROR_REASON_AUTHORIZATION_FAILED, sanitize(err.Error()))
	default:
		return s.dependencyError(ctx, "begin authorization", err)
	}
}

// dependencyError reports a Vault or database failure.
func (s *Service) dependencyError(ctx context.Context, what string, err error) error {
	f := classify(ctx, err)
	if f.code == codes.Unavailable && f.reason == mcpv1.ErrorReason_ERROR_REASON_UNSPECIFIED {
		s.Log.Error(what+" failed", "request_id", RequestID(ctx), "error", err)
		return f.err()
	}
	return s.internal(ctx, what, err)
}

func (s *Service) internal(ctx context.Context, what string, err error) error {
	s.Log.Error(what+" failed", "request_id", RequestID(ctx), "error", err)
	return status.Errorf(codes.Internal, "internal error (request %s)", RequestID(ctx))
}

func toProto(i store.Integration) *mcpv1.Integration {
	auth := mcpv1.AuthKind_AUTH_KIND_OAUTH
	if i.Auth == store.AuthBearer {
		auth = mcpv1.AuthKind_AUTH_KIND_BEARER_TOKEN
	}
	var state mcpv1.IntegrationStatus
	switch i.Status {
	case store.StatusPending:
		state = mcpv1.IntegrationStatus_INTEGRATION_STATUS_PENDING_AUTHORIZATION
	case store.StatusConnected:
		state = mcpv1.IntegrationStatus_INTEGRATION_STATUS_CONNECTED
	case store.StatusNeedsReauth:
		state = mcpv1.IntegrationStatus_INTEGRATION_STATUS_NEEDS_REAUTHORIZATION
	}
	return &mcpv1.Integration{
		IntegrationId: i.ID.String(),
		TenantId:      i.TenantID.String(),
		UserId:        i.UserID,
		DisplayName:   i.DisplayName,
		ServerUrl:     i.ServerURL,
		CatalogSlug:   i.CatalogSlug,
		Auth:          auth,
		Status:        state,
		StatusDetail:  i.StatusDetail,
		CreateTime:    timestamppb.New(i.CreatedAt),
		UpdateTime:    timestamppb.New(i.UpdatedAt),
	}
}
