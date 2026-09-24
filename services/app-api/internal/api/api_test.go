package api_test

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	"jarvis.internal/app-api/internal/api"
	"jarvis.internal/app-api/internal/secret"
	appv1 "jarvis.internal/gen/go/jarvis/app/v1"
	orchv1 "jarvis.internal/gen/go/jarvis/orchestrator/v1"
	"jarvis.internal/libs/go/usertoken"
)

var errNotFound = status.Error(codes.NotFound, "no such task")

func TestPairingGivesASessionForTheAppAndTheVoiceGateway(t *testing.T) {
	h := newHarness(t)
	issued := h.code(t)
	link, err := url.Parse(issued.GetPairingUrl())
	if err != nil || link.Scheme != "jarvis" || link.Host != "pair" || link.Query().Get("server") != publicURL ||
		link.Query().Get("code") != issued.GetCode() {
		t.Fatalf("pairing url %q", issued.GetPairingUrl())
	}
	if time.Until(issued.GetExpireTime().AsTime()) > 10*time.Minute {
		t.Fatalf("expires %v", issued.GetExpireTime().AsTime())
	}

	// People type codes loosely.
	typed := " " + strings.ToLower(strings.ReplaceAll(issued.GetCode(), "-", " ")) + " "
	resp, err := h.client.RedeemPairingCode(tctx(t), connect.NewRequest(&appv1.RedeemPairingCodeRequest{
		Code: typed, DeviceName: "Κώστα's iPhone", DeviceModel: "iPhone17,1"}))
	if err != nil {
		t.Fatal(err)
	}
	s := resp.Msg.GetSession()
	if s.GetTenantId() != h.tenant || s.GetUserId() != h.user || s.GetVoiceUrl() != voiceURL ||
		s.GetRefreshToken() == "" || !s.GetRefreshTokenExpireTime().AsTime().After(time.Now().Add(29*24*time.Hour)) {
		t.Fatalf("session = %v", s)
	}

	// The voice token is what the voice gateway accepts, verified with the
	// published JWKS; the access token is not.
	jwksResp, err := http.Get(h.server.URL + "/.well-known/jwks.json")
	if err != nil {
		t.Fatal(err)
	}
	jwksBody, _ := io.ReadAll(jwksResp.Body)
	_ = jwksResp.Body.Close()
	keys, err := usertoken.ParseJWKS(jwksBody)
	if err != nil {
		t.Fatal(err)
	}
	gateway, err := usertoken.NewVerifier(keys, tokenIssuer, api.VoiceAudience, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := gateway.Verify(s.GetVoiceToken())
	if err != nil || identity.TenantID != h.tenant || identity.UserID != h.user || identity.SessionID != s.GetSessionId() {
		t.Fatalf("voice token: %+v, %v", identity, err)
	}
	if _, err := gateway.Verify(s.GetAccessToken()); err == nil {
		t.Fatal("the voice gateway accepted an access token")
	}

	// The access token works here, for this user only.
	if _, err := h.client.ListTasks(tctx(t), authed(s.GetAccessToken(), &appv1.ListTasksRequest{})); err != nil {
		t.Fatal(err)
	}
	if calls := h.orch.calls(); len(calls) != 1 || calls[0] != h.tenant+"/"+h.user {
		t.Fatalf("orchestrator calls = %v", calls)
	}

	// A code works once.
	_, err = h.client.RedeemPairingCode(tctx(t), connect.NewRequest(&appv1.RedeemPairingCodeRequest{
		Code: issued.GetCode(), DeviceName: "Another phone", DeviceModel: "iPhone17,1"}))
	wantReason(t, err, connect.CodeUnauthenticated, appv1.ErrorReason_ERROR_REASON_PAIRING_CODE_INVALID)
}

func TestBadPairingCodesAreRefusedAlike(t *testing.T) {
	h := newHarness(t, func(o *options) { o.burst = 4 })
	code, _ := secret.NewPairingCode()
	normalized, _ := secret.NormalizeCode(code)
	if err := h.store.CreatePairingCode(tctx(t), secret.Hash(normalized), uuid.MustParse(h.tenant), h.user,
		time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	for name, attempt := range map[string]string{"expired": code, "unknown": "ABCD-EFGH-JKMN", "malformed": "hello"} {
		_, err := h.client.RedeemPairingCode(tctx(t), connect.NewRequest(&appv1.RedeemPairingCodeRequest{
			Code: attempt, DeviceName: "phone", DeviceModel: "iPhone17,1"}))
		if connect.CodeOf(err) != connect.CodeUnauthenticated {
			t.Fatalf("%s: %v", name, err)
		}
		wantReason(t, err, connect.CodeUnauthenticated, appv1.ErrorReason_ERROR_REASON_PAIRING_CODE_INVALID)
	}
	_, err := h.client.RedeemPairingCode(tctx(t), connect.NewRequest(&appv1.RedeemPairingCodeRequest{
		Code: code, DeviceName: "", DeviceModel: "iPhone17,1"}))
	if connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("empty device name: %v", err)
	}
	// Guessing is also rate limited per address.
	_, err = h.client.RedeemPairingCode(tctx(t), connect.NewRequest(&appv1.RedeemPairingCodeRequest{
		Code: "ABCD-EFGH-JKMP", DeviceName: "phone", DeviceModel: "iPhone17,1"}))
	if connect.CodeOf(err) != connect.CodeResourceExhausted {
		t.Fatalf("fifth attempt: %v", err)
	}
}

func TestRefreshRotatesTheTokenAndACopiedTokenEndsTheSession(t *testing.T) {
	h := newHarness(t)
	first := h.pair(t)
	refresh := func(token string) (*appv1.Session, error) {
		resp, err := h.client.RefreshSession(tctx(t), connect.NewRequest(&appv1.RefreshSessionRequest{RefreshToken: token}))
		if err != nil {
			return nil, err
		}
		return resp.Msg.GetSession(), nil
	}
	second, err := refresh(first.GetRefreshToken())
	if err != nil || second.GetRefreshToken() == first.GetRefreshToken() || second.GetSessionId() != first.GetSessionId() ||
		second.GetAccessToken() == first.GetAccessToken() {
		t.Fatalf("rotation: %v, %v", second, err)
	}
	// The app lost that response and retries at once: it gets new tokens.
	third, err := refresh(first.GetRefreshToken())
	if err != nil || third.GetRefreshToken() == second.GetRefreshToken() {
		t.Fatalf("retry within the grace period: %v, %v", third, err)
	}
	// The token it never received no longer works.
	if _, err := refresh(second.GetRefreshToken()); connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("dropped token: %v", err)
	}
	fourth, err := refresh(third.GetRefreshToken())
	if err != nil {
		t.Fatal(err)
	}

	// Later, someone presents the replaced token: it was copied.
	if _, err := db.Exec(tctx(t), `UPDATE sessions SET rotated_at = now() - interval '5 minutes' WHERE id = $1`,
		fourth.GetSessionId()); err != nil {
		t.Fatal(err)
	}
	_, err = refresh(third.GetRefreshToken())
	wantReason(t, err, connect.CodeUnauthenticated, appv1.ErrorReason_ERROR_REASON_SESSION_ENDED)
	// The whole session ended: the legitimate token and the access token too.
	_, err = refresh(fourth.GetRefreshToken())
	wantReason(t, err, connect.CodeUnauthenticated, appv1.ErrorReason_ERROR_REASON_SESSION_ENDED)
	_, err = h.client.ListTasks(tctx(t), authed(fourth.GetAccessToken(), &appv1.ListTasksRequest{}))
	wantReason(t, err, connect.CodeUnauthenticated, appv1.ErrorReason_ERROR_REASON_SESSION_ENDED)
	var reason string
	if err := db.QueryRow(tctx(t), `SELECT revoke_reason FROM sessions WHERE id = $1`, fourth.GetSessionId()).
		Scan(&reason); err != nil || reason != "refresh token reused" {
		t.Fatalf("revoke reason %q, %v", reason, err)
	}
}

func TestSignOutEndsTheSessionAtOnce(t *testing.T) {
	h := newHarness(t)
	s := h.pair(t)
	other := h.pair(t) // the same user's other phone stays signed in
	if _, err := h.client.SignOut(tctx(t), connect.NewRequest(&appv1.SignOutRequest{RefreshToken: s.GetRefreshToken()})); err != nil {
		t.Fatal(err)
	}
	_, err := h.client.ListTasks(tctx(t), authed(s.GetAccessToken(), &appv1.ListTasksRequest{}))
	wantReason(t, err, connect.CodeUnauthenticated, appv1.ErrorReason_ERROR_REASON_SESSION_ENDED)
	_, err = h.client.RefreshSession(tctx(t), connect.NewRequest(&appv1.RefreshSessionRequest{RefreshToken: s.GetRefreshToken()}))
	wantReason(t, err, connect.CodeUnauthenticated, appv1.ErrorReason_ERROR_REASON_SESSION_ENDED)
	// Idempotent, and quiet about unknown tokens.
	for _, token := range []string{s.GetRefreshToken(), "garbage", ""} {
		if _, err := h.client.SignOut(tctx(t), connect.NewRequest(&appv1.SignOutRequest{RefreshToken: token})); err != nil {
			t.Fatalf("sign out %q: %v", token, err)
		}
	}
	if _, err := h.client.ListTasks(tctx(t), authed(other.GetAccessToken(), &appv1.ListTasksRequest{})); err != nil {
		t.Fatalf("the other phone was signed out: %v", err)
	}
}

func TestOnlyAccessTokensOfLiveSessionsAreAccepted(t *testing.T) {
	h := newHarness(t)
	s := h.pair(t)
	sessionless, _ := usertoken.Issuer{Key: h.key, KeyID: "test-key", Issuer: tokenIssuer, Audience: api.AccessAudience}.
		Issue(h.user, h.tenant, time.Minute)
	foreign, _ := usertoken.Issuer{Key: h.key, KeyID: "test-key", Issuer: tokenIssuer, Audience: api.AccessAudience}.
		IssueForSession("someone-else", h.tenant, s.GetSessionId(), time.Minute)
	for name, token := range map[string]string{
		"voice token":         s.GetVoiceToken(),
		"no session":          sessionless,
		"refresh token":       s.GetRefreshToken(),
		"garbage":             "abc.def.ghi",
		"other user, my sid":  foreign,
		"empty bearer header": "",
	} {
		_, err := h.client.ListTasks(tctx(t), authed(token, &appv1.ListTasksRequest{}))
		if connect.CodeOf(err) != connect.CodeUnauthenticated {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := h.client.ListTasks(tctx(t), connect.NewRequest(&appv1.ListTasksRequest{})); connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("no header: %v", err)
	}
	if len(h.orch.calls()) != 0 {
		t.Fatal("the orchestrator was called for an unauthenticated request")
	}
}

func approvalTask(id, approval string, expires time.Time) *orchv1.Task {
	return &orchv1.Task{TaskId: id, Goal: "Clean the build folder", State: orchv1.TaskState_TASK_STATE_AWAITING_APPROVAL,
		PendingApproval: &orchv1.PendingApproval{ApprovalId: approval, DeviceName: "MacBook", Payload: []byte("payload-" + approval),
			ExpireTime: timestamppb.New(expires)}}
}

func TestTasksAndApprovalsActForTheSignedInUser(t *testing.T) {
	h := newHarness(t)
	s := h.pair(t)
	done := uuid.NewString()
	soon, later, stale := uuid.NewString(), uuid.NewString(), uuid.NewString()
	h.orch.tasks = []*orchv1.Task{
		{TaskId: done, Goal: "Book a table", State: orchv1.TaskState_TASK_STATE_SUCCEEDED, Result: "Booked for 21:00", Steps: 3},
		approvalTask(later, "appr-later", time.Now().Add(4*time.Minute)),
		approvalTask(soon, "appr-soon", time.Now().Add(time.Minute)),
		approvalTask(stale, "appr-stale", time.Now().Add(-time.Minute)),
	}

	tasks, err := h.client.ListTasks(tctx(t), authed(s.GetAccessToken(), &appv1.ListTasksRequest{Limit: 10}))
	if err != nil {
		t.Fatal(err)
	}
	got := tasks.Msg.GetTasks()
	if len(got) != 4 || got[0].GetState() != appv1.TaskState_TASK_STATE_SUCCEEDED || got[0].GetResult() != "Booked for 21:00" ||
		got[1].GetPendingApproval().GetApprovalId() != "appr-later" || got[1].GetPendingApproval().GetTaskGoal() != "Clean the build folder" {
		t.Fatalf("tasks = %v", got)
	}

	approvals, err := h.client.ListApprovals(tctx(t), authed(s.GetAccessToken(), &appv1.ListApprovalsRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, a := range approvals.Msg.GetApprovals() {
		ids = append(ids, a.GetApprovalId())
	}
	if !slices.Equal(ids, []string{"appr-soon", "appr-later"}) ||
		string(approvals.Msg.GetApprovals()[0].GetPayload()) != "payload-appr-soon" {
		t.Fatalf("approvals = %v (expired ones must be hidden, soonest first)", ids)
	}

	signature := make([]byte, 64)
	signature[0] = 7
	out, err := h.client.SubmitApproval(tctx(t), authed(s.GetAccessToken(), &appv1.SubmitApprovalRequest{
		ApprovalId: "appr-soon", ApproverId: "kostas-iphone", Signature: signature}))
	if err != nil || out.Msg.GetOutput() != `{"exit_code":0}` {
		t.Fatalf("submit = %v, %v", out, err)
	}
	sent := h.orch.approvals[0]
	if sent.GetApproverId() != "kostas-iphone" || sent.GetSignature()[0] != 7 || sent.GetTenantId() != h.tenant ||
		sent.GetUserId() != h.user {
		t.Fatalf("sent = %v", sent)
	}
	for name, bad := range map[string]*appv1.SubmitApprovalRequest{
		"short signature": {ApprovalId: "a", ApproverId: "phone", Signature: make([]byte, 63)},
		"bad approver":    {ApprovalId: "a", ApproverId: "my phone", Signature: signature},
		"no approval":     {ApprovalId: "", ApproverId: "phone", Signature: signature},
	} {
		if _, err := h.client.SubmitApproval(tctx(t), authed(s.GetAccessToken(), bad)); connect.CodeOf(err) != connect.CodeInvalidArgument {
			t.Errorf("%s: %v", name, err)
		}
	}
	for code, reason := range map[codes.Code]appv1.ErrorReason{
		codes.NotFound:         appv1.ErrorReason_ERROR_REASON_APPROVAL_NOT_FOUND,
		codes.PermissionDenied: appv1.ErrorReason_ERROR_REASON_APPROVAL_REJECTED,
	} {
		h.orch.mu.Lock()
		h.orch.submitErr = status.Error(code, "no")
		h.orch.mu.Unlock()
		_, err := h.client.SubmitApproval(tctx(t), authed(s.GetAccessToken(), &appv1.SubmitApprovalRequest{
			ApprovalId: "appr-soon", ApproverId: "kostas-iphone", Signature: signature}))
		wantReason(t, err, connect.Code(code), reason)
	}
	h.orch.mu.Lock()
	h.orch.submitErr = status.Error(codes.Unavailable, "down")
	h.orch.mu.Unlock()
	_, err = h.client.SubmitApproval(tctx(t), authed(s.GetAccessToken(), &appv1.SubmitApprovalRequest{
		ApprovalId: "appr-soon", ApproverId: "kostas-iphone", Signature: signature}))
	if connect.CodeOf(err) != connect.CodeUnavailable || strings.Contains(err.Error(), "down") {
		t.Fatalf("orchestrator down: %v", err)
	}

	cancelled, err := h.client.CancelTask(tctx(t), authed(s.GetAccessToken(), &appv1.CancelTaskRequest{TaskId: soon}))
	if err != nil || cancelled.Msg.GetTask().GetState() != appv1.TaskState_TASK_STATE_CANCELLED ||
		cancelled.Msg.GetTask().GetPendingApproval() != nil {
		t.Fatalf("cancel = %v, %v", cancelled, err)
	}
	_, err = h.client.CancelTask(tctx(t), authed(s.GetAccessToken(), &appv1.CancelTaskRequest{TaskId: uuid.NewString()}))
	wantReason(t, err, connect.CodeNotFound, appv1.ErrorReason_ERROR_REASON_TASK_NOT_FOUND)

	for _, call := range h.orch.calls() {
		if call != h.tenant+"/"+h.user {
			t.Fatalf("a call was made for %s", call)
		}
	}
	h.orch.mu.Lock()
	defer h.orch.mu.Unlock()
	if len(h.orch.requestID) == 0 || h.orch.requestID[0] == "" {
		t.Fatal("request ids are not passed to the orchestrator")
	}
}

func TestAdminListsAndRevokesSessions(t *testing.T) {
	h := newHarness(t)
	s := h.pair(t)
	list, err := h.admin.ListSessions(tctx(t), &appv1.ListSessionsRequest{TenantId: h.tenant, UserId: h.user})
	if err != nil || len(list.GetSessions()) != 1 || list.GetSessions()[0].GetDeviceName() != "Κώστα's iPhone" ||
		list.GetSessions()[0].GetSessionId() != s.GetSessionId() {
		t.Fatalf("sessions = %v, %v", list, err)
	}
	// Another user's request changes nothing.
	if _, err := h.admin.RevokeSession(tctx(t), &appv1.RevokeSessionRequest{TenantId: h.tenant, UserId: "someone-else",
		SessionId: s.GetSessionId()}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.client.ListTasks(tctx(t), authed(s.GetAccessToken(), &appv1.ListTasksRequest{})); err != nil {
		t.Fatalf("revoked by someone else: %v", err)
	}
	if _, err := h.admin.RevokeSession(tctx(t), &appv1.RevokeSessionRequest{TenantId: h.tenant, UserId: h.user,
		SessionId: s.GetSessionId()}); err != nil {
		t.Fatal(err)
	}
	_, err = h.client.ListTasks(tctx(t), authed(s.GetAccessToken(), &appv1.ListTasksRequest{}))
	wantReason(t, err, connect.CodeUnauthenticated, appv1.ErrorReason_ERROR_REASON_SESSION_ENDED)
	if list, _ := h.admin.ListSessions(tctx(t), &appv1.ListSessionsRequest{TenantId: h.tenant, UserId: h.user}); len(list.GetSessions()) != 0 {
		t.Fatalf("revoked session still listed: %v", list)
	}
	for _, bad := range []*appv1.CreatePairingCodeRequest{{TenantId: "nope", UserId: "u"}, {TenantId: h.tenant, UserId: ""},
		{TenantId: h.tenant, UserId: "has space"}} {
		if _, err := h.admin.CreatePairingCode(context.Background(), bad); status.Code(err) != codes.InvalidArgument {
			t.Errorf("%v: %v", bad, err)
		}
	}
}

func TestPushTokensFollowTheirPhonesSession(t *testing.T) {
	h := newHarness(t)
	first := h.pair(t)
	token := strings.Repeat("ab", 32)
	register := func(s *appv1.Session, device string, env appv1.PushEnvironment) error {
		_, err := h.client.RegisterPushToken(tctx(t), authed(s.GetAccessToken(),
			&appv1.RegisterPushTokenRequest{DeviceToken: device, Environment: env}))
		return err
	}
	tokens := func() []string {
		list, err := h.store.PushTokens(tctx(t), uuid.MustParse(h.tenant), h.user)
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, p := range list {
			out = append(out, p.SessionID.String()+"/"+p.DeviceToken+"/"+p.Environment)
		}
		return out
	}
	if err := register(first, strings.ToUpper(token), appv1.PushEnvironment_PUSH_ENVIRONMENT_SANDBOX); err != nil {
		t.Fatal(err)
	}
	if got := tokens(); !slices.Equal(got, []string{first.GetSessionId() + "/" + token + "/sandbox"}) {
		t.Fatalf("tokens %v", got)
	}

	// The same phone paired again: its notifications follow the new session.
	second := h.pair(t)
	if err := register(second, token, appv1.PushEnvironment_PUSH_ENVIRONMENT_PRODUCTION); err != nil {
		t.Fatal(err)
	}
	if got := tokens(); !slices.Equal(got, []string{second.GetSessionId() + "/" + token + "/production"}) {
		t.Fatalf("tokens after re-pairing %v", got)
	}

	for name, bad := range map[string]*appv1.RegisterPushTokenRequest{
		"not hex":        {DeviceToken: strings.Repeat("zz", 32), Environment: appv1.PushEnvironment_PUSH_ENVIRONMENT_SANDBOX},
		"too short":      {DeviceToken: "abcd", Environment: appv1.PushEnvironment_PUSH_ENVIRONMENT_SANDBOX},
		"no environment": {DeviceToken: token},
	} {
		if _, err := h.client.RegisterPushToken(tctx(t), authed(second.GetAccessToken(), bad)); connect.CodeOf(err) != connect.CodeInvalidArgument {
			t.Errorf("%s: %v", name, err)
		}
	}

	// A revoked session's phone gets nothing.
	if _, err := h.admin.RevokeSession(tctx(t), &appv1.RevokeSessionRequest{TenantId: h.tenant, UserId: h.user,
		SessionId: second.GetSessionId()}); err != nil {
		t.Fatal(err)
	}
	if got := tokens(); len(got) != 0 {
		t.Fatalf("a revoked session still gets pushes: %v", got)
	}

	// Turning notifications off removes the token.
	third := h.pair(t)
	if err := register(third, token, appv1.PushEnvironment_PUSH_ENVIRONMENT_SANDBOX); err != nil {
		t.Fatal(err)
	}
	if err := register(third, "", appv1.PushEnvironment_PUSH_ENVIRONMENT_UNSPECIFIED); err != nil {
		t.Fatal(err)
	}
	if got := tokens(); len(got) != 0 {
		t.Fatalf("tokens after turning off %v", got)
	}
	// Without a session, nobody registers anything.
	if _, err := h.client.RegisterPushToken(tctx(t), connect.NewRequest(&appv1.RegisterPushTokenRequest{DeviceToken: token,
		Environment: appv1.PushEnvironment_PUSH_ENVIRONMENT_SANDBOX})); connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("anonymous register: %v", err)
	}
}
