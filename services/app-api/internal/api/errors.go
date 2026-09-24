package api

import (
	"context"
	"errors"
	"log/slog"

	"connectrpc.com/connect"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	appv1 "jarvis.internal/gen/go/jarvis/app/v1"
)

// ErrorDomain is the google.rpc.ErrorInfo domain of the app API's errors.
const ErrorDomain = "app.jarvis"

// reasoned is an error with an ErrorInfo detail the app can act on.
func reasoned(code connect.Code, reason appv1.ErrorReason, message string) *connect.Error {
	err := connect.NewError(code, errors.New(message))
	if detail, detailErr := connect.NewErrorDetail(&errdetails.ErrorInfo{Reason: reason.String(), Domain: ErrorDomain}); detailErr == nil {
		err.AddDetail(detail)
	}
	return err
}

func invalid(message string) *connect.Error {
	return connect.NewError(connect.CodeInvalidArgument, errors.New(message))
}

func unauthenticated() *connect.Error {
	return connect.NewError(connect.CodeUnauthenticated, errors.New("a valid access token is required"))
}

func sessionEnded() *connect.Error {
	return reasoned(connect.CodeUnauthenticated, appv1.ErrorReason_ERROR_REASON_SESSION_ENDED,
		"the session has ended; pair the app again")
}

// internal logs the cause and returns an opaque error with the request id.
func internal(ctx context.Context, log *slog.Logger, what string, err error) *connect.Error {
	id := requestID(ctx)
	log.Error(what+" failed", "request_id", id, "error", err)
	return connect.NewError(connect.CodeInternal, errors.New("internal error (request "+id+")"))
}

// fromOrchestrator maps an orchestrator failure that has no specific meaning
// for the caller.
func fromOrchestrator(ctx context.Context, log *slog.Logger, what string, err error) *connect.Error {
	switch status.Code(err) {
	case codes.Unavailable, codes.DeadlineExceeded:
		log.Warn(what+": orchestrator unavailable", "request_id", requestID(ctx), "error", err)
		return connect.NewError(connect.CodeUnavailable, errors.New("the service is temporarily unavailable; try again"))
	case codes.Canceled:
		return connect.NewError(connect.CodeCanceled, errors.New("cancelled"))
	}
	return internal(ctx, log, what, err)
}
