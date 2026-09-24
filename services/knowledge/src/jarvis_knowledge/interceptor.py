"""Every RPC: request id, caller authentication and authorization, error
handling, a log line and metrics."""

from __future__ import annotations

import contextvars
import logging
import re
import time
import uuid
from collections.abc import Awaitable, Callable
from typing import Any, NoReturn, cast

import grpc
from google.protobuf import any_pb2
from google.rpc import code_pb2, error_details_pb2, status_pb2
from grpc_status import rpc_status

from jarvis_knowledge.authz import Policy, peer_principal
from jarvis_knowledge.metrics import Metrics

log = logging.getLogger(__name__)

ERROR_DOMAIN = "knowledge.jarvis"

request_id: contextvars.ContextVar[str] = contextvars.ContextVar("request_id", default="")

_REQUEST_ID = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")


async def abort(
    context: grpc.aio.ServicerContext[Any, Any], code: grpc.StatusCode, message: str, reason: str | None = None
) -> NoReturn:
    """Ends the RPC with a status (and an ErrorInfo detail when a reason is given)."""
    if reason is None:
        await context.abort(code, message)
    detail = any_pb2.Any()
    detail.Pack(error_details_pb2.ErrorInfo(domain=ERROR_DOMAIN, reason=reason))
    status = status_pb2.Status(code=getattr(code_pb2, code.name), message=message, details=[detail])
    await context.abort_with_status(rpc_status.to_status(status))


class Interceptor(grpc.aio.ServerInterceptor):
    """Authorizes methods of `service` by policy; other services (health,
    reflection) only need the verified client certificate TLS already demands."""

    def __init__(self, service: str, policy: Policy, metrics: Metrics) -> None:
        self._prefix = f"/{service}/"
        self._policy = policy
        self._metrics = metrics

    async def intercept_service(
        self,
        continuation: Callable[[grpc.HandlerCallDetails], Awaitable[grpc.RpcMethodHandler[Any, Any] | None]],
        details: grpc.HandlerCallDetails,
    ) -> grpc.RpcMethodHandler[Any, Any] | None:
        handler = await continuation(details)
        if handler is None or handler.unary_unary is None or not details.method.startswith(self._prefix):
            return handler
        method = details.method.removeprefix(self._prefix)
        inner = handler.unary_unary

        async def behavior(request: Any, context: grpc.aio.ServicerContext[Any, Any]) -> Any:
            started = time.perf_counter()
            metadata = dict(context.invocation_metadata() or ())
            incoming = metadata.get("x-request-id")
            rid = incoming if isinstance(incoming, str) and _REQUEST_ID.match(incoming) else str(uuid.uuid4())
            token = request_id.set(rid)
            principal = peer_principal(context.auth_context())
            try:
                await context.send_initial_metadata((("x-request-id", rid),))
                if principal is None:
                    await abort(
                        context,
                        grpc.StatusCode.UNAUTHENTICATED,
                        "caller identity could not be established from the client certificate",
                    )
                if not self._policy.allowed(principal or "", method):
                    await abort(context, grpc.StatusCode.PERMISSION_DENIED, "caller is not allowed to call this method")
                return await cast(Callable[[Any, Any], Awaitable[Any]], inner)(request, context)
            except grpc.aio.AbortError:
                raise
            except Exception:
                log.exception("unhandled error in RPC handler", extra={"method": method, "request_id": rid})
                await context.abort(grpc.StatusCode.INTERNAL, f"internal error (request {rid})")
            finally:
                code = cast(grpc.StatusCode | None, context.code()) or grpc.StatusCode.OK
                code_name = code.name if isinstance(code, grpc.StatusCode) else str(code)
                elapsed = time.perf_counter() - started
                self._metrics.rpcs.labels(method, code_name).inc()
                self._metrics.rpc_seconds.labels(method).observe(elapsed)
                level = logging.ERROR if code_name in {"INTERNAL", "UNKNOWN", "DATA_LOSS"} else logging.INFO
                log.log(
                    level,
                    "rpc",
                    extra={
                        "method": method,
                        "principal": principal,
                        "code": code_name,
                        "duration_ms": round(elapsed * 1000, 2),
                        "request_id": rid,
                    },
                )
                request_id.reset(token)

        return grpc.unary_unary_rpc_method_handler(
            behavior,
            request_deserializer=handler.request_deserializer,
            response_serializer=handler.response_serializer,
        )
