"""jarvis.agent.v1.AgentWorkerService, plus request logging and metrics."""

from __future__ import annotations

import logging
import time
from collections.abc import Awaitable, Callable
from typing import Any, NoReturn

import grpc
from google.protobuf import any_pb2
from google.rpc import code_pb2, error_details_pb2, status_pb2
from grpc_status import rpc_status
from jarvis.agent.v1 import agent_pb2 as pb
from jarvis.agent.v1 import agent_pb2_grpc as pb_grpc
from jarvis.common.v1 import provider_pb2
from prometheus_client import CollectorRegistry, Counter, Histogram

from jarvis_agent.decide import decide
from jarvis_agent.extract import extract_knowledge
from jarvis_agent.providers import InvalidRequest, ProviderError, Providers

log = logging.getLogger(__name__)

ERROR_DOMAIN = "agent.jarvis"
type Context = grpc.aio.ServicerContext[Any, Any]


class Metrics:
    def __init__(self) -> None:
        self.registry = CollectorRegistry()
        self.calls = Counter(
            "agent_calls_total",
            "Calls by method, provider and outcome.",
            ["method", "provider", "outcome"],
            registry=self.registry,
        )
        self.seconds = Histogram(
            "agent_call_seconds",
            "Call duration by method and provider.",
            ["method", "provider"],
            buckets=(0.25, 0.5, 1, 2, 4, 8, 15, 30, 60, 120),
            registry=self.registry,
        )
        self.tokens = Counter(
            "agent_tokens_total",
            "Provider tokens by provider and direction.",
            ["provider", "direction"],
            registry=self.registry,
        )


async def _abort(
    context: Context,
    code: grpc.StatusCode,
    message: str,
    reason: pb.ErrorReason.ValueType = pb.ERROR_REASON_UNSPECIFIED,
) -> NoReturn:
    detail = any_pb2.Any()
    detail.Pack(error_details_pb2.ErrorInfo(domain=ERROR_DOMAIN, reason=pb.ErrorReason.Name(reason)))
    status = status_pb2.Status(code=getattr(code_pb2, code.name), message=message, details=[detail] if reason else [])
    await context.abort_with_status(rpc_status.to_status(status))


def _provider(model: pb.Model) -> str:
    names = {provider_pb2.PROVIDER_OPENAI: "openai", provider_pb2.PROVIDER_XAI: "xai"}
    return names.get(model.provider, "other")


class AgentWorker(pb_grpc.AgentWorkerServiceServicer):
    def __init__(self, providers: Providers, metrics: Metrics) -> None:
        self._providers = providers
        self._metrics = metrics

    async def _run[Resp](
        self,
        method: str,
        model: pb.Model,
        context: Context,
        call: Callable[[], Awaitable[Resp]],
        usage: Callable[[Resp], pb.Usage],
    ) -> Resp:
        provider = _provider(model)
        started = time.perf_counter()
        outcome = "ok"
        request_id = dict(context.invocation_metadata() or ()).get("x-request-id", "")
        try:
            result = await call()
        except InvalidRequest as e:
            outcome = "invalid"
            await _abort(context, grpc.StatusCode.INVALID_ARGUMENT, str(e))
        except ProviderError as e:
            outcome = pb.ErrorReason.Name(e.reason).removeprefix("ERROR_REASON_").lower()
            await _abort(context, e.code, str(e), e.reason)
        except Exception:
            outcome = "internal"
            log.exception("unhandled error", extra={"method": method, "request_id": request_id})
            await _abort(context, grpc.StatusCode.INTERNAL, "internal error")
        else:
            used = usage(result)
            self._metrics.tokens.labels(provider, "input").inc(used.input_tokens)
            self._metrics.tokens.labels(provider, "output").inc(used.output_tokens)
            return result
        finally:
            elapsed = time.perf_counter() - started
            self._metrics.calls.labels(method, provider, outcome).inc()
            self._metrics.seconds.labels(method, provider).observe(elapsed)
            # Never logged: keys, prompts, transcripts, outputs.
            log.info(
                "call",
                extra={
                    "method": method,
                    "provider": provider,
                    "model": model.model,
                    "outcome": outcome,
                    "duration_ms": round(elapsed * 1000, 1),
                    "request_id": request_id,
                },
            )

    async def Decide(self, request: pb.DecideRequest, context: Context) -> pb.DecideResponse:
        return await self._run(
            "Decide", request.model, context, lambda: decide(self._providers, request), lambda r: r.usage
        )

    async def ExtractKnowledge(
        self, request: pb.ExtractKnowledgeRequest, context: Context
    ) -> pb.ExtractKnowledgeResponse:
        return await self._run(
            "ExtractKnowledge",
            request.model,
            context,
            lambda: extract_knowledge(self._providers, request),
            lambda r: r.usage,
        )
