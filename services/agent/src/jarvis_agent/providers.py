"""OpenAI-compatible providers (OpenAI and xAI both implement the Responses API).

A client is made per call with the tenant's key; the HTTP connection pool is
shared. Keys live only in the request and the client made for it.
"""

from __future__ import annotations

from dataclasses import dataclass

import grpc
import httpx2
import openai
from jarvis.agent.v1 import agent_pb2 as pb
from jarvis.common.v1 import provider_pb2


class ProviderError(Exception):
    """A provider failure, mapped to a gRPC status and an ErrorReason."""

    def __init__(self, code: grpc.StatusCode, reason: pb.ErrorReason.ValueType, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.reason = reason


class InvalidRequest(ValueError):
    """The request is malformed."""


@dataclass(frozen=True, slots=True)
class Providers:
    openai_base_url: str
    xai_base_url: str
    timeout: float
    max_retries: int
    http: httpx2.AsyncClient

    def client(self, model: pb.Model) -> openai.AsyncOpenAI:
        match model.provider:
            case provider_pb2.PROVIDER_OPENAI:
                base_url = self.openai_base_url
            case provider_pb2.PROVIDER_XAI:
                base_url = self.xai_base_url
            case _:
                raise InvalidRequest("provider must be OpenAI or xAI")
        if not model.model or len(model.model) > 128:
            raise InvalidRequest("model is required")
        if not model.api_key:
            raise InvalidRequest("api_key is required")
        return openai.AsyncOpenAI(
            api_key=model.api_key.decode(),
            base_url=base_url,
            timeout=self.timeout,
            max_retries=self.max_retries,
            http_client=self.http,
        )


def classify(error: openai.OpenAIError) -> ProviderError:
    """Maps SDK errors; provider messages are not passed on (they may echo input)."""
    match error:
        case openai.AuthenticationError() | openai.PermissionDeniedError():
            return ProviderError(
                grpc.StatusCode.UNAUTHENTICATED,
                pb.ERROR_REASON_PROVIDER_REJECTED_KEY,
                "the provider rejected the API key",
            )
        case openai.RateLimitError():
            return ProviderError(
                grpc.StatusCode.RESOURCE_EXHAUSTED,
                pb.ERROR_REASON_PROVIDER_RATE_LIMITED,
                "the provider's rate limit or quota was reached",
            )
        case openai.BadRequestError() | openai.NotFoundError() | openai.UnprocessableEntityError():
            status = getattr(error, "status_code", 400)
            return ProviderError(
                grpc.StatusCode.FAILED_PRECONDITION,
                pb.ERROR_REASON_UNSPECIFIED,
                f"the provider refused the request (HTTP {status}); check the model name",
            )
        case _:
            return ProviderError(
                grpc.StatusCode.UNAVAILABLE, pb.ERROR_REASON_PROVIDER_UNAVAILABLE, "the provider could not be reached"
            )
