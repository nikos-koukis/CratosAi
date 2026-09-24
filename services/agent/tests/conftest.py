"""The sidecar on a real Unix socket, with a scripted fake Responses API."""

from __future__ import annotations

import json
import os
import shutil
import tempfile
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import grpc
import httpx2
import pytest_asyncio
from jarvis.agent.v1 import agent_pb2 as pb
from jarvis.agent.v1 import agent_pb2_grpc as pb_grpc
from jarvis.common.v1 import provider_pb2

from jarvis_agent.config import Config
from jarvis_agent.main import start
from jarvis_agent.service import Metrics

os.environ.setdefault("GRPC_VERBOSITY", "ERROR")

API_KEY = b"sk-test-secret-key-0123456789"


def response_json(output: list[dict[str, Any]], *, model: str = "gpt-6-luna") -> dict[str, Any]:
    return {
        "id": "resp_1",
        "object": "response",
        "created_at": 1790000000,
        "status": "completed",
        "model": model,
        "output": output,
        "parallel_tool_calls": True,
        "tool_choice": "auto",
        "tools": [],
        "usage": {
            "input_tokens": 12,
            "output_tokens": 7,
            "total_tokens": 19,
            "input_tokens_details": {"cached_tokens": 0},
            "output_tokens_details": {"reasoning_tokens": 0},
        },
    }


def text_output(text: str) -> dict[str, Any]:
    return {
        "type": "message",
        "id": "msg_1",
        "status": "completed",
        "role": "assistant",
        "content": [{"type": "output_text", "text": text, "annotations": []}],
    }


def call_output(call_id: str, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    return {
        "type": "function_call",
        "id": f"fc_{call_id}",
        "call_id": call_id,
        "name": name,
        "arguments": json.dumps(arguments),
        "status": "completed",
    }


@dataclass
class FakeProvider:
    """Answers POST /v1/responses from a script; records every request."""

    replies: list[tuple[int, dict[str, Any]]] = field(default_factory=list)
    requests: list[httpx2.Request] = field(default_factory=list)

    def reply(self, output: list[dict[str, Any]]) -> None:
        self.replies.append((200, response_json(output)))

    def fail(self, status: int, body: dict[str, Any] | None = None) -> None:
        self.replies.append((status, body or {"error": {"message": "echo of the secret prompt", "type": "x"}}))

    def body(self, index: int = -1) -> dict[str, Any]:
        return dict(json.loads(self.requests[index].content))

    def handle(self, request: httpx2.Request) -> httpx2.Response:
        self.requests.append(request)
        status, body = self.replies.pop(0) if self.replies else (500, {"error": {"message": "no scripted reply"}})
        return httpx2.Response(status, json=body)


@dataclass
class Sidecar:
    stub: pb_grpc.AgentWorkerServiceAsyncStub
    provider: FakeProvider
    socket: Path
    metrics: Metrics


@pytest_asyncio.fixture
async def sidecar() -> AsyncIterator[Sidecar]:
    provider = FakeProvider()
    # Unix socket paths are limited to ~104 bytes; pytest's tmp_path is longer on macOS.
    directory = Path(tempfile.mkdtemp(prefix="jarvis-agent-", dir="/tmp"))
    cfg = Config(
        socket=directory / "run" / "agent.sock",
        admin_addr="127.0.0.1:0",
        openai_base_url="http://openai.test/v1",
        xai_base_url="http://xai.test/v1",
        request_timeout=5,
        max_retries=0,
        max_concurrency=8,
        log_format="json",
        log_level="info",
    )
    metrics = Metrics()
    async with httpx2.AsyncClient(transport=httpx2.MockTransport(provider.handle)) as http:
        server = await start(cfg, http, metrics)
        channel = grpc.aio.insecure_channel(f"unix:{cfg.socket}")
        yield Sidecar(pb_grpc.AgentWorkerServiceStub(channel), provider, cfg.socket, metrics)
        await channel.close()
        await server.stop(None)
    shutil.rmtree(directory, ignore_errors=True)


def model(
    provider: provider_pb2.Provider.ValueType = provider_pb2.PROVIDER_OPENAI, name: str = "gpt-6-luna"
) -> pb.Model:
    return pb.Model(provider=provider, model=name, api_key=API_KEY)
