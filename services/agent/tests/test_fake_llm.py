"""The sidecar against the development fake Responses API, over real HTTP."""

from __future__ import annotations

import shutil
import tempfile
import threading
from collections.abc import AsyncIterator
from pathlib import Path

import grpc
import httpx2
import pytest
import pytest_asyncio
from jarvis.agent.v1 import agent_pb2 as pb
from jarvis.agent.v1 import agent_pb2_grpc as pb_grpc
from jarvis.common.v1 import provider_pb2

from jarvis_agent.config import Config
from jarvis_agent.fake_llm import _Server
from jarvis_agent.main import start
from jarvis_agent.service import Metrics

KEY = "sk-dev-fake-llm-key"


@pytest_asyncio.fixture
async def stub() -> AsyncIterator[pb_grpc.AgentWorkerServiceAsyncStub]:
    fake = _Server(("127.0.0.1", 0), KEY, "linear__search_issues", '{"query":"login"}')
    thread = threading.Thread(target=fake.serve_forever, daemon=True)
    thread.start()
    host, port = fake.server_address[:2]
    directory = Path(tempfile.mkdtemp(prefix="jarvis-agent-", dir="/tmp"))
    cfg = Config(
        socket=directory / "agent.sock",
        admin_addr="127.0.0.1:0",
        openai_base_url=f"http://{host!s}:{port}/v1",
        xai_base_url=f"http://{host!s}:{port}/v1",
        request_timeout=5,
        max_retries=0,
        max_concurrency=4,
        log_format="json",
        log_level="info",
    )
    async with httpx2.AsyncClient() as http:
        server = await start(cfg, http, Metrics())
        channel = grpc.aio.insecure_channel(f"unix:{cfg.socket}")
        yield pb_grpc.AgentWorkerServiceStub(channel)
        await channel.close()
        await server.stop(None)
    fake.shutdown()
    fake.server_close()
    shutil.rmtree(directory, ignore_errors=True)


def model(key: str = KEY) -> pb.Model:
    return pb.Model(provider=provider_pb2.PROVIDER_XAI, model="grok-4.6", api_key=key.encode())


TOOLS = [pb.ToolSpec(name="linear__search_issues", description="Search issues.", parameters_json='{"type":"object"}')]


async def test_a_task_calls_the_tool_then_summarizes(stub: pb_grpc.AgentWorkerServiceAsyncStub) -> None:
    first = await stub.Decide(
        pb.DecideRequest(model=model(), items=[pb.Item(user_text="Find the login bug")], tools=TOOLS)
    )
    assert [c.name for c in first.tool_calls] == ["linear__search_issues"]
    assert first.tool_calls[0].arguments_json == '{"query":"login"}'
    items = [
        pb.Item(user_text="Find the login bug"),
        pb.Item(model_step=first.step),
        pb.Item(tool_result=pb.ToolResult(call_id=first.tool_calls[0].call_id, output='{"issues":["JAR-7"]}')),
    ]
    second = await stub.Decide(pb.DecideRequest(model=model(), items=items, tools=TOOLS))
    assert not second.tool_calls and "JAR-7" in second.text


async def test_memory_extraction_keeps_what_the_user_said(stub: pb_grpc.AgentWorkerServiceAsyncStub) -> None:
    turns = [
        pb.TranscriptTurn(speaker="user", text="Το αγαπημένο μου χρώμα είναι το πράσινο."),
        pb.TranscriptTurn(speaker="assistant", text="Το σημείωσα."),
    ]
    resp = await stub.ExtractKnowledge(pb.ExtractKnowledgeRequest(model=model(), turns=turns, locale="el-GR"))
    assert [e.name for e in resp.entities] == ["User"]
    assert [p.text for p in resp.passages] == ["The user said: Το αγαπημένο μου χρώμα είναι το πράσινο."]


async def test_a_wrong_key_is_rejected(stub: pb_grpc.AgentWorkerServiceAsyncStub) -> None:
    with pytest.raises(grpc.aio.AioRpcError) as failure:
        await stub.Decide(pb.DecideRequest(model=model("sk-someone-else"), items=[pb.Item(user_text="hi")]))
    assert failure.value.code() == grpc.StatusCode.UNAUTHENTICATED
