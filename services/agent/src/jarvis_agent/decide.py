"""Decide: one agent step through the Responses API.

Requests are stateless (`store=false`): the provider keeps nothing, and the
history is replayed from the orchestrator's items every time. A model step is
replayed as the message and function-call items the model produced, without
provider item ids (which refer to server-side storage we do not use).
"""

from __future__ import annotations

import json
import re
from typing import Any

import openai
from jarvis.agent.v1 import agent_pb2 as pb

from jarvis_agent.providers import InvalidRequest, Providers, classify

MAX_ITEMS = 400
MAX_TOOLS = 128
DEFAULT_OUTPUT_TOKENS = 2000
_TOOL_NAME = re.compile(r"^[a-zA-Z0-9_-]{1,64}$")
_REPLAYED_TYPES = {"message", "function_call"}


def _tool(spec: pb.ToolSpec) -> dict[str, Any]:
    if not _TOOL_NAME.match(spec.name):
        raise InvalidRequest(f"tool name {spec.name[:70]!r} must match [a-zA-Z0-9_-]{{1,64}}")
    try:
        parameters = json.loads(spec.parameters_json or '{"type": "object"}')
    except json.JSONDecodeError as e:
        raise InvalidRequest(f"tool {spec.name}: parameters_json is not JSON") from e
    if not isinstance(parameters, dict) or parameters.get("type") != "object":
        raise InvalidRequest(f"tool {spec.name}: parameters must be an object schema")
    return {
        "type": "function",
        "name": spec.name,
        "description": spec.description[:4000],
        "parameters": parameters,
        "strict": False,
    }


def _replay(step: pb.ModelStep) -> list[dict[str, Any]]:
    try:
        items = json.loads(step.provider_items or b"[]")
    except json.JSONDecodeError as e:
        raise InvalidRequest("model_step.provider_items is not JSON") from e
    if not isinstance(items, list) or not all(isinstance(i, dict) and i.get("type") in _REPLAYED_TYPES for i in items):
        raise InvalidRequest("model_step.provider_items must be a list of message and function_call items")
    return items


def build_input(items: list[pb.Item]) -> list[dict[str, Any]]:
    if not items:
        raise InvalidRequest("items must not be empty")
    if len(items) > MAX_ITEMS:
        raise InvalidRequest(f"at most {MAX_ITEMS} items")
    out: list[dict[str, Any]] = []
    for item in items:
        match item.WhichOneof("item"):
            case "user_text":
                out.append({"role": "user", "content": item.user_text})
            case "model_step":
                out.extend(_replay(item.model_step))
            case "tool_result":
                if not item.tool_result.call_id:
                    raise InvalidRequest("tool_result.call_id is required")
                out.append(
                    {
                        "type": "function_call_output",
                        "call_id": item.tool_result.call_id,
                        "output": item.tool_result.output,
                    }
                )
            case _:
                raise InvalidRequest("an item is empty")
    return out


def _clean(item: dict[str, Any]) -> dict[str, Any] | None:
    """What of an output item to replay next time."""
    match item.get("type"):
        case "function_call":
            return {
                "type": "function_call",
                "call_id": item["call_id"],
                "name": item["name"],
                "arguments": item.get("arguments", "{}"),
            }
        case "message":
            texts = [c.get("text", "") for c in item.get("content", []) if c.get("type") == "output_text"]
            return {
                "type": "message",
                "role": "assistant",
                "content": [{"type": "output_text", "text": t} for t in texts],
            }
        case _:
            return None  # reasoning without encrypted content cannot be replayed statelessly


async def decide(providers: Providers, request: pb.DecideRequest) -> pb.DecideResponse:
    client = providers.client(request.model)
    if len(request.tools) > MAX_TOOLS:
        raise InvalidRequest(f"at most {MAX_TOOLS} tools")
    tools = [_tool(t) for t in request.tools]
    max_tokens = request.max_output_tokens or DEFAULT_OUTPUT_TOKENS
    if not 1 <= max_tokens <= 32000:
        raise InvalidRequest("max_output_tokens must be between 1 and 32000")
    kwargs: dict[str, Any] = {}
    if tools:
        kwargs["tools"] = tools
    try:
        response = await client.responses.create(
            model=request.model.model,
            instructions=request.instructions or openai.omit,
            input=build_input(list(request.items)),  # type: ignore[arg-type]
            store=False,
            max_output_tokens=max_tokens,
            **kwargs,
        )
    except openai.OpenAIError as e:
        raise classify(e) from e

    output = [item.model_dump(mode="json", exclude_none=True) for item in response.output]
    replay = [c for c in (_clean(i) for i in output) if c is not None]
    calls = [
        pb.ToolCall(call_id=i["call_id"], name=i["name"], arguments_json=i.get("arguments", "{}"))
        for i in output
        if i.get("type") == "function_call"
    ]
    usage = response.usage
    return pb.DecideResponse(
        text=response.output_text,
        tool_calls=calls,
        step=pb.ModelStep(provider_items=json.dumps(replay, ensure_ascii=False).encode()),
        usage=pb.Usage(
            input_tokens=usage.input_tokens if usage else 0, output_tokens=usage.output_tokens if usage else 0
        ),
    )
