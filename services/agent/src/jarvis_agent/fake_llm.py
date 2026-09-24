"""A local stand-in for the OpenAI / xAI Responses API, for development.

Point AGENT_OPENAI_BASE_URL (or AGENT_XAI_BASE_URL) at it to run background
tasks and memory extraction end to end without spending API credits:

    jarvis-fake-llm --key sk-dev-... [--tool NAME --tool-args JSON] [--delay SECONDS]

- Tasks: the first decision calls --tool (when the task offers it), the next
  one answers with a summary of the tool's result. Without --tool it answers
  at once.
- Memory extraction: every user line of the transcript becomes a passage
  about the User.
- --delay makes every task decision take that long, e.g. so a task finishes
  after the conversation that started it has ended.

It accepts only requests carrying --key (the key stored in the Vault for the
test tenant), so it also proves that the tenant's key reaches the provider.
"""

from __future__ import annotations

import argparse
import hmac
import ipaddress
import json
import logging
import re
import sys
import time
import uuid
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

log = logging.getLogger("jarvis_fake_llm")

MAX_BODY = 8 << 20
_TRANSCRIPT = re.compile(r"<transcript>\n?(.*?)\n?</transcript>", re.DOTALL)


def _message(text: str) -> dict[str, Any]:
    return {
        "type": "message",
        "id": f"msg_{uuid.uuid4().hex[:12]}",
        "status": "completed",
        "role": "assistant",
        "content": [{"type": "output_text", "text": text, "annotations": []}],
    }


def _response(model: str, output: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "id": f"resp_{uuid.uuid4().hex[:12]}",
        "object": "response",
        "created_at": int(time.time()),
        "status": "completed",
        "model": model,
        "output": output,
        "parallel_tool_calls": True,
        "tool_choice": "auto",
        "tools": [],
        "usage": {
            "input_tokens": 100,
            "output_tokens": 20,
            "total_tokens": 120,
            "input_tokens_details": {"cached_tokens": 0},
            "output_tokens_details": {"reasoning_tokens": 0},
        },
    }


def _text_of(value: Any) -> str:
    """The text of a Responses `input`: a string or a list of items."""
    if isinstance(value, str):
        return value
    parts: list[str] = []
    for item in value if isinstance(value, list) else []:
        content = item.get("content") if isinstance(item, dict) else None
        if isinstance(content, str):
            parts.append(content)
        elif isinstance(content, list):
            parts.extend(str(c.get("text", "")) for c in content if isinstance(c, dict))
    return "\n".join(parts)


def extract(body: dict[str, Any]) -> list[dict[str, Any]]:
    """Memory extraction: one passage per user line."""
    match = _TRANSCRIPT.search(_text_of(body.get("input")))
    lines = match.group(1).splitlines() if match else []
    said = [line.removeprefix("user:").strip() for line in lines if line.startswith("user:")]
    user = {"type": "Person", "name": "User"}
    extraction = {
        "entities": [{"type": "Person", "name": "User", "aliases": [], "description": "The user of Jarvis."}],
        "relations": [],
        "passages": [{"text": f"The user said: {text}", "mentions": [user]} for text in said if text][:20],
    }
    return [_message(json.dumps(extraction, ensure_ascii=False))]


def decide(body: dict[str, Any], tool: str, tool_args: str) -> list[dict[str, Any]]:
    """A task step: call the tool once, then summarize."""
    raw = body.get("input")
    items: list[Any] = raw if isinstance(raw, list) else []
    results = [i for i in items if isinstance(i, dict) and i.get("type") == "function_call_output"]
    offered = {t.get("name") for t in body.get("tools") or [] if isinstance(t, dict)}
    if tool and tool in offered and not results:
        call = uuid.uuid4().hex[:12]
        return [
            {
                "type": "function_call",
                "id": f"fc_{call}",
                "call_id": f"call_{call}",
                "name": tool,
                "arguments": tool_args,
                "status": "completed",
            }
        ]
    if results:
        output = str(results[-1].get("output", ""))[:500]
        return [_message(f"Finished. The tool returned: {output}")]
    return [_message("Finished; there was nothing to look up.")]


class _Handler(BaseHTTPRequestHandler):
    server: _Server

    def log_message(self, format: str, *args: Any) -> None:
        return  # one structured line per request below instead

    def _reply(self, status: HTTPStatus, body: dict[str, Any]) -> None:
        data = json.dumps(body, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self) -> None:
        expected = f"Bearer {self.server.key}".encode()
        if not hmac.compare_digest(self.headers.get("Authorization", "").encode(), expected):
            log.warning("rejected a request with the wrong API key")
            error = {"type": "invalid_request_error", "code": "invalid_api_key"}
            self._reply(HTTPStatus.UNAUTHORIZED, {"error": error})
            return
        if not self.path.rstrip("/").endswith("/responses"):
            self._reply(HTTPStatus.NOT_FOUND, {"error": {"type": "invalid_request_error", "message": "not found"}})
            return
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0 or length > MAX_BODY:
            self._reply(HTTPStatus.BAD_REQUEST, {"error": {"type": "invalid_request_error", "message": "bad body"}})
            return
        try:
            body = json.loads(self.rfile.read(length))
        except json.JSONDecodeError:
            self._reply(HTTPStatus.BAD_REQUEST, {"error": {"type": "invalid_request_error", "message": "bad json"}})
            return
        structured = (body.get("text") or {}).get("format", {}).get("type") == "json_schema"
        if not structured and self.server.delay > 0:
            time.sleep(self.server.delay)
        output = extract(body) if structured else decide(body, self.server.tool, self.server.tool_args)
        kind = "extraction" if structured else "decision"
        log.info("%s for model %s: %s", kind, body.get("model"), ", ".join(o["type"] for o in output))
        self._reply(HTTPStatus.OK, _response(str(body.get("model", "fake")), output))


class _Server(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address: tuple[str, int], key: str, tool: str, tool_args: str, delay: float = 0) -> None:
        super().__init__(address, _Handler)
        self.key, self.tool, self.tool_args, self.delay = key, tool, tool_args, delay


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="jarvis-fake-llm", description=__doc__.split("\n\n")[0])
    parser.add_argument("--listen", default="127.0.0.1:9910", help="loopback address (default %(default)s)")
    parser.add_argument("--key", required=True, help="the API key it accepts (the test tenant's key in the Vault)")
    parser.add_argument("--tool", default="", help="tool a task calls first, e.g. an MCP tool name")
    parser.add_argument("--tool-args", default="{}", help="its arguments, a JSON object")
    parser.add_argument("--delay", type=float, default=0, help="seconds each task decision takes (default 0)")
    args = parser.parse_args(argv)
    host, _, port = args.listen.rpartition(":")
    try:
        loopback = ipaddress.ip_address(host).is_loopback
    except ValueError:
        loopback = False
    if not loopback or not port.isdigit():
        parser.error("--listen must be a loopback host:port")
    try:
        tool_args = json.loads(args.tool_args)
    except ValueError:
        tool_args = None
    if not isinstance(tool_args, dict):
        parser.error("--tool-args must be a JSON object")
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s", stream=sys.stderr)
    server = _Server((host, int(port)), args.key, args.tool, args.tool_args, max(0.0, args.delay))
    log.info("fake Responses API at http://%s/v1 (tool: %s)", args.listen, args.tool or "none")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
