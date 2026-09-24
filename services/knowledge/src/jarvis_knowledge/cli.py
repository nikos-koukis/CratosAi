"""knowledgectl: drive the knowledge service from a terminal.

    knowledgectl download-model [--dir .dev/models]
    knowledgectl upsert    --tenant T --user U [--scope tenant] --file knowledge.json
    knowledgectl retrieve  --tenant T --user U --query "..." [--budget 800] [--hops 1] [--json]
    knowledgectl entity    --tenant T --user U --key "Person:maria papadopoulou"
    knowledgectl delete-source --tenant T --user U --source conversation:1
    knowledgectl delete-entity --tenant T --user U --key "Person:maria papadopoulou"
    knowledgectl forget-user   --tenant T --user U

`upsert` reads an UpsertKnowledgeRequest in protobuf JSON (camelCase or
snake_case), without tenant and user, e.g.
    {"source": {"id": "conversation:1", "kind": "conversation"},
     "entities": [{"type": "Person", "name": "Maria"}],
     "passages": [{"text": "Maria moved the demo to Friday."}]}
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

import grpc
from google.protobuf import json_format
from google.protobuf.message import Message
from jarvis.knowledge.v1 import knowledge_pb2 as pb
from jarvis.knowledge.v1 import knowledge_pb2_grpc as pb_grpc

from jarvis_knowledge.embedding import MODELS, ensure_model

_SCOPES = {"user": pb.SCOPE_USER, "tenant": pb.SCOPE_TENANT}
# Which identity each command uses by default (see config/authz.dev.toml).
_DEFAULT_AS = {"delete-source": "dashboard-api", "delete-entity": "dashboard-api", "forget-user": "dashboard-api"}


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="knowledgectl", description=__doc__.split("\n\n")[0])
    parser.add_argument("--addr", default="127.0.0.1:50053", help="service address")
    parser.add_argument("--server-name", default="localhost", help="TLS server name")
    parser.add_argument("--certs", type=Path, default=Path(".dev/certs"), help="ca.pem and <identity>[-key].pem")
    parser.add_argument(
        "--as", dest="identity", help="client identity (default: orchestrator, dashboard-api for deletes)"
    )
    parser.add_argument("--timeout", type=float, default=30.0, help="per-RPC timeout in seconds")
    commands = parser.add_subparsers(dest="command", required=True)

    download = commands.add_parser("download-model", help="download and verify the embedding model")
    download.add_argument("--dir", type=Path, default=Path(".dev/models"))
    download.add_argument("--model", default=next(iter(MODELS)), choices=sorted(MODELS))

    def owned(name: str, help_: str, *, scope: bool = True) -> argparse.ArgumentParser:
        command = commands.add_parser(name, help=help_)
        command.add_argument("--tenant", required=True)
        command.add_argument("--user", required=True)
        if scope:
            command.add_argument("--scope", choices=sorted(_SCOPES), default="user")
        return command

    owned("upsert", "store knowledge from a JSON file").add_argument("--file", type=Path, required=True)
    retrieve = owned("retrieve", "print the context for a query", scope=False)
    retrieve.add_argument("--query", required=True)
    retrieve.add_argument("--budget", type=int, default=0)
    retrieve.add_argument("--hops", type=int)
    retrieve.add_argument("--kinds", nargs="*", default=[])
    retrieve.add_argument("--json", action="store_true", help="print the whole response")
    owned("entity", "show an entity and its relations").add_argument("--key", required=True)
    owned("delete-source", "forget one source").add_argument("--source", required=True)
    owned("delete-entity", "forget one entity").add_argument("--key", required=True)
    owned("forget-user", "forget everything private to a user", scope=False)
    return parser


def _stub(args: argparse.Namespace) -> pb_grpc.KnowledgeServiceStub:
    identity = args.identity or _DEFAULT_AS.get(args.command, "orchestrator")
    credentials = grpc.ssl_channel_credentials(
        root_certificates=(args.certs / "ca.pem").read_bytes(),
        private_key=(args.certs / f"{identity}-key.pem").read_bytes(),
        certificate_chain=(args.certs / f"{identity}.pem").read_bytes(),
    )
    channel = grpc.secure_channel(args.addr, credentials, options=[("grpc.ssl_target_name_override", args.server_name)])
    return pb_grpc.KnowledgeServiceStub(channel)


def _show(message: Message) -> None:
    print(json_format.MessageToJson(message, ensure_ascii=False, indent=2))


def run(args: argparse.Namespace) -> None:
    if args.command == "download-model":
        started = time.perf_counter()
        directory = ensure_model(MODELS[args.model], args.dir, download=True)
        print(f"{args.model} verified in {directory} ({time.perf_counter() - started:.1f}s)")
        return

    stub = _stub(args)
    metadata = (("x-request-id", f"knowledgectl-{time.time_ns()}"),)
    kw = {"timeout": args.timeout, "metadata": metadata}
    scope = _SCOPES.get(getattr(args, "scope", "user"), pb.SCOPE_USER)
    match args.command:
        case "upsert":
            request = json_format.Parse(args.file.read_text(), pb.UpsertKnowledgeRequest())
            request.tenant_id, request.user_id, request.scope = args.tenant, args.user, scope
            _show(stub.UpsertKnowledge(request, **kw))
        case "retrieve":
            retrieve = pb.RetrieveRequest(
                tenant_id=args.tenant,
                user_id=args.user,
                query=args.query,
                token_budget=args.budget,
                source_kinds=args.kinds,
            )
            if args.hops is not None:
                retrieve.max_hops = args.hops
            response = stub.Retrieve(retrieve, **kw)
            if args.json:
                _show(response)
            else:
                took = response.took.ToTimedelta().total_seconds() * 1000
                print(response.context or "(nothing relevant)")
                print(
                    f"\n~{response.estimated_tokens} tokens, {took:.1f} ms"
                    + (", truncated to fit the budget" if response.truncated else ""),
                    file=sys.stderr,
                )
        case "entity":
            _show(
                stub.GetEntity(
                    pb.GetEntityRequest(tenant_id=args.tenant, user_id=args.user, scope=scope, key=args.key), **kw
                )
            )
        case "delete-source":
            _show(
                stub.DeleteSource(
                    pb.DeleteSourceRequest(
                        tenant_id=args.tenant, user_id=args.user, scope=scope, source_id=args.source
                    ),
                    **kw,
                )
            )
        case "delete-entity":
            _show(
                stub.DeleteEntity(
                    pb.DeleteEntityRequest(tenant_id=args.tenant, user_id=args.user, scope=scope, key=args.key), **kw
                )
            )
        case "forget-user":
            _show(
                stub.DeleteUserKnowledge(pb.DeleteUserKnowledgeRequest(tenant_id=args.tenant, user_id=args.user), **kw)
            )


def main() -> None:
    args = _parser().parse_args()
    try:
        run(args)
    except grpc.RpcError as e:
        print(f"knowledgectl: {e.code().name}: {e.details()}", file=sys.stderr)
        sys.exit(1)
    except (OSError, json_format.ParseError, ValueError) as e:
        print(f"knowledgectl: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
