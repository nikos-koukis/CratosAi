"""Stores a FAKE provider key for the development tenant, as the dashboard would.

The fake providers of tools/dev-stack.sh accept only this key, so the stack
runs end to end without real API keys. Never pass a real key here.

    uv run --frozen python tools/dev-tenant.py <tenant-id> <fake-key>
"""

import sys
from pathlib import Path

import grpc
from jarvis.common.v1 import provider_pb2
from jarvis.vault.v1 import vault_pb2, vault_pb2_grpc


def main() -> None:
    tenant, key = sys.argv[1], sys.argv[2]
    if not key.startswith("sk-dev-"):
        sys.exit("dev-tenant.py stores only fake keys (sk-dev-...)")
    certs = Path(__file__).resolve().parent.parent / "services/vault/.dev/certs"
    credentials = grpc.ssl_channel_credentials(
        (certs / "ca.pem").read_bytes(),
        (certs / "dashboard-api-key.pem").read_bytes(),
        (certs / "dashboard-api.pem").read_bytes(),
    )
    channel = grpc.secure_channel(
        "127.0.0.1:50051",
        credentials,
        options=[("grpc.ssl_target_name_override", "localhost")],
    )
    stub = vault_pb2_grpc.VaultServiceStub(channel)
    for provider in (provider_pb2.PROVIDER_OPENAI, provider_pb2.PROVIDER_XAI):
        stub.CreateKey(
            vault_pb2.CreateKeyRequest(
                tenant_id=tenant,
                provider=provider,
                label="dev fake",
                secret=key.encode(),
                replace_active=True,
            ),
            timeout=10,
        )
    print(f"stored the fake key for tenant {tenant}")


if __name__ == "__main__":
    main()
