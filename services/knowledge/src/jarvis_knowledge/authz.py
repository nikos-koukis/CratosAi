"""Zero-trust callers: mutual TLS identity plus a per-principal RPC allowlist.

Same model as the other Jarvis services: the caller is the single URI SAN of
its verified client certificate (e.g. spiffe://jarvis.local/orchestrator),
and a TOML policy lists the methods each principal may call:

    [[principal]]
    id = "spiffe://jarvis.local/orchestrator"
    allow = ["Retrieve", "UpsertKnowledge"]
"""

from __future__ import annotations

import tomllib
from collections.abc import Iterable, Mapping
from functools import lru_cache
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from cryptography import x509


class PolicyError(Exception):
    """The authorization policy is invalid."""


@lru_cache(maxsize=256)
def _principal_from_pem(pem: bytes) -> str | None:
    try:
        cert = x509.load_pem_x509_certificate(pem)
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except ValueError, x509.ExtensionNotFound:
        return None
    uris = san.get_values_for_type(x509.UniformResourceIdentifier)
    if len(uris) != 1:
        return None
    parsed = urlsplit(uris[0])
    return uris[0] if parsed.scheme and parsed.netloc else None


def peer_principal(auth_context: Mapping[str, Iterable[bytes]]) -> str | None:
    """The single URI SAN of the peer's verified certificate, if any.

    gRPC only exposes the certificate after verifying it against the client
    CA (the server requires client certificates).
    """
    pem = next(iter(auth_context.get("x509_pem_cert", ())), None)
    return _principal_from_pem(bytes(pem)) if pem else None


class Policy:
    def __init__(self, grants: dict[str, frozenset[str]]) -> None:
        self._grants = grants

    @classmethod
    def parse(cls, text: str, known: Iterable[str]) -> Policy:
        try:
            document = tomllib.loads(text)
        except tomllib.TOMLDecodeError as e:
            raise PolicyError(f"invalid authorization policy: {e}") from e
        valid = set(known)
        unknown_top = set(document) - {"principal"}
        if unknown_top:
            raise PolicyError(f"invalid authorization policy: unknown field {sorted(unknown_top)[0]}")
        entries: Any = document.get("principal", [])
        if not isinstance(entries, list):
            raise PolicyError("invalid authorization policy: [[principal]] must be an array of tables")
        grants: dict[str, frozenset[str]] = {}
        for entry in entries:
            if not isinstance(entry, dict) or set(entry) - {"id", "allow"}:
                raise PolicyError("invalid authorization policy: a principal has only `id` and `allow`")
            principal, allow = entry.get("id"), entry.get("allow")
            if not isinstance(principal, str) or not (urlsplit(principal).scheme and urlsplit(principal).netloc):
                raise PolicyError(f"invalid authorization policy: principal {principal!r} is not a URI")
            if principal in grants:
                raise PolicyError(f"invalid authorization policy: principal {principal} listed twice")
            if not isinstance(allow, list) or not allow or not all(isinstance(m, str) for m in allow):
                raise PolicyError(f"invalid authorization policy: principal {principal} needs a non-empty allow list")
            for method in allow:
                if method not in valid:
                    raise PolicyError(f"invalid authorization policy: unknown method {method!r}")
            grants[principal] = frozenset(allow)
        return cls(grants)

    @classmethod
    def load(cls, path: Path, known: Iterable[str]) -> Policy:
        try:
            text = path.read_text()
        except OSError as e:
            raise PolicyError(f"cannot read authorization policy: {e.strerror}") from e
        return cls.parse(text, known)

    def allowed(self, principal: str, method: str) -> bool:
        return method in self._grants.get(principal, frozenset())

    def __len__(self) -> int:
        return len(self._grants)
