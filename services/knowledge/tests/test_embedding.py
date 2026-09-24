"""Model integrity, and the real model's behaviour when it is downloaded."""

from __future__ import annotations

import hashlib
import io
import urllib.request
from pathlib import Path
from typing import Any

import numpy as np
import pytest

from jarvis_knowledge import embedding
from jarvis_knowledge.embedding import MULTILINGUAL_E5_SMALL, Embedder, ModelError, ModelFile, ModelSpec, ensure_model

PAYLOAD = b"pretend this is an onnx model"
SPEC = ModelSpec(
    repo="example/tiny",
    revision="0" * 40,
    files=(ModelFile("model.onnx", hashlib.sha256(PAYLOAD).hexdigest(), len(PAYLOAD)),),
    onnx_file="model.onnx",
    dimensions=4,
    max_tokens=8,
    query_prefix="",
    passage_prefix="",
)


def _serve(monkeypatch: pytest.MonkeyPatch, body: bytes) -> list[str]:
    urls: list[str] = []

    def fake_urlopen(url: str, timeout: float) -> Any:
        urls.append(url)
        return io.BytesIO(body)

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    return urls


def test_download_verifies_and_pins(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    urls = _serve(monkeypatch, PAYLOAD)
    directory = ensure_model(SPEC, tmp_path, download=True)
    assert (directory / "model.onnx").read_bytes() == PAYLOAD
    assert urls == [f"https://huggingface.co/example/tiny/resolve/{'0' * 40}/model.onnx"]
    # Present and valid: no download.
    ensure_model(SPEC, tmp_path, download=False)
    assert len(urls) == 1


def test_tampered_download_is_rejected_and_not_kept(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _serve(monkeypatch, b"pretend this is an evil model")
    with pytest.raises(ModelError, match="does not match"):
        ensure_model(SPEC, tmp_path, download=True)
    assert not any(p.is_file() for p in tmp_path.rglob("*"))


def test_oversized_download_is_aborted(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(embedding, "_CHUNK", 8)
    _serve(monkeypatch, PAYLOAD + b"x" * 100)
    with pytest.raises(ModelError, match="larger"):
        ensure_model(SPEC, tmp_path, download=True)


def test_missing_or_modified_files(tmp_path: Path) -> None:
    with pytest.raises(ModelError, match="missing"):
        ensure_model(SPEC, tmp_path, download=False)
    path = embedding.model_directory(SPEC, tmp_path) / "model.onnx"
    path.parent.mkdir(parents=True)
    path.write_bytes(PAYLOAD[:-1] + b"!")
    with pytest.raises(ModelError, match="does not match"):
        ensure_model(SPEC, tmp_path, download=False)


@pytest.fixture
def real(model_dir: Path | None) -> Embedder:
    if model_dir is None or not embedding.model_directory(MULTILINGUAL_E5_SMALL, model_dir).is_dir():
        pytest.skip("real model not downloaded (knowledgectl download-model --dir .dev/models)")
    directory = ensure_model(MULTILINGUAL_E5_SMALL, model_dir, download=False)
    return Embedder(MULTILINGUAL_E5_SMALL, directory, threads=2)


def test_real_model_ranks_greek_and_english(real: Embedder) -> None:
    passages = [
        "Η Μαρία Παπαδοπούλου είναι product manager στο έργο Atlas.",
        "Maria Papadopoulou leads the Atlas project since May 2026.",
        "Ο Γιώργος πήγε διακοπές στην Κρήτη τον Αύγουστο.",
        "The quarterly budget review is on Friday.",
    ]
    q = real.embed(["Τι έχω με τη Μαρία για το Atlas;"], "query")[0]
    p = real.embed(passages, "passage")
    assert p.shape == (4, 384) and p.dtype == np.float32
    assert np.allclose(np.linalg.norm(p, axis=1), 1.0, atol=1e-5)
    scores = p @ q
    assert list(np.argsort(-scores)[:2]) == [0, 1]  # both languages beat the unrelated notes
    assert scores[1] >= 0.78 > scores[3]  # the default relevance floor separates them


def test_real_model_is_deterministic_and_batch_independent(real: Embedder) -> None:
    one = real.embed(["short"], "passage")[0]
    batch = real.embed(["short", "a much longer sentence that forces padding of the first"], "passage")[0]
    assert np.allclose(one, batch, atol=1e-5)
