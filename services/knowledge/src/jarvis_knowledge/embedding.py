"""Local text embeddings.

The model runs inside the service (ONNX Runtime, CPU), so knowledge text is
never sent to an external API. Model files are pinned to an exact upstream
revision and verified by SHA-256 before use.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import os
import tempfile
import urllib.request
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, Protocol, cast

import numpy as np
import numpy.typing as npt
import onnxruntime as ort
from tokenizers import Tokenizer

log = logging.getLogger(__name__)

Vector = npt.NDArray[np.float32]
Kind = Literal["query", "passage"]


class ModelError(Exception):
    """The embedding model is missing, corrupt or could not be downloaded."""


@dataclass(frozen=True, slots=True)
class ModelFile:
    name: str
    sha256: str
    size: int


@dataclass(frozen=True, slots=True)
class ModelSpec:
    """An embedding model pinned to one revision of its repository."""

    repo: str
    revision: str
    files: tuple[ModelFile, ...]
    onnx_file: str
    dimensions: int
    max_tokens: int
    # E5 models expect every input to say whether it is a query or a passage.
    query_prefix: str
    passage_prefix: str

    @property
    def slug(self) -> str:
        return f"{self.repo.replace('/', '--')}@{self.revision[:12]}"


# intfloat/multilingual-e5-small: MIT licensed, 384 dimensions, ~100
# languages including Greek.
MULTILINGUAL_E5_SMALL = ModelSpec(
    repo="intfloat/multilingual-e5-small",
    revision="614241f622f53c4eeff9890bdc4f31cfecc418b3",
    files=(
        ModelFile("onnx/model.onnx", "ca456c06b3a9505ddfd9131408916dd79290368331e7d76bb621f1cba6bc8665", 470_268_510),
        ModelFile("tokenizer.json", "0b44a9d7b51c3c62626640cda0e2c2f70fdacdc25bbbd68038369d14ebdf4c39", 17_082_730),
    ),
    onnx_file="onnx/model.onnx",
    dimensions=384,
    max_tokens=512,
    query_prefix="query: ",
    passage_prefix="passage: ",
)

MODELS = {MULTILINGUAL_E5_SMALL.repo: MULTILINGUAL_E5_SMALL}

_CHUNK = 1 << 20


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        while block := f.read(_CHUNK):
            digest.update(block)
    return digest.hexdigest()


def model_directory(spec: ModelSpec, root: Path) -> Path:
    return root / spec.repo.replace("/", "--") / spec.revision


def ensure_model(spec: ModelSpec, root: Path, *, download: bool) -> Path:
    """Returns the directory holding the verified model files.

    Missing files are downloaded (over HTTPS, from the pinned revision) only
    when `download` is true; production images ship the files instead
    (`knowledgectl download-model`).
    """
    directory = model_directory(spec, root)
    for file in spec.files:
        path = directory / file.name
        if path.is_file():
            if path.stat().st_size == file.size and _sha256(path) == file.sha256:
                continue
            raise ModelError(f"{path} does not match the pinned model; delete it and download again")
        if not download:
            raise ModelError(f"{path} is missing; run `knowledgectl download-model` or enable downloads")
        _download(spec, file, path)
    return directory


def _download(spec: ModelSpec, file: ModelFile, path: Path) -> None:
    url = f"https://huggingface.co/{spec.repo}/resolve/{spec.revision}/{file.name}"
    log.info("downloading model file", extra={"url": url, "bytes": file.size})
    path.parent.mkdir(parents=True, exist_ok=True)
    digest = hashlib.sha256()
    size = 0
    fd, tmp_name = tempfile.mkstemp(dir=path.parent, prefix=".download-")
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, "wb") as out, urllib.request.urlopen(url, timeout=60) as response:
            while block := response.read(_CHUNK):
                out.write(block)
                digest.update(block)
                size += len(block)
                if size > file.size:
                    raise ModelError(f"{file.name}: larger than the pinned {file.size} bytes")
        if size != file.size or digest.hexdigest() != file.sha256:
            raise ModelError(f"{file.name}: downloaded file does not match the pinned hash")
        tmp.replace(path)
    except OSError as e:
        raise ModelError(f"cannot download {url}: {e}") from e
    finally:
        tmp.unlink(missing_ok=True)


class Embedder:
    """Turns text into L2-normalized vectors (cosine similarity = dot product)."""

    def __init__(self, spec: ModelSpec, directory: Path, *, threads: int) -> None:
        self.spec = spec
        options = ort.SessionOptions()
        options.intra_op_num_threads = threads
        options.inter_op_num_threads = 1
        options.graph_optimization_level = ort.GraphOptimizationLevel.ORT_ENABLE_ALL
        self._session = ort.InferenceSession(
            str(directory / spec.onnx_file), sess_options=options, providers=["CPUExecutionProvider"]
        )
        self._inputs = {i.name for i in self._session.get_inputs()}
        self._tokenizer = Tokenizer.from_file(str(directory / "tokenizer.json"))
        self._tokenizer.enable_truncation(max_length=spec.max_tokens)
        pad_id = self._tokenizer.token_to_id("<pad>")
        if pad_id is None:
            raise ModelError("tokenizer has no <pad> token")
        self._tokenizer.enable_padding(pad_id=pad_id, pad_token="<pad>")  # noqa: S106 (a token name, not a secret)

    def embed(self, texts: Sequence[str], kind: Kind) -> Vector:
        """Embeds texts; returns an (n, dimensions) float32 array."""
        if not texts:
            return np.zeros((0, self.spec.dimensions), dtype=np.float32)
        prefix = self.spec.query_prefix if kind == "query" else self.spec.passage_prefix
        encodings = self._tokenizer.encode_batch([prefix + t for t in texts])
        ids = np.asarray([e.ids for e in encodings], dtype=np.int64)
        mask = np.asarray([e.attention_mask for e in encodings], dtype=np.int64)
        feed: dict[str, npt.NDArray[np.int64]] = {"input_ids": ids, "attention_mask": mask}
        if "token_type_ids" in self._inputs:
            feed["token_type_ids"] = np.zeros_like(ids)
        hidden = np.asarray(self._session.run(None, feed)[0], dtype=np.float32)
        # Mean pooling over real tokens, then L2 normalization (as E5 is trained).
        weights = mask[:, :, None].astype(np.float32)
        pooled = (hidden * weights).sum(axis=1) / np.clip(weights.sum(axis=1), 1e-9, None)
        norms = np.linalg.norm(pooled, axis=1, keepdims=True)
        return cast(Vector, (pooled / np.clip(norms, 1e-12, None)).astype(np.float32))


class TextEmbedder(Protocol):
    """What the service needs from an embedder."""

    @property
    def dimensions(self) -> int: ...

    @property
    def model(self) -> str: ...

    async def query(self, text: str) -> Vector: ...

    async def passages(self, texts: Sequence[str]) -> list[Vector]: ...


class AsyncEmbedder:
    """Runs the embedder off the event loop (ONNX Runtime releases the GIL)."""

    # Passages are embedded in batches of similar length to limit padding.
    batch_size = 16

    def __init__(self, embedder: Embedder, *, concurrency: int) -> None:
        self._embedder = embedder
        self._slots = asyncio.Semaphore(concurrency)

    @property
    def dimensions(self) -> int:
        return self._embedder.spec.dimensions

    @property
    def model(self) -> str:
        return self._embedder.spec.slug

    async def query(self, text: str) -> Vector:
        async with self._slots:
            vectors = await asyncio.to_thread(self._embedder.embed, [text], "query")
        return cast(Vector, vectors[0])

    async def passages(self, texts: Sequence[str]) -> list[Vector]:
        order = sorted(range(len(texts)), key=lambda i: len(texts[i]))
        result: list[Vector | None] = [None] * len(texts)
        for start in range(0, len(order), self.batch_size):
            batch = order[start : start + self.batch_size]
            async with self._slots:
                vectors = await asyncio.to_thread(self._embedder.embed, [texts[i] for i in batch], "passage")
            for i, vector in zip(batch, vectors, strict=True):
                result[i] = vector
        return [v for v in result if v is not None]
