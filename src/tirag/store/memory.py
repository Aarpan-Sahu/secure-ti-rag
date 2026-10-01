"""In-process store with optional JSON persistence.

Used for local development, unit tests and the evaluation harness. It implements the same
three retrieval channels as the PostgreSQL backend (cosine similarity, BM25, exact IOC match).
It is *not* intended for multi-replica production use (see ``TIRAG_STORE_BACKEND``).
"""

from __future__ import annotations

import json
import math
import os
import tempfile
import threading
from collections import Counter, defaultdict
from pathlib import Path

import numpy as np
from langchain_core.documents import Document

from tirag.models import QuarantineRecord
from tirag.store.base import ChunkStore, ScoredChunk, SearchFilter, StoreStats
from tirag.text import tokenize

_K1 = 1.5
_B = 0.75


class _Entry:
    __slots__ = ("doc", "embedding", "length", "term_freq")

    def __init__(self, doc: Document, embedding: np.ndarray) -> None:
        self.doc = doc
        self.embedding = embedding
        tokens = tokenize(doc.page_content)
        self.term_freq = Counter(tokens)
        self.length = max(len(tokens), 1)


class MemoryStore(ChunkStore):
    def __init__(self, path: str | None = None) -> None:
        self._lock = threading.RLock()
        self._by_doc: dict[str, list[_Entry]] = {}
        self._state: dict[str, str] = {}
        self._quarantine: list[QuarantineRecord] = []
        self._path = Path(path) if path else None
        if self._path and self._path.exists():
            self._load()

    # --- lifecycle -------------------------------------------------------------------------
    def init_schema(self) -> None:
        return None

    def ping(self) -> bool:
        return True

    # --- writes ----------------------------------------------------------------------------
    def upsert_document(
        self, doc_id: str, chunks: list[Document], embeddings: list[list[float]]
    ) -> None:
        if len(chunks) != len(embeddings):
            raise ValueError("chunks and embeddings must be the same length")
        entries = [
            _Entry(doc, _unit(np.asarray(vec, dtype=np.float32)))
            for doc, vec in zip(chunks, embeddings, strict=True)
        ]
        with self._lock:
            if entries:
                self._by_doc[doc_id] = entries
            else:
                self._by_doc.pop(doc_id, None)

    def delete_document(self, doc_id: str) -> int:
        with self._lock:
            return len(self._by_doc.pop(doc_id, []))

    def record_quarantine(self, records: list[QuarantineRecord]) -> None:
        with self._lock:
            self._quarantine.extend(records)

    def get_state(self, key: str) -> str | None:
        with self._lock:
            return self._state.get(key)

    def set_state(self, key: str, value: str) -> None:
        with self._lock:
            self._state[key] = value

    # --- reads -----------------------------------------------------------------------------
    def _entries(self, flt: SearchFilter) -> list[_Entry]:
        with self._lock:
            return [
                e for entries in self._by_doc.values() for e in entries if flt.allows(e.doc.metadata)
            ]

    def search_vector(self, embedding: list[float], k: int, flt: SearchFilter) -> list[ScoredChunk]:
        entries = self._entries(flt)
        if not entries:
            return []
        query = _unit(np.asarray(embedding, dtype=np.float32))
        matrix = np.stack([e.embedding for e in entries])
        scores = matrix @ query
        order = np.argsort(-scores)[:k]
        return [ScoredChunk(entries[i].doc, float(scores[i]), "vector") for i in order]

    def search_lexical(self, terms: list[str], k: int, flt: SearchFilter) -> list[ScoredChunk]:
        entries = self._entries(flt)
        if not entries or not terms:
            return []
        n = len(entries)
        avg_len = sum(e.length for e in entries) / n
        df = {t: sum(1 for e in entries if t in e.term_freq) for t in terms}
        scored: list[ScoredChunk] = []
        for entry in entries:
            score = 0.0
            for term in terms:
                tf = entry.term_freq.get(term, 0)
                if not tf:
                    continue
                idf = math.log(1 + (n - df[term] + 0.5) / (df[term] + 0.5))
                score += idf * tf * (_K1 + 1) / (tf + _K1 * (1 - _B + _B * entry.length / avg_len))
            if score > 0:
                scored.append(ScoredChunk(entry.doc, score, "lexical"))
        scored.sort(key=lambda s: -s.score)
        return scored[:k]

    def search_iocs(self, values: list[str], k: int, flt: SearchFilter) -> list[ScoredChunk]:
        wanted = set(values)
        if not wanted:
            return []
        scored = []
        for entry in self._entries(flt):
            hits = wanted.intersection(entry.doc.metadata.get("iocs", []))
            if hits:
                scored.append(ScoredChunk(entry.doc, float(len(hits)), "ioc"))
        scored.sort(key=lambda s: -s.score)
        return scored[:k]

    def stats(self) -> StoreStats:
        with self._lock:
            by_source: dict[str, int] = defaultdict(int)
            by_type: dict[str, int] = defaultdict(int)
            chunks = 0
            for entries in self._by_doc.values():
                for e in entries:
                    chunks += 1
                    by_source[e.doc.metadata.get("source", "?")] += 1
                    by_type[e.doc.metadata.get("doc_type", "?")] += 1
            return StoreStats(
                chunks=chunks,
                documents=len(self._by_doc),
                by_source=dict(by_source),
                by_doc_type=dict(by_type),
                quarantined=len(self._quarantine),
            )

    def quarantined(self) -> list[QuarantineRecord]:
        with self._lock:
            return list(self._quarantine)

    # --- persistence -----------------------------------------------------------------------
    def flush(self) -> None:
        if not self._path:
            return
        with self._lock:
            payload = {
                "state": self._state,
                "quarantine": [q.__dict__ for q in self._quarantine],
                "docs": {
                    doc_id: [
                        {
                            "text": e.doc.page_content,
                            "metadata": e.doc.metadata,
                            "embedding": e.embedding.tolist(),
                        }
                        for e in entries
                    ]
                    for doc_id, entries in self._by_doc.items()
                },
            }
        self._path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=self._path.parent, suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(payload, fh)
            os.replace(tmp, self._path)  # atomic
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)

    def _load(self) -> None:
        assert self._path is not None
        data = json.loads(self._path.read_text(encoding="utf-8"))
        self._state = dict(data.get("state", {}))
        self._quarantine = [QuarantineRecord(**q) for q in data.get("quarantine", [])]
        for doc_id, rows in data.get("docs", {}).items():
            self._by_doc[doc_id] = [
                _Entry(
                    Document(page_content=r["text"], metadata=r["metadata"]),
                    np.asarray(r["embedding"], dtype=np.float32),
                )
                for r in rows
            ]


def _unit(vec: np.ndarray) -> np.ndarray:
    norm = float(np.linalg.norm(vec))
    return vec if norm == 0.0 else vec / norm
