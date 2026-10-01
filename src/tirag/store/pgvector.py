"""PostgreSQL + pgvector backend (production).

One table holds chunks with: a ``vector`` column (HNSW, cosine), a generated ``tsvector`` column
(GIN, full-text) and an ``iocs text[]`` column (GIN, exact IOC match). Hybrid retrieval therefore
needs a single managed database (Amazon RDS for PostgreSQL supports the pgvector extension).

All statements are parameterised. Free-text terms are reduced to ``[a-z0-9._-]`` tokens before
being turned into a ``tsquery``, so user input never reaches SQL or tsquery syntax unescaped.
"""

from __future__ import annotations

import json
import logging
import re
from datetime import datetime
from typing import Any

import psycopg
from langchain_core.documents import Document
from pgvector import Vector
from pgvector.psycopg import register_vector
from psycopg import sql
from psycopg_pool import ConnectionPool

from tirag.models import QuarantineRecord
from tirag.store.base import ChunkStore, ScoredChunk, SearchFilter, StoreStats

log = logging.getLogger(__name__)

_SAFE_TERM = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")

_COLUMNS = (
    "id, doc_id, chunk_idx, content, source, source_id, doc_type, title, url, tlp, tlp_rank, "
    "iocs, labels, modified, content_hash, metadata"
)


class PgVectorStore(ChunkStore):
    def __init__(self, dsn: str, dim: int, pool_max: int = 10) -> None:
        if not isinstance(dim, int) or not 16 <= dim <= 4096:
            raise ValueError("embedding dimension out of range")
        self._dsn = dsn
        self._dim = dim
        self._pool_max = pool_max
        self._pool: ConnectionPool | None = None

    # --- connection management -------------------------------------------------------------
    def _get_pool(self) -> ConnectionPool:
        if self._pool is None:
            pool = ConnectionPool(
                self._dsn,
                min_size=1,
                max_size=self._pool_max,
                kwargs={"autocommit": True},
                configure=register_vector,
                open=False,
                name="tirag",
            )
            pool.open(wait=True, timeout=15)
            self._pool = pool
        return self._pool

    def close(self) -> None:
        if self._pool is not None:
            self._pool.close()
            self._pool = None

    def ping(self) -> bool:
        try:
            with self._get_pool().connection(timeout=3) as conn:
                conn.execute("SELECT 1")
            return True
        except Exception:
            log.warning("database ping failed", exc_info=True)
            return False

    # --- schema ----------------------------------------------------------------------------
    def init_schema(self) -> None:
        ddl = [
            sql.SQL(
                """
                CREATE TABLE IF NOT EXISTS ti_chunks (
                    id            uuid PRIMARY KEY,
                    doc_id        text NOT NULL,
                    chunk_idx     integer NOT NULL,
                    content       text NOT NULL,
                    embedding     vector({dim}) NOT NULL,
                    source        text NOT NULL,
                    source_id     text NOT NULL,
                    doc_type      text NOT NULL,
                    title         text,
                    url           text,
                    tlp           text NOT NULL,
                    tlp_rank      smallint NOT NULL CHECK (tlp_rank BETWEEN 0 AND 4),
                    iocs          text[] NOT NULL DEFAULT '{{}}',
                    labels        text[] NOT NULL DEFAULT '{{}}',
                    modified      timestamptz,
                    content_hash  text NOT NULL,
                    metadata      jsonb NOT NULL DEFAULT '{{}}',
                    tsv           tsvector GENERATED ALWAYS AS (to_tsvector('simple', content)) STORED,
                    created_at    timestamptz NOT NULL DEFAULT now(),
                    UNIQUE (doc_id, chunk_idx)
                )
                """
            ).format(dim=sql.Literal(self._dim)),
            sql.SQL("CREATE INDEX IF NOT EXISTS ti_chunks_doc_idx ON ti_chunks (doc_id)"),
            sql.SQL("CREATE INDEX IF NOT EXISTS ti_chunks_tsv_idx ON ti_chunks USING gin (tsv)"),
            sql.SQL("CREATE INDEX IF NOT EXISTS ti_chunks_iocs_idx ON ti_chunks USING gin (iocs)"),
            sql.SQL(
                "CREATE INDEX IF NOT EXISTS ti_chunks_vec_idx ON ti_chunks "
                "USING hnsw (embedding vector_cosine_ops)"
            ),
            sql.SQL(
                "CREATE TABLE IF NOT EXISTS ti_sync_state ("
                "key text PRIMARY KEY, value text NOT NULL, updated_at timestamptz NOT NULL DEFAULT now())"
            ),
            sql.SQL(
                "CREATE TABLE IF NOT EXISTS ti_quarantine ("
                "id bigserial PRIMARY KEY, doc_id text NOT NULL, chunk_idx integer NOT NULL, "
                "reason text NOT NULL, preview text NOT NULL, created_at timestamptz NOT NULL DEFAULT now())"
            ),
        ]
        # The extension must exist before the pool registers the vector type on new connections.
        with psycopg.connect(self._dsn, autocommit=True) as conn:
            conn.execute("CREATE EXTENSION IF NOT EXISTS vector")
            for stmt in ddl:
                conn.execute(stmt)
            row = conn.execute(
                "SELECT atttypmod FROM pg_attribute WHERE attrelid = 'ti_chunks'::regclass "
                "AND attname = 'embedding'"
            ).fetchone()
        if row is not None and row[0] != self._dim:
            raise RuntimeError(
                f"existing ti_chunks.embedding has dimension {row[0]} but configuration says "
                f"{self._dim}; re-index into a new table/database instead of mixing dimensions"
            )

    # --- writes ----------------------------------------------------------------------------
    def upsert_document(
        self, doc_id: str, chunks: list[Document], embeddings: list[list[float]]
    ) -> None:
        if len(chunks) != len(embeddings):
            raise ValueError("chunks and embeddings must be the same length")
        rows = []
        for idx, (doc, emb) in enumerate(zip(chunks, embeddings, strict=True)):
            md = doc.metadata
            known = {
                "chunk_id", "doc_id", "chunk_idx", "source", "source_id", "doc_type", "title",
                "url", "tlp", "tlp_rank", "iocs", "labels", "modified", "content_hash",
            }  # fmt: skip
            rows.append(
                (
                    md["chunk_id"],
                    doc_id,
                    idx,
                    doc.page_content,
                    Vector(emb),
                    md["source"],
                    md["source_id"],
                    md["doc_type"],
                    md.get("title"),
                    md.get("url"),
                    md["tlp"],
                    int(md["tlp_rank"]),
                    list(md.get("iocs", [])),
                    list(md.get("labels", [])),
                    _parse_ts(md.get("modified")),
                    md["content_hash"],
                    json.dumps({k: v for k, v in md.items() if k not in known}, default=str),
                )
            )
        with self._get_pool().connection() as conn, conn.transaction():
            conn.execute("DELETE FROM ti_chunks WHERE doc_id = %s", (doc_id,))
            if rows:
                with conn.cursor() as cur:
                    cur.executemany(
                        "INSERT INTO ti_chunks (id, doc_id, chunk_idx, content, embedding, source, "
                        "source_id, doc_type, title, url, tlp, tlp_rank, iocs, labels, modified, "
                        "content_hash, metadata) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s::jsonb)",
                        rows,
                    )

    def delete_document(self, doc_id: str) -> int:
        with self._get_pool().connection() as conn:
            return conn.execute("DELETE FROM ti_chunks WHERE doc_id = %s", (doc_id,)).rowcount

    def record_quarantine(self, records: list[QuarantineRecord]) -> None:
        if not records:
            return
        with self._get_pool().connection() as conn, conn.cursor() as cur:
            cur.executemany(
                "INSERT INTO ti_quarantine (doc_id, chunk_idx, reason, preview) VALUES (%s,%s,%s,%s)",
                [(r.doc_id, r.chunk_idx, r.reason, r.preview) for r in records],
            )

    def get_state(self, key: str) -> str | None:
        with self._get_pool().connection() as conn:
            row = conn.execute("SELECT value FROM ti_sync_state WHERE key = %s", (key,)).fetchone()
        return row[0] if row else None

    def set_state(self, key: str, value: str) -> None:
        with self._get_pool().connection() as conn:
            conn.execute(
                "INSERT INTO ti_sync_state (key, value) VALUES (%s, %s) "
                "ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()",
                (key, value),
            )

    # --- reads -----------------------------------------------------------------------------
    @staticmethod
    def _filter_sql(flt: SearchFilter) -> tuple[sql.Composable, list[Any]]:
        clauses = [sql.SQL("tlp_rank <= %s")]
        params: list[Any] = [flt.max_tlp_rank]
        if flt.doc_types is not None:
            clauses.append(sql.SQL("doc_type = ANY(%s)"))
            params.append(sorted(flt.doc_types))
        if flt.sources is not None:
            clauses.append(sql.SQL("source = ANY(%s)"))
            params.append(sorted(flt.sources))
        return sql.SQL(" AND ").join(clauses), params

    def search_vector(self, embedding: list[float], k: int, flt: SearchFilter) -> list[ScoredChunk]:
        where, params = self._filter_sql(flt)
        query = sql.SQL(
            "SELECT {cols}, 1 - (embedding <=> %s) AS score FROM ti_chunks WHERE {where} "
            "ORDER BY embedding <=> %s LIMIT %s"
        ).format(cols=sql.SQL(_COLUMNS), where=where)
        vec = Vector(embedding)
        with self._get_pool().connection() as conn:
            rows = conn.execute(query, [vec, *params, vec, k]).fetchall()
        return [ScoredChunk(_to_document(r), float(r[-1]), "vector") for r in rows]

    def search_lexical(self, terms: list[str], k: int, flt: SearchFilter) -> list[ScoredChunk]:
        safe = [t for t in terms if _SAFE_TERM.match(t)]
        if not safe:
            return []
        tsquery = " | ".join("'" + t.replace("'", "''") + "'" for t in safe[:32])
        where, params = self._filter_sql(flt)
        query = sql.SQL(
            "SELECT {cols}, ts_rank(tsv, q) AS score FROM ti_chunks, to_tsquery('simple', %s) q "
            "WHERE tsv @@ q AND {where} ORDER BY score DESC LIMIT %s"
        ).format(cols=sql.SQL(_COLUMNS), where=where)
        with self._get_pool().connection() as conn:
            rows = conn.execute(query, [tsquery, *params, k]).fetchall()
        return [ScoredChunk(_to_document(r), float(r[-1]), "lexical") for r in rows]

    def search_iocs(self, values: list[str], k: int, flt: SearchFilter) -> list[ScoredChunk]:
        if not values:
            return []
        where, params = self._filter_sql(flt)
        query = sql.SQL(
            "SELECT {cols}, cardinality(ARRAY(SELECT unnest(iocs) INTERSECT SELECT unnest(%s::text[]))) "
            "AS score FROM ti_chunks WHERE iocs && %s::text[] AND {where} ORDER BY score DESC LIMIT %s"
        ).format(cols=sql.SQL(_COLUMNS), where=where)
        with self._get_pool().connection() as conn:
            rows = conn.execute(query, [values, values, *params, k]).fetchall()
        return [ScoredChunk(_to_document(r), float(r[-1]), "ioc") for r in rows]

    def stats(self) -> StoreStats:
        with self._get_pool().connection() as conn:
            chunks, docs = conn.execute(
                "SELECT count(*), count(DISTINCT doc_id) FROM ti_chunks"
            ).fetchone()  # type: ignore[misc]
            by_source = dict(conn.execute("SELECT source, count(*) FROM ti_chunks GROUP BY 1").fetchall())
            by_type = dict(conn.execute("SELECT doc_type, count(*) FROM ti_chunks GROUP BY 1").fetchall())
            quarantined = conn.execute("SELECT count(*) FROM ti_quarantine").fetchone()[0]  # type: ignore[index]
        return StoreStats(
            chunks=chunks,
            documents=docs,
            by_source={k: int(v) for k, v in by_source.items()},
            by_doc_type={k: int(v) for k, v in by_type.items()},
            quarantined=int(quarantined),
        )


def _parse_ts(value: Any) -> datetime | None:
    if not value:
        return None
    if isinstance(value, datetime):
        return value
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None


def _to_document(row: tuple) -> Document:
    (cid, doc_id, idx, content, source, source_id, doc_type, title, url, tlp, tlp_rank,
     iocs, labels, modified, content_hash, extra) = row[:16]  # fmt: skip
    metadata: dict[str, Any] = {
        **(extra or {}),
        "chunk_id": str(cid),
        "doc_id": doc_id,
        "chunk_idx": idx,
        "source": source,
        "source_id": source_id,
        "doc_type": doc_type,
        "title": title,
        "url": url,
        "tlp": tlp,
        "tlp_rank": int(tlp_rank),
        "iocs": list(iocs or []),
        "labels": list(labels or []),
        "modified": modified.isoformat() if modified else None,
        "content_hash": content_hash,
    }
    return Document(page_content=content, metadata=metadata)
