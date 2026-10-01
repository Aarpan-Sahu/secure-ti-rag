from __future__ import annotations

from tirag.config import Settings
from tirag.store.base import ChunkStore, ScoredChunk, SearchFilter, StoreStats


def build_store(settings: Settings) -> ChunkStore:
    if settings.store_backend == "memory":
        from tirag.store.memory import MemoryStore

        return MemoryStore(settings.memory_index_path)
    from tirag.store.pgvector import PgVectorStore

    return PgVectorStore(
        settings.database_dsn(), dim=settings.embedding_dim, pool_max=settings.db_pool_max
    )


__all__ = ["ChunkStore", "ScoredChunk", "SearchFilter", "StoreStats", "build_store"]
