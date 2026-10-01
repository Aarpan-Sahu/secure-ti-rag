"""Request / response models (strict: unknown fields are rejected)."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from tirag.models import DocType

SourceName = Literal["misp", "opencti"]


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class QueryRequest(_Strict):
    question: str = Field(min_length=3, max_length=2000, description="Natural-language question")
    top_k: int | None = Field(default=None, ge=1, le=20)
    doc_types: list[DocType] | None = Field(default=None, max_length=7)
    sources: list[SourceName] | None = Field(default=None, max_length=2)


class SearchRequest(QueryRequest):
    pass


class CitationOut(BaseModel):
    n: int
    chunk_id: str
    doc_id: str
    source: str
    source_id: str
    doc_type: str
    title: str | None
    url: str | None
    tlp: str
    score: float
    excerpt: str


class QueryResponse(BaseModel):
    request_id: str
    answer: str
    grounded: bool
    citations: list[CitationOut]
    flags: list[str]
    retrieved: int
    latency_ms: int


class SearchHit(BaseModel):
    chunk_id: str
    doc_id: str
    source: str
    doc_type: str
    title: str | None
    url: str | None
    tlp: str
    score: float
    channels: list[str]
    excerpt: str


class SearchResponse(BaseModel):
    request_id: str
    hits: list[SearchHit]


class StatsResponse(BaseModel):
    chunks: int
    documents: int
    by_source: dict[str, int]
    by_doc_type: dict[str, int]
    quarantined: int


class ErrorBody(BaseModel):
    code: str
    message: str
    request_id: str


class ErrorResponse(BaseModel):
    error: ErrorBody


class HealthResponse(BaseModel):
    status: Literal["ok", "degraded"]
    version: str
    checks: dict[str, bool] = {}
