"""FastAPI application factory.

Note: this module deliberately does not use ``from __future__ import annotations``; FastAPI must
evaluate the ``Annotated[..., Depends(local_function)]`` annotations of the nested route handlers.
"""

import logging
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from typing import Annotated

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from langchain_core.documents import Document
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest
from starlette.exceptions import HTTPException as StarletteHTTPException

from tirag import __version__
from tirag.api import metrics
from tirag.api.middleware import RequestContextMiddleware
from tirag.api.schemas import (
    CitationOut,
    ErrorResponse,
    HealthResponse,
    QueryRequest,
    QueryResponse,
    SearchHit,
    SearchRequest,
    SearchResponse,
    StatsResponse,
)
from tirag.config import Settings, get_settings
from tirag.embeddings import build_embeddings
from tirag.llm import build_llm
from tirag.logging_setup import configure_logging
from tirag.rag.chain import Clearance, GuardrailViolation, RAGService, UpstreamError
from tirag.security.auth import Authenticator, AuthError, Principal, build_authenticator
from tirag.security.iocs import defang_text
from tirag.security.ratelimit import RateLimiter
from tirag.store import build_store

audit_log = logging.getLogger("tirag.audit")
log = logging.getLogger(__name__)

_bearer_scheme = HTTPBearer(auto_error=False, description="API key or OIDC access token")


def build_service(settings: Settings) -> RAGService:
    store = build_store(settings)
    if settings.auto_migrate:
        store.init_schema()
    return RAGService(store, build_embeddings(settings), build_llm(settings), settings)


def _error(
    status: int, code: str, message: str, request: Request, headers: dict[str, str] | None = None
):
    rid = getattr(request.state, "request_id", "-")
    return JSONResponse(
        status_code=status,
        content={"error": {"code": code, "message": message, "request_id": rid}},
        headers=headers,
    )


def create_app(
    settings: Settings | None = None,
    service: RAGService | None = None,
    authenticator: Authenticator | None = None,
    clock: Callable[[], float] | None = None,
) -> FastAPI:
    settings = settings or get_settings()
    configure_logging(settings.log_level)
    service = service or build_service(settings)
    authenticator = authenticator or build_authenticator(settings)
    limiter_kwargs = {"clock": clock} if clock else {}
    limiter = RateLimiter(
        settings.rate_limit_per_minute, settings.rate_limit_burst, **limiter_kwargs
    )
    auth_fail_limiter = RateLimiter(20, 10, **limiter_kwargs)

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        log.info("starting", extra={"version": __version__, "env": settings.env})
        yield
        service.store.close()  # type: ignore[union-attr]

    app = FastAPI(
        title="Secure Threat-Intelligence RAG",
        version=__version__,
        description="Natural-language, cited answers over MISP and OpenCTI threat intelligence.",
        docs_url="/docs" if settings.docs_enabled else None,
        redoc_url=None,
        openapi_url="/openapi.json" if settings.docs_enabled else None,
        lifespan=lifespan,
    )
    app.state.settings = settings
    app.state.service = service

    app.add_middleware(RequestContextMiddleware, max_body_bytes=settings.max_body_bytes)
    if settings.cors_origin_list:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=settings.cors_origin_list,
            allow_methods=["GET", "POST"],
            allow_headers=["Authorization", "Content-Type"],
            max_age=600,
        )

    # --- error handling --------------------------------------------------------------------
    @app.exception_handler(AuthError)
    async def _auth_error(request: Request, exc: AuthError):
        metrics.AUTH_FAILURES.labels("forbidden" if exc.status == 403 else "unauthenticated").inc()
        headers = {"WWW-Authenticate": "Bearer"} if exc.status == 401 else None
        return _error(
            exc.status,
            "unauthorized" if exc.status == 401 else "forbidden",
            exc.message,
            request,
            headers,
        )

    @app.exception_handler(RequestValidationError)
    async def _validation_error(request: Request, exc: RequestValidationError):
        detail = "; ".join(f"{'.'.join(map(str, e['loc'][1:]))}: {e['msg']}" for e in exc.errors())[
            :300
        ]
        return _error(422, "invalid_request", detail or "invalid request", request)

    @app.exception_handler(StarletteHTTPException)
    async def _http_error(request: Request, exc: StarletteHTTPException):
        return _error(
            exc.status_code, "http_error", str(exc.detail), request, getattr(exc, "headers", None)
        )

    @app.exception_handler(Exception)
    async def _unhandled(request: Request, exc: Exception):
        log.exception("unhandled error")
        return _error(500, "internal_error", "internal server error", request)

    # --- dependencies ----------------------------------------------------------------------
    def authenticated(
        request: Request,
        credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer_scheme)] = None,
    ) -> Principal:
        ip = request.client.host if request.client else "unknown"
        try:
            principal = authenticator.authenticate(request.headers.get("authorization"))
        except AuthError as exc:
            allowed, retry = auth_fail_limiter.check(f"authfail:{ip}")
            log.warning("authentication failed", extra={"client": ip, "reason": exc.message})
            if not allowed:
                metrics.RATE_LIMITED.inc()
                raise HTTPException(
                    429, "too many failed attempts", headers={"Retry-After": str(int(retry) + 1)}
                ) from exc
            raise
        return principal

    def rate_limited(principal: Annotated[Principal, Depends(authenticated)]) -> Principal:
        allowed, retry = limiter.check(principal.name)
        if not allowed:
            metrics.RATE_LIMITED.inc()
            raise HTTPException(
                429, "rate limit exceeded", headers={"Retry-After": str(int(retry) + 1)}
            )
        return principal

    def admin_only(principal: Annotated[Principal, Depends(authenticated)]) -> Principal:
        if not principal.is_admin:
            raise AuthError(403, "admin role required")
        return principal

    errors = {
        400: {"model": ErrorResponse},
        401: {"model": ErrorResponse},
        403: {"model": ErrorResponse},
        429: {"model": ErrorResponse},
        502: {"model": ErrorResponse},
    }

    # --- operational endpoints -------------------------------------------------------------
    @app.get("/healthz", response_model=HealthResponse, tags=["ops"], summary="Liveness probe")
    def healthz() -> HealthResponse:
        return HealthResponse(status="ok", version=__version__)

    @app.get("/readyz", response_model=HealthResponse, tags=["ops"], summary="Readiness probe")
    def readyz(response: Response) -> HealthResponse:
        db_ok = service.store.ping()
        if not db_ok:
            response.status_code = 503
        return HealthResponse(
            status="ok" if db_ok else "degraded", version=__version__, checks={"database": db_ok}
        )

    @app.get("/metrics", tags=["ops"], include_in_schema=False)
    def prometheus_metrics(principal: Annotated[Principal, Depends(admin_only)]) -> Response:
        return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)

    # --- API -------------------------------------------------------------------------------
    def _clearance(principal: Principal, body: QueryRequest) -> Clearance:
        return Clearance(
            max_tlp=principal.max_tlp,
            doc_types=frozenset(t.value for t in body.doc_types) if body.doc_types else None,
            sources=frozenset(body.sources) if body.sources else None,
        )

    def _audit(
        principal: Principal, request: Request, question: str, event: str, **fields: object
    ) -> None:
        import hashlib

        record = {
            "event": event,
            "principal": principal.name,
            "role": principal.role,
            "max_tlp": principal.max_tlp.value,
            "query_sha256": hashlib.sha256(question.encode()).hexdigest(),
            "query_len": len(question),
            **fields,
        }
        if settings.audit_log_queries:
            record["query"] = question
        audit_log.info(event, extra=record)

    @app.post(
        "/v1/query",
        response_model=QueryResponse,
        tags=["rag"],
        responses=errors,
        summary="Ask a question; get a cited, grounded answer",
    )
    def query(
        body: QueryRequest, request: Request, principal: Annotated[Principal, Depends(rate_limited)]
    ) -> QueryResponse:
        try:
            result = service.answer(body.question, _clearance(principal, body), body.top_k)
        except GuardrailViolation as exc:
            metrics.QUERIES.labels("blocked").inc()
            for flag in exc.flags:
                metrics.GUARDRAIL_FLAGS.labels(flag).inc()
            _audit(principal, request, body.question, "query_blocked", flags=exc.flags)
            raise HTTPException(400, "request rejected by input policy") from exc
        except UpstreamError as exc:
            metrics.UPSTREAM_ERRORS.inc()
            metrics.QUERIES.labels("error").inc()
            _audit(principal, request, body.question, "query_error")
            raise HTTPException(502, "upstream service unavailable") from exc

        outcome = "answered" if result.grounded else "no_answer"
        metrics.QUERIES.labels(outcome).inc()
        metrics.RETRIEVED_CHUNKS.observe(result.retrieved)
        for flag in result.flags:
            metrics.GUARDRAIL_FLAGS.labels(flag).inc()
        _audit(
            principal,
            request,
            body.question,
            "query",
            grounded=result.grounded,
            retrieved=result.retrieved,
            flags=result.flags,
            chunk_ids=result.chunk_ids,
            latency_ms=result.latency_ms,
        )
        return QueryResponse(
            request_id=request.state.request_id,
            answer=result.answer,
            grounded=result.grounded,
            citations=[CitationOut(**c.__dict__) for c in result.citations],
            flags=result.flags,
            retrieved=result.retrieved,
            latency_ms=result.latency_ms,
        )

    @app.post(
        "/v1/search",
        response_model=SearchResponse,
        tags=["rag"],
        responses=errors,
        summary="Retrieval only (no LLM): ranked evidence chunks",
    )
    def search(
        body: SearchRequest,
        request: Request,
        principal: Annotated[Principal, Depends(rate_limited)],
    ) -> SearchResponse:
        try:
            docs = service.search(body.question, _clearance(principal, body), body.top_k)
        except GuardrailViolation as exc:
            _audit(principal, request, body.question, "search_blocked", flags=exc.flags)
            raise HTTPException(400, "request rejected by input policy") from exc
        except UpstreamError as exc:
            metrics.UPSTREAM_ERRORS.inc()
            raise HTTPException(502, "upstream service unavailable") from exc
        _audit(principal, request, body.question, "search", retrieved=len(docs))
        return SearchResponse(
            request_id=request.state.request_id, hits=[_hit(d, settings) for d in docs]
        )

    @app.get(
        "/v1/stats",
        response_model=StatsResponse,
        tags=["rag"],
        responses=errors,
        summary="Index statistics",
    )
    def stats(principal: Annotated[Principal, Depends(rate_limited)]) -> StatsResponse:
        s = service.store.stats()
        return StatsResponse(**s.__dict__)

    return app


def _hit(doc: Document, settings: Settings) -> SearchHit:
    md = doc.metadata
    body = doc.page_content.split("\n", 1)[-1][:300]
    title = md.get("title")
    if settings.defang_output and title:
        title = defang_text(title)
    return SearchHit(
        chunk_id=md["chunk_id"],
        doc_id=md["doc_id"],
        source=md["source"],
        doc_type=md["doc_type"],
        title=title,
        url=md.get("url"),
        tlp=md["tlp"],
        score=float(md.get("score", 0.0)),
        channels=list(md.get("channels", [])),
        excerpt=defang_text(body) if settings.defang_output else body,
    )


def app_factory() -> FastAPI:  # pragma: no cover - uvicorn entry point (--factory)
    return create_app()
