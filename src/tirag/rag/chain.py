"""RAG orchestration with LangChain (LCEL).

    question -> input guardrail -> retrieve (TLP-filtered, hybrid) -> prompt -> LLM -> parse
             -> output guardrails (citations, IOC grounding, markup/secret scrub, defang) -> result

The chain is composed of ``Runnable`` steps so it is traceable with LangSmith/OpenTelemetry
callbacks and each step can be unit-tested in isolation.
"""

from __future__ import annotations

import logging
import re
import time
from dataclasses import dataclass, field
from typing import Any

from langchain_core.documents import Document
from langchain_core.embeddings import Embeddings
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.output_parsers import StrOutputParser
from langchain_core.runnables import Runnable, RunnableLambda, RunnablePassthrough

from tirag.config import Settings
from tirag.models import TLP
from tirag.rag.prompts import NO_EVIDENCE_ANSWER, PROMPT, format_context
from tirag.rag.retriever import HybridRetriever
from tirag.security.guardrails import allowed_iocs_for, check_query, sanitize_output
from tirag.security.iocs import defang_text
from tirag.store.base import ChunkStore, SearchFilter

log = logging.getLogger(__name__)

_CITATION = re.compile(r"\[(\d{1,3})\]")


class GuardrailViolation(Exception):
    def __init__(self, reason: str, flags: list[str]) -> None:
        super().__init__(reason)
        self.reason = reason
        self.flags = flags


class UpstreamError(Exception):
    """The LLM or embedding provider failed (mapped to HTTP 502 by the API layer)."""


@dataclass
class Citation:
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


@dataclass
class RAGResult:
    answer: str
    grounded: bool
    citations: list[Citation]
    flags: list[str] = field(default_factory=list)
    retrieved: int = 0
    latency_ms: int = 0
    chunk_ids: list[str] = field(default_factory=list)


@dataclass
class Clearance:
    max_tlp: TLP
    doc_types: frozenset[str] | None = None
    sources: frozenset[str] | None = None


class RAGService:
    def __init__(
        self, store: ChunkStore, embeddings: Embeddings, llm: BaseChatModel, settings: Settings
    ) -> None:
        self.store = store
        self.embeddings = embeddings
        self.llm = llm
        self.settings = settings
        self._chain = self._build_chain()

    # --- retrieval only --------------------------------------------------------------------
    def retriever_for(self, clearance: Clearance, k: int | None = None) -> HybridRetriever:
        s = self.settings
        return HybridRetriever(
            store=self.store,
            embeddings=self.embeddings,
            search_filter=SearchFilter(
                max_tlp_rank=clearance.max_tlp.rank,
                doc_types=clearance.doc_types,
                sources=clearance.sources,
            ),
            k=k or s.top_k,
            fetch_k=s.fetch_k,
            max_chunks_per_doc=s.max_chunks_per_doc,
            min_vector_score=s.min_vector_score,
            min_term_overlap=s.min_term_overlap,
        )

    def search(self, query: str, clearance: Clearance, k: int | None = None) -> list[Document]:
        check = check_query(query, self.settings)
        if not check.allowed:
            raise GuardrailViolation(check.reason or "rejected", check.flags)
        try:
            return self.retriever_for(clearance, k).invoke(check.query)
        except Exception as exc:
            raise UpstreamError("retrieval backend failure") from exc

    # --- full answer -----------------------------------------------------------------------
    def answer(self, question: str, clearance: Clearance, k: int | None = None) -> RAGResult:
        started = time.perf_counter()
        check = check_query(question, self.settings)
        if not check.allowed:
            raise GuardrailViolation(check.reason or "rejected", check.flags)
        try:
            result: RAGResult = self._chain.invoke(
                {"question": check.query, "clearance": clearance, "k": k, "flags": list(check.flags)}
            )
        except GuardrailViolation:
            raise
        except Exception as exc:
            log.exception("RAG chain failed")
            raise UpstreamError("answer generation failed") from exc
        result.latency_ms = int((time.perf_counter() - started) * 1000)
        return result

    # --- chain -----------------------------------------------------------------------------
    def _build_chain(self) -> Runnable[dict[str, Any], RAGResult]:
        retrieve = RunnableLambda(self._retrieve).with_config(run_name="retrieve")
        generate = (
            RunnablePassthrough.assign(rendered=RunnableLambda(self._render_context))
            | RunnablePassthrough.assign(
                context=lambda x: x["rendered"][0],
                used_docs=lambda x: x["rendered"][1],
            )
            | RunnablePassthrough.assign(raw=PROMPT | self.llm | StrOutputParser())
            | RunnableLambda(self._postprocess).with_config(run_name="guardrails")
        )
        no_evidence = RunnableLambda(self._no_evidence)

        def route(state: dict[str, Any]) -> RAGResult:
            return (generate if state["docs"] else no_evidence).invoke(state)

        return retrieve | RunnableLambda(route)

    def _retrieve(self, state: dict[str, Any]) -> dict[str, Any]:
        retriever = self.retriever_for(state["clearance"], state.get("k"))
        return {**state, "docs": retriever.invoke(state["question"])}

    def _render_context(self, state: dict[str, Any]) -> tuple[str, list[Document]]:
        return format_context(state["docs"], self.settings.max_context_chars)

    def _no_evidence(self, state: dict[str, Any]) -> RAGResult:
        return RAGResult(
            answer=NO_EVIDENCE_ANSWER,
            grounded=False,
            citations=[],
            flags=[*state["flags"], "no_evidence"],
            retrieved=0,
        )

    def _postprocess(self, state: dict[str, Any]) -> RAGResult:
        docs: list[Document] = state["used_docs"]
        flags: list[str] = list(state["flags"])

        allowed = allowed_iocs_for([d.page_content for d in docs], state["question"])
        checked = sanitize_output(state["raw"], allowed, self.settings)
        flags.extend(checked.flags)
        text = checked.text

        if NO_EVIDENCE_ANSWER.lower() in text.lower():
            return RAGResult(
                answer=NO_EVIDENCE_ANSWER,
                grounded=False,
                citations=[],
                flags=[*flags, "no_evidence"],
                retrieved=len(docs),
            )

        cited: list[int] = []

        def keep_valid(match: re.Match[str]) -> str:
            n = int(match.group(1))
            if 1 <= n <= len(docs):
                if n not in cited:
                    cited.append(n)
                return match.group(0)
            flags.append("invalid_citation_removed")
            return ""

        text = _CITATION.sub(keep_valid, text).strip()

        if not cited:
            # An answer with no valid citation is not grounded: do not present it as one.
            return RAGResult(
                answer="The model response could not be grounded in the retrieved evidence, so it was "
                "withheld. Review the retrieved sources via /v1/search.",
                grounded=False,
                citations=[],
                flags=[*flags, "ungrounded_answer_withheld"],
                retrieved=len(docs),
                chunk_ids=[d.metadata["chunk_id"] for d in docs],
            )

        citations = [self._citation(n, docs[n - 1]) for n in sorted(cited)]
        return RAGResult(
            answer=text,
            grounded=True,
            citations=citations,
            flags=sorted(set(flags)),
            retrieved=len(docs),
            chunk_ids=[d.metadata["chunk_id"] for d in docs],
        )

    def _citation(self, n: int, doc: Document) -> Citation:
        md = doc.metadata
        body = doc.page_content.split("\n", 1)[-1][:300]
        if self.settings.defang_output:
            body = defang_text(body)
        return Citation(
            n=n,
            chunk_id=md["chunk_id"],
            doc_id=md["doc_id"],
            source=md["source"],
            source_id=md["source_id"],
            doc_type=md["doc_type"],
            title=md.get("title"),
            url=md.get("url"),
            tlp=md["tlp"],
            score=float(md.get("score", 0.0)),
            excerpt=body,
        )
