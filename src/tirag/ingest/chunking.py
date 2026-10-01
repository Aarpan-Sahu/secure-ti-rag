"""Type-aware chunking.

* Narrative documents (events, actors, malware, reports) are split with LangChain's
  ``RecursiveCharacterTextSplitter``.
* Indicator documents are split on line boundaries into groups of at most ``iocs_per_chunk``
  indicators so a hash or IP never straddles two chunks.

Every chunk is prefixed with a short *contextual header* (type, title, source, TLP). Without it a
chunk like ``- sha256: ab12...`` carries no signal about what it belongs to, which hurts both
semantic and lexical retrieval and makes citations unreadable.
"""

from __future__ import annotations

import hashlib
import uuid

from langchain_core.documents import Document
from langchain_text_splitters import RecursiveCharacterTextSplitter

from tirag.config import Settings
from tirag.models import DocType, ThreatDoc
from tirag.security.iocs import extract_iocs

_NAMESPACE = uuid.UUID("0b9a1c7e-5d38-4f0b-8f0e-6f7e1a2b3c4d")
_MAX_IOCS_PER_CHUNK = 200


def contextual_header(doc: ThreatDoc) -> str:
    return f"[{doc.doc_type.value}] {doc.title} (source: {doc.source}, TLP:{doc.tlp.value})"


def _split_body(doc: ThreatDoc, settings: Settings) -> list[str]:
    if doc.doc_type == DocType.INDICATOR:
        lines = [ln for ln in doc.text.splitlines() if ln.strip()]
        # Keep any non-indicator preamble (lines not starting with "- ") attached to every group.
        preamble = [ln for ln in lines if not ln.lstrip().startswith("- ")]
        items = [ln for ln in lines if ln.lstrip().startswith("- ")]
        if not items:
            return ["\n".join(lines)] if lines else []
        n = settings.iocs_per_chunk
        return ["\n".join([*preamble, *items[i : i + n]]) for i in range(0, len(items), n)]
    splitter = RecursiveCharacterTextSplitter(
        chunk_size=settings.chunk_size,
        chunk_overlap=settings.chunk_overlap,
        separators=["\n\n", "\n", ". ", " ", ""],
    )
    return [c for c in splitter.split_text(doc.text) if c.strip()]


def build_chunks(doc: ThreatDoc, settings: Settings) -> list[Document]:
    header = contextual_header(doc)
    chunks: list[Document] = []
    for idx, body in enumerate(_split_body(doc, settings)):
        content = f"{header}\n{body}"
        content_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()
        iocs = [i.value for i in extract_iocs(content)][:_MAX_IOCS_PER_CHUNK]
        chunks.append(
            Document(
                page_content=content,
                metadata={
                    "chunk_id": str(uuid.uuid5(_NAMESPACE, f"{doc.doc_id}:{idx}:{content_hash}")),
                    "doc_id": doc.doc_id,
                    "chunk_idx": idx,
                    "source": doc.source,
                    "source_id": doc.source_id,
                    "doc_type": doc.doc_type.value,
                    "title": doc.title,
                    "url": doc.url,
                    "tlp": doc.tlp.value,
                    "tlp_rank": doc.tlp.rank,
                    "iocs": iocs,
                    "labels": doc.labels[:20],
                    "modified": doc.modified.isoformat() if doc.modified else None,
                    "content_hash": content_hash,
                },
            )
        )
    return chunks
