"""Ingestion pipeline: fetch -> sanitise -> chunk -> screen -> embed -> upsert.

Design points
-------------
* **Idempotent**: chunk IDs are deterministic and ``upsert_document`` replaces all chunks of a
  document atomically, so re-running (or overlapping windows) never duplicates content.
* **Fail-closed on poisoning**: chunks that look like prompt-injection payloads are quarantined
  (kept out of the index, recorded for analyst review). If *every* chunk of an updated document is
  quarantined, the previously indexed version is removed as well.
* **Fault tolerant**: one bad document is recorded in the report and skipped; the sync cursor only
  advances if the whole feed was read successfully.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable
from datetime import UTC, datetime, timedelta

from langchain_core.embeddings import Embeddings

from tirag.config import Settings
from tirag.connectors.base import Connector, ConnectorError
from tirag.ingest.chunking import build_chunks
from tirag.models import IngestReport, QuarantineRecord, ThreatDoc
from tirag.security.sanitize import clean_text, scan_injection
from tirag.store.base import ChunkStore

log = logging.getLogger(__name__)

EPOCH = datetime(1970, 1, 1, tzinfo=UTC)
_OVERLAP = timedelta(minutes=10)  # re-read a little before the cursor to tolerate clock skew


def _embed_in_batches(embeddings: Embeddings, texts: list[str], batch: int) -> list[list[float]]:
    out: list[list[float]] = []
    for i in range(0, len(texts), batch):
        out.extend(embeddings.embed_documents(texts[i : i + batch]))
    return out


def sanitise_doc(doc: ThreatDoc, settings: Settings) -> ThreatDoc:
    doc.title = clean_text(doc.title, 300) or doc.source_id
    doc.text = clean_text(doc.text, settings.max_ingest_chars)
    doc.labels = [clean_text(label, 100) for label in doc.labels]
    return doc


def process_document(
    doc: ThreatDoc,
    store: ChunkStore,
    embeddings: Embeddings,
    settings: Settings,
    report: IngestReport,
) -> None:
    doc = sanitise_doc(doc, settings)
    if not doc.text:
        report.documents_skipped += 1
        return

    chunks = build_chunks(doc, settings)
    kept = []
    quarantined: list[QuarantineRecord] = []
    for chunk in chunks:
        scan = scan_injection(chunk.page_content)
        if scan.flagged and settings.injection_policy == "quarantine":
            quarantined.append(
                QuarantineRecord(
                    doc_id=doc.doc_id,
                    chunk_idx=int(chunk.metadata["chunk_idx"]),
                    reason=",".join(scan.matches),
                    preview=chunk.page_content[:240],
                )
            )
            continue
        if scan.flagged:
            chunk.metadata["injection_flagged"] = True
        kept.append(chunk)

    if quarantined:
        store.record_quarantine(quarantined)
        report.chunks_quarantined += len(quarantined)
        log.warning(
            "quarantined suspected prompt-injection content",
            extra={"doc_id": doc.doc_id, "chunks": len(quarantined)},
        )
    if not kept:
        store.delete_document(doc.doc_id)  # never keep a stale copy of a tampered document
        report.documents_skipped += 1
        return

    vectors = _embed_in_batches(
        embeddings, [c.page_content for c in kept], settings.embed_batch_size
    )
    store.upsert_document(doc.doc_id, kept, vectors)
    report.documents_indexed += 1
    report.chunks_indexed += len(kept)


def ingest_connector(
    connector: Connector,
    store: ChunkStore,
    embeddings: Embeddings,
    settings: Settings,
    *,
    full: bool = False,
) -> IngestReport:
    report = IngestReport(source=connector.name)
    state_key = f"sync:{connector.name}:last_success"
    started = datetime.now(UTC)

    lookback = started - timedelta(
        days=settings.misp_lookback_days
        if connector.name == "misp"
        else settings.opencti_lookback_days
    )
    previous = None if full else store.get_state(state_key)
    if getattr(connector, "full_history", False):
        since = EPOCH  # static fixture feeds ignore the sync window
    elif previous:
        since = datetime.fromisoformat(previous) - _OVERLAP
    else:
        since = lookback

    feed_ok = True
    try:
        docs: Iterable[ThreatDoc] = connector.fetch(since)
        for doc in docs:
            report.documents_seen += 1
            try:
                process_document(doc, store, embeddings, settings, report)
            except Exception as exc:  # one bad document must not abort the whole sync
                log.exception("failed to ingest document", extra={"doc_id": doc.doc_id})
                report.errors.append(f"{doc.doc_id}: {type(exc).__name__}")
    except ConnectorError as exc:
        feed_ok = False
        report.errors.append(f"feed error: {exc}")
        log.error("feed read failed", extra={"source": connector.name, "error": str(exc)})

    report.documents_skipped += getattr(connector, "skipped", 0)
    if feed_ok:
        store.set_state(state_key, started.isoformat())
    store.flush()
    log.info("ingest finished", extra={"report": report.as_dict()})
    return report
