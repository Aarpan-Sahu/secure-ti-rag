from __future__ import annotations

import math
from datetime import UTC, datetime
from pathlib import Path

import pytest
from langchain_core.documents import Document

from tests.conftest import make_settings
from tirag.embeddings import HashEmbeddings, build_embeddings
from tirag.ingest.chunking import build_chunks, contextual_header
from tirag.models import TLP, DocType, QuarantineRecord, ThreatDoc
from tirag.store.base import SearchFilter
from tirag.store.memory import MemoryStore


def cosine(a: list[float], b: list[float]) -> float:
    return sum(x * y for x, y in zip(a, b, strict=True))


# ----------------------------------------------------------------------------- embeddings


def test_hash_embeddings_are_deterministic_unit_vectors() -> None:
    emb = HashEmbeddings(128)
    a1, a2 = (
        emb.embed_query("STORMVEIL ransomware hospitals"),
        emb.embed_query("STORMVEIL ransomware hospitals"),
    )
    assert a1 == a2
    assert len(a1) == 128
    assert math.isclose(math.sqrt(sum(v * v for v in a1)), 1.0, rel_tol=1e-6)


def test_hash_embeddings_rank_related_text_higher() -> None:
    emb = HashEmbeddings(384)
    q = emb.embed_query("ransomware affecting hospitals")
    near = emb.embed_documents(["Ransomware group targets regional hospitals"])[0]
    far = emb.embed_documents(["Detecting leaked cloud access keys in repositories"])[0]
    assert cosine(q, near) > cosine(q, far)


def test_hash_embeddings_empty_text_is_zero_vector_not_nan() -> None:
    assert set(HashEmbeddings(32).embed_query("")) == {0.0}


def test_hash_embeddings_rejects_tiny_dimension() -> None:
    with pytest.raises(ValueError):
        HashEmbeddings(4)


def test_build_embeddings_factory() -> None:
    assert isinstance(
        build_embeddings(make_settings(embedding_provider="hash", embedding_dim=64)), HashEmbeddings
    )


# ----------------------------------------------------------------------------- chunking


def _doc(doc_type: DocType, text: str, **kw) -> ThreatDoc:
    return ThreatDoc(
        source="misp",
        source_id="evt-1",
        doc_type=doc_type,
        title="Test Title",
        text=text,
        tlp=kw.pop("tlp", TLP.GREEN),
        modified=datetime(2026, 9, 1, tzinfo=UTC),
        **kw,
    )


def test_indicator_chunks_group_lines_and_keep_header() -> None:
    lines = "\n".join(f"- ipv4: 198.51.100.{i}" for i in range(1, 61))
    chunks = build_chunks(_doc(DocType.INDICATOR, lines), make_settings(iocs_per_chunk=25))
    assert [c.page_content.count("- ipv4:") for c in chunks] == [25, 25, 10]
    assert all(
        c.page_content.startswith("[indicator] Test Title (source: misp, TLP:GREEN)")
        for c in chunks
    )
    assert "198.51.100.1" in chunks[0].metadata["iocs"]
    assert "198.51.100.60" in chunks[-1].metadata["iocs"]


def test_narrative_chunks_respect_size_and_carry_metadata() -> None:
    text = " ".join(f"Sentence number {i} describes tradecraft in detail." for i in range(200))
    s = make_settings(chunk_size=400, chunk_overlap=50)
    chunks = build_chunks(_doc(DocType.REPORT, text), s)
    assert len(chunks) > 5
    body_lens = [len(c.page_content.split("\n", 1)[1]) for c in chunks]
    assert max(body_lens) <= 400
    md = chunks[0].metadata
    assert md["tlp"] == "GREEN" and md["tlp_rank"] == 1
    assert md["doc_id"] == "misp:report:evt-1" and md["chunk_idx"] == 0
    assert md["modified"].startswith("2026-09-01")


def test_chunk_ids_are_deterministic_and_content_sensitive() -> None:
    s = make_settings()
    a = build_chunks(_doc(DocType.REPORT, "alpha beta gamma"), s)
    b = build_chunks(_doc(DocType.REPORT, "alpha beta gamma"), s)
    c = build_chunks(_doc(DocType.REPORT, "alpha beta delta"), s)
    assert a[0].metadata["chunk_id"] == b[0].metadata["chunk_id"]
    assert a[0].metadata["chunk_id"] != c[0].metadata["chunk_id"]


def test_empty_text_produces_no_chunks() -> None:
    assert build_chunks(_doc(DocType.REPORT, "   "), make_settings()) == []
    assert contextual_header(_doc(DocType.EVENT, "x")).startswith("[event] Test Title")


# ----------------------------------------------------------------------------- memory store


def _chunk(
    doc_id: str,
    idx: int,
    text: str,
    tlp: TLP = TLP.GREEN,
    doc_type: str = "report",
    source: str = "misp",
    iocs: list[str] | None = None,
) -> Document:
    return Document(
        page_content=text,
        metadata={
            "chunk_id": f"{doc_id}-{idx}",
            "doc_id": doc_id,
            "chunk_idx": idx,
            "source": source,
            "source_id": doc_id,
            "doc_type": doc_type,
            "title": doc_id,
            "url": None,
            "tlp": tlp.value,
            "tlp_rank": tlp.rank,
            "iocs": iocs or [],
            "labels": [],
            "modified": None,
            "content_hash": "h",
        },
    )


@pytest.fixture
def store() -> MemoryStore:
    emb = HashEmbeddings(64)
    s = MemoryStore()
    docs = [
        _chunk(
            "d1",
            0,
            "ransomware group targets hospitals",
            TLP.CLEAR,
            "report",
            "misp",
            ["198.51.100.1"],
        ),
        _chunk("d2", 0, "cloud key abuse and miners", TLP.AMBER, "event", "opencti"),
        _chunk(
            "d3", 0, "restricted signalling collection", TLP.RED, "report", "misp", ["192.0.2.201"]
        ),
    ]
    for d in docs:
        s.upsert_document(d.metadata["doc_id"], [d], emb.embed_documents([d.page_content]))
    return s


def test_tlp_ceiling_is_enforced_on_every_channel(store: MemoryStore) -> None:
    emb = HashEmbeddings(64)
    low = SearchFilter(max_tlp_rank=TLP.GREEN.rank)
    q = emb.embed_query("signalling collection restricted")
    for hits in (
        store.search_vector(q, 10, low),
        store.search_lexical(["signalling", "restricted"], 10, low),
        store.search_iocs(["192.0.2.201"], 10, low),
    ):
        assert all(h.document.metadata["tlp_rank"] <= 1 for h in hits)
    assert store.search_iocs(["192.0.2.201"], 10, low) == []
    assert (
        store.search_iocs(["192.0.2.201"], 10, SearchFilter(max_tlp_rank=4))[0].document.metadata[
            "doc_id"
        ]
        == "d3"
    )


def test_doc_type_and_source_filters(store: MemoryStore) -> None:
    flt = SearchFilter(
        max_tlp_rank=4, doc_types=frozenset({"event"}), sources=frozenset({"opencti"})
    )
    hits = store.search_lexical(["cloud", "ransomware"], 10, flt)
    assert [h.document.metadata["doc_id"] for h in hits] == ["d2"]


def test_lexical_ranks_rare_terms_higher(store: MemoryStore) -> None:
    hits = store.search_lexical(["hospitals", "group"], 10, SearchFilter(max_tlp_rank=4))
    assert hits[0].document.metadata["doc_id"] == "d1"


def test_upsert_replaces_all_chunks_of_a_document(store: MemoryStore) -> None:
    emb = HashEmbeddings(64)
    new = [_chunk("d1", 0, "brand new text", TLP.CLEAR), _chunk("d1", 1, "second chunk", TLP.CLEAR)]
    store.upsert_document("d1", new, emb.embed_documents([c.page_content for c in new]))
    assert store.stats().chunks == 4
    assert store.search_lexical(["hospitals"], 10, SearchFilter(max_tlp_rank=4)) == []
    store.upsert_document("d1", [], [])
    assert store.stats().documents == 2


def test_upsert_validates_lengths_and_delete_reports_count(store: MemoryStore) -> None:
    with pytest.raises(ValueError):
        store.upsert_document("x", [_chunk("x", 0, "t")], [])
    assert store.delete_document("d2") == 1
    assert store.delete_document("d2") == 0


def test_state_quarantine_and_stats(store: MemoryStore) -> None:
    store.set_state("k", "v")
    assert store.get_state("k") == "v" and store.get_state("missing") is None
    store.record_quarantine([QuarantineRecord("d9", 0, "ignore_instructions", "preview")])
    st = store.stats()
    assert st.quarantined == 1 and st.by_source == {"misp": 2, "opencti": 1}


def test_persistence_round_trip(tmp_path: Path, store: MemoryStore) -> None:
    path = tmp_path / "nested" / "index.json"
    persisted = MemoryStore(str(path))
    emb = HashEmbeddings(64)
    c = _chunk("p1", 0, "persisted ransomware chunk", TLP.GREEN, iocs=["203.0.113.9"])
    persisted.upsert_document("p1", [c], emb.embed_documents([c.page_content]))
    persisted.set_state("sync", "now")
    persisted.flush()
    reloaded = MemoryStore(str(path))
    assert reloaded.get_state("sync") == "now"
    hit = reloaded.search_iocs(["203.0.113.9"], 5, SearchFilter(max_tlp_rank=4))
    assert hit and hit[0].document.page_content == "persisted ransomware chunk"
    assert not list(path.parent.glob("*.tmp"))
