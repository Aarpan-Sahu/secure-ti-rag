"""Integration tests against a REAL PostgreSQL with the pgvector extension (embedded via pgserver)."""

from __future__ import annotations

from pathlib import Path

import pytest

from tests.conftest import ScriptedChatModel, make_settings
from tirag.connectors.mock_feeds import fixture_connectors
from tirag.embeddings import HashEmbeddings
from tirag.evalkit import run_eval
from tirag.ingest.pipeline import ingest_connector
from tirag.models import TLP, QuarantineRecord
from tirag.rag.chain import Clearance, RAGService
from tirag.store.base import SearchFilter
from tirag.store.pgvector import PgVectorStore

pgserver = pytest.importorskip("pgserver")
pytestmark = pytest.mark.integration

DIM = 384
GOLDEN = Path(__file__).resolve().parents[2] / "eval" / "golden_set.json"


@pytest.fixture(scope="module")
def pg_dsn(tmp_path_factory):
    server = pgserver.get_server(tmp_path_factory.mktemp("pgdata"), cleanup_mode="delete")
    yield server.get_uri()
    server.cleanup()


@pytest.fixture
def store(pg_dsn):
    s = PgVectorStore(pg_dsn, dim=DIM, pool_max=4)
    s.init_schema()
    with s._get_pool().connection() as conn:
        conn.execute("TRUNCATE ti_chunks, ti_sync_state, ti_quarantine")
    yield s
    s.close()


@pytest.fixture
def loaded(store):
    settings = make_settings(embedding_dim=DIM)
    emb = HashEmbeddings(DIM)
    for connector in fixture_connectors(settings):
        ingest_connector(connector, store, emb, settings, full=True)
    return store, emb, settings


def test_schema_is_idempotent_and_has_expected_indexes(store) -> None:
    store.init_schema()
    with store._get_pool().connection() as conn:
        idx = {
            r[0]
            for r in conn.execute("SELECT indexname FROM pg_indexes WHERE tablename='ti_chunks'")
        }
        ext = conn.execute("SELECT extversion FROM pg_extension WHERE extname='vector'").fetchone()
    assert {
        "ti_chunks_vec_idx",
        "ti_chunks_tsv_idx",
        "ti_chunks_iocs_idx",
        "ti_chunks_doc_idx",
    } <= idx
    assert ext is not None
    assert store.ping() is True


def test_dimension_mismatch_is_refused(pg_dsn, store) -> None:
    other = PgVectorStore(pg_dsn, dim=DIM * 2)
    with pytest.raises(RuntimeError, match="dimension"):
        other.init_schema()


def test_invalid_dimension_is_rejected() -> None:
    with pytest.raises(ValueError):
        PgVectorStore("postgresql://x", dim=3)


def test_fixture_ingest_matches_memory_backend_counts(loaded) -> None:
    store, _, _ = loaded
    st = store.stats()
    assert (st.chunks, st.documents, st.quarantined) == (30, 30, 1)
    assert st.by_source == {"misp": 14, "opencti": 16}
    assert store.get_state("sync:misp:last_success") and store.get_state("nope") is None


def test_reingest_is_idempotent_in_postgres(loaded) -> None:
    store, emb, settings = loaded
    for connector in fixture_connectors(settings):
        ingest_connector(connector, store, emb, settings, full=True)
    assert store.stats().chunks == 30


def test_all_three_retrieval_channels_work(loaded) -> None:
    store, emb, _ = loaded
    flt = SearchFilter(max_tlp_rank=TLP.AMBER.rank)
    ioc = store.search_iocs(["198.51.100.23"], 10, flt)
    assert ioc and all("198.51.100.23" in h.document.metadata["iocs"] for h in ioc)
    lex = store.search_lexical(["glassloader", "ransomware"], 10, flt)
    assert lex and lex[0].score > 0
    vec = store.search_vector(emb.embed_query("ransomware hospitals phishing ISO"), 5, flt)
    assert len(vec) == 5 and vec[0].score >= vec[-1].score
    assert vec[0].document.metadata["tlp_rank"] <= 2


def test_tlp_is_enforced_by_sql_on_every_channel(loaded) -> None:
    store, emb, _ = loaded
    low = SearchFilter(max_tlp_rank=TLP.AMBER.rank)
    high = SearchFilter(max_tlp_rank=TLP.RED.rank)
    assert store.search_iocs(["192.0.2.201"], 5, low) == []
    assert store.search_iocs(["192.0.2.201"], 5, high)
    assert store.search_lexical(["winterglass"], 5, low) == []
    assert store.search_lexical(["winterglass"], 5, high)
    for hit in store.search_vector(emb.embed_query("winterglass liaison signalling"), 30, low):
        assert hit.document.metadata["tlp_rank"] <= 2


def test_doc_type_and_source_filters_in_sql(loaded) -> None:
    store, _, _ = loaded
    flt = SearchFilter(
        max_tlp_rank=4, doc_types=frozenset({"report"}), sources=frozenset({"opencti"})
    )
    hits = store.search_lexical(["stormveil", "cloud", "herons"], 10, flt)
    assert hits and all(h.document.metadata["doc_type"] == "report" for h in hits)


@pytest.mark.parametrize(
    "terms",
    [
        ["'; DROP TABLE ti_chunks; --"],
        ["a' | 'b"],
        ["(((", "))) &", "!x"],
        ["\\", ":*"],
        ["x" * 500],
        [""],
    ],
)
def test_hostile_lexical_terms_cannot_break_the_tsquery_or_sql(loaded, terms) -> None:
    store, _, _ = loaded
    assert isinstance(store.search_lexical(terms, 5, SearchFilter(max_tlp_rank=4)), list)
    assert store.stats().chunks == 30  # the table is still there


def test_hostile_ioc_values_are_parameterised(loaded) -> None:
    store, _, _ = loaded
    assert (
        store.search_iocs(["x'); DROP TABLE ti_chunks;--", '"}'], 5, SearchFilter(max_tlp_rank=4))
        == []
    )
    assert store.stats().chunks == 30


def test_upsert_replaces_a_document_atomically(loaded) -> None:
    store, _, _ = loaded
    doc_id = next(iter(_doc_ids(store)))
    before = store.stats().chunks
    assert store.delete_document(doc_id) >= 1
    assert store.stats().chunks < before
    assert store.delete_document(doc_id) == 0


def test_failed_upsert_rolls_back_and_keeps_old_data(loaded) -> None:
    store, emb, _ = loaded
    from langchain_core.documents import Document

    doc_id = next(iter(_doc_ids(store)))
    n_before = store.stats().chunks
    good = Document(
        page_content="x",
        metadata={
            "chunk_id": "not-a-uuid",
            "doc_id": doc_id,
            "source": "misp",
            "source_id": "s",
            "doc_type": "report",
            "tlp": "GREEN",
            "tlp_rank": 1,
            "content_hash": "h",
        },
    )
    with pytest.raises(Exception):  # noqa: B017 - invalid uuid -> DB error
        store.upsert_document(doc_id, [good], [emb.embed_query("x")])
    assert store.stats().chunks == n_before  # the DELETE was rolled back with the failed INSERT


def test_quarantine_and_state_persistence(store) -> None:
    store.record_quarantine([QuarantineRecord("d1", 0, "ignore_instructions", "preview")])
    store.set_state("k", "v1")
    store.set_state("k", "v2")
    assert store.get_state("k") == "v2" and store.stats().quarantined == 1
    store.record_quarantine([])


def test_ping_reports_false_when_database_unreachable() -> None:
    dead = PgVectorStore("postgresql://nobody@127.0.0.1:1/none?connect_timeout=1", dim=DIM)
    assert dead.ping() is False


def test_full_rag_over_postgres_meets_the_evaluation_thresholds(loaded) -> None:
    store, emb, settings = loaded
    service = RAGService(store, emb, ScriptedChatModel(reply="", seen=[]), settings)
    from tirag.llm import ExtractiveChatModel

    service = RAGService(store, emb, ExtractiveChatModel(), settings)
    report = run_eval(GOLDEN, service)
    summary = report.summary()
    assert report.passed(0.85), (summary, report.failures())
    assert summary["tlp_leaks"] == 0 and summary["poison_leaks"] == 0


def test_postgres_enforces_tlp_in_the_chain(loaded) -> None:
    store, emb, settings = loaded
    llm = ScriptedChatModel(reply="ok [1]", seen=[])
    svc = RAGService(store, emb, llm, settings)
    svc.answer("What is staged from 192.0.2.201?", Clearance(max_tlp=TLP.AMBER))
    assert "192.0.2.201" not in "".join(str(m.content) for call in llm.seen for m in call[1:])


def _doc_ids(store: PgVectorStore):
    with store._get_pool().connection() as conn:
        return [r[0] for r in conn.execute("SELECT DISTINCT doc_id FROM ti_chunks ORDER BY 1")]
