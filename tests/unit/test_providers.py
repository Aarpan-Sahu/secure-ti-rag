"""Provider factories build correctly configured clients (no network calls are made)."""

from __future__ import annotations

import pytest

from tests.conftest import make_settings
from tirag.embeddings import build_embeddings
from tirag.llm import ExtractiveChatModel, build_llm


def test_bedrock_llm_is_configured_for_deterministic_bounded_output() -> None:
    s = make_settings(
        llm_provider="bedrock",
        llm_model_id="us.anthropic.claude-sonnet-4-5-20250929-v1:0",
        aws_region="eu-west-1",
        llm_max_tokens=512,
        bedrock_guardrail_id="gr-abc123",
        bedrock_guardrail_version="3",
    )
    llm = build_llm(s)
    assert llm.model_id == "us.anthropic.claude-sonnet-4-5-20250929-v1:0"
    assert llm.region_name == "eu-west-1" and llm.temperature == 0.0 and llm.max_tokens == 512
    assert llm.guardrail_config == {"guardrailIdentifier": "gr-abc123", "guardrailVersion": "3"}


def test_bedrock_llm_without_guardrail_omits_the_config() -> None:
    assert build_llm(make_settings(llm_provider="bedrock")).guardrail_config is None


def test_bedrock_embeddings_request_normalised_vectors_of_the_configured_size() -> None:
    emb = build_embeddings(make_settings(embedding_provider="bedrock", embedding_dim=1024))
    assert emb.model_id == "amazon.titan-embed-text-v2:0"
    assert emb.model_kwargs == {"dimensions": 1024, "normalize": True}


def test_anthropic_provider_and_extractive_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key-not-real")
    llm = build_llm(make_settings(llm_provider="anthropic", llm_model_id="claude-sonnet-4-5"))
    assert llm.temperature == 0.0
    assert isinstance(build_llm(make_settings()), ExtractiveChatModel)


def test_unknown_providers_are_refused() -> None:
    from tirag.config import Settings

    s = make_settings()
    object.__setattr__(s, "llm_provider", "magic")
    object.__setattr__(s, "embedding_provider", "magic")
    with pytest.raises(ValueError):
        build_llm(s)
    with pytest.raises(ValueError):
        build_embeddings(s)
    assert Settings  # imported for type reference only
