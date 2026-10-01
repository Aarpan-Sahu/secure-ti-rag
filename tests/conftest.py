from __future__ import annotations

from typing import Any

import pytest
from langchain_core.callbacks import CallbackManagerForLLMRun
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage, BaseMessage
from langchain_core.outputs import ChatGeneration, ChatResult
from pydantic import Field

from tirag.config import Settings
from tirag.evalkit import build_eval_service
from tirag.rag.chain import RAGService


def make_settings(**overrides: Any) -> Settings:
    base: dict[str, Any] = {"env": "test", "auth_mode": "disabled"}
    base.update(overrides)
    return Settings(_env_file=None, **base)  # type: ignore[call-arg]


class ScriptedChatModel(BaseChatModel):
    """Returns a fixed reply (or raises) and records every prompt it receives."""

    reply: str = ""
    error: bool = False
    seen: list[list[BaseMessage]] = Field(default_factory=list)

    @property
    def _llm_type(self) -> str:
        return "scripted"

    def _generate(
        self,
        messages: list[BaseMessage],
        stop: list[str] | None = None,
        run_manager: CallbackManagerForLLMRun | None = None,
        **kwargs: Any,
    ) -> ChatResult:
        self.seen.append(messages)
        if self.error:
            raise RuntimeError("simulated provider outage")
        return ChatResult(generations=[ChatGeneration(message=AIMessage(content=self.reply))])


@pytest.fixture
def settings() -> Settings:
    return make_settings()


@pytest.fixture(scope="session")
def fixture_service() -> RAGService:
    """The real pipeline over the synthetic fixtures (memory store, hash embeddings)."""
    service, _store, _settings = build_eval_service()
    return service


@pytest.fixture
def scripted_service(fixture_service: RAGService):
    """Factory: the fixture index with a scripted LLM, for testing output guardrails."""

    def factory(reply: str = "", error: bool = False) -> tuple[RAGService, ScriptedChatModel]:
        llm = ScriptedChatModel(reply=reply, error=error, seen=[])
        svc = RAGService(
            fixture_service.store, fixture_service.embeddings, llm, fixture_service.settings
        )
        return svc, llm

    return factory
