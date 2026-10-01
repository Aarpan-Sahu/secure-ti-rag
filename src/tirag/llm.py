"""Chat-model providers.

* ``bedrock``    - Anthropic Claude on Amazon Bedrock via ``ChatBedrockConverse`` (production). IAM
  role credentials only; an optional Bedrock Guardrail is attached when configured.
* ``anthropic``  - Anthropic API (needs ``ANTHROPIC_API_KEY``).
* ``extractive`` - deterministic, offline *extractive* model: it selects the most relevant
  evidence sentences and cites them. It is NOT a generative LLM; it exists so the full pipeline
  (retrieval, guardrails, citations, API) can run in CI and on a laptop without credentials, and
  it makes the evaluation harness reproducible.
"""

from __future__ import annotations

import re
from typing import Any

from langchain_core.callbacks import CallbackManagerForLLMRun
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage, BaseMessage
from langchain_core.outputs import ChatGeneration, ChatResult

from tirag.config import Settings
from tirag.rag.prompts import NO_EVIDENCE_ANSWER
from tirag.text import content_terms

_DOC_RE = re.compile(r'<document index="(\d+)"[^>]*>\n?(.*?)\n?</document>', re.DOTALL)
_QUESTION_RE = re.compile(r"Analyst question:\s*(.+)\Z", re.DOTALL)
_SENTENCE_SPLIT = re.compile(r"(?<=[.!?])\s+|\n+")


class ExtractiveChatModel(BaseChatModel):
    """Selects and cites the best-matching evidence sentences (no generation)."""

    max_sentences: int = 5

    @property
    def _llm_type(self) -> str:
        return "tirag-extractive"

    def _generate(
        self,
        messages: list[BaseMessage],
        stop: list[str] | None = None,
        run_manager: CallbackManagerForLLMRun | None = None,
        **kwargs: Any,
    ) -> ChatResult:
        human = next((m for m in reversed(messages) if m.type == "human"), None)
        text = human.content if human is not None and isinstance(human.content, str) else ""
        q_match = _QUESTION_RE.search(text)
        terms = set(content_terms(q_match.group(1))) if q_match else set()

        scored: list[tuple[float, int, str]] = []
        for index, body in _DOC_RE.findall(text):
            header, _, rest = body.partition("\n")
            title_overlap = len(terms.intersection(content_terms(header)))
            for pos, sentence in enumerate(_SENTENCE_SPLIT.split(rest)):
                sentence = sentence.strip(" -\t")
                if len(sentence) < 20:
                    continue
                overlap = len(terms.intersection(content_terms(sentence)))
                score = overlap + 0.5 * title_overlap
                if score > 0:
                    # earlier documents / sentences win ties
                    scored.append((score - 0.001 * int(index) - 0.0001 * pos, int(index), sentence))
        scored.sort(key=lambda t: -t[0])
        picked: list[tuple[int, str]] = []
        seen: set[str] = set()
        for _score, index, sentence in scored:
            key = sentence.lower()
            if key in seen:
                continue
            seen.add(key)
            picked.append((index, sentence))
            if len(picked) >= self.max_sentences:
                break

        answer = (
            "\n".join(f"- {sentence} [{index}]" for index, sentence in picked)
            if picked
            else NO_EVIDENCE_ANSWER
        )
        return ChatResult(generations=[ChatGeneration(message=AIMessage(content=answer))])


def build_llm(settings: Settings) -> BaseChatModel:
    provider = settings.llm_provider
    if provider == "extractive":
        return ExtractiveChatModel()
    if provider == "bedrock":
        from botocore.config import Config
        from langchain_aws import ChatBedrockConverse

        kwargs: dict[str, Any] = {}
        if settings.bedrock_guardrail_id:
            kwargs["guardrail_config"] = {
                "guardrailIdentifier": settings.bedrock_guardrail_id,
                "guardrailVersion": settings.bedrock_guardrail_version,
            }
        return ChatBedrockConverse(
            model=settings.llm_model_id,
            region_name=settings.aws_region,
            temperature=0.0,
            max_tokens=settings.llm_max_tokens,
            config=Config(
                read_timeout=int(settings.llm_timeout_seconds),
                connect_timeout=5,
                retries={"max_attempts": 3, "mode": "adaptive"},
            ),
            **kwargs,
        )
    if provider == "anthropic":
        from langchain_anthropic import ChatAnthropic

        return ChatAnthropic(
            model=settings.llm_model_id,
            temperature=0.0,
            max_tokens=settings.llm_max_tokens,
            timeout=settings.llm_timeout_seconds,
            max_retries=2,
        )
    raise ValueError(f"unsupported llm provider: {provider}")
