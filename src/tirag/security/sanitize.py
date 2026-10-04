"""Sanitisation and prompt-injection screening for untrusted text.

Threat-intelligence feeds are *untrusted input*: community MISP instances and OpenCTI connectors
ingest content authored by third parties, and an attacker who can get a poisoned report into a
feed can try to steer the analyst-facing LLM (indirect prompt injection / RAG poisoning).
These helpers implement the first two layers of defence:

1. ``clean_text``  - remove invisible / control / bidi characters and active markup.
2. ``scan_injection`` - weighted pattern scoring; chunks above the threshold are quarantined at
   ingest time and analyst queries above the threshold are rejected.

Pattern matching is a *heuristic* layer, not a guarantee. It is combined with prompt-structure
isolation, output validation and TLP filtering (see ``tirag.rag`` and ``docs/security.md``).
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass

# Unicode categories removed from text: control (Cc, except \n and \t), format (Cf: zero-width
# joiners, bidi overrides, tag characters), private use (Co), surrogates (Cs), unassigned (Cn).
_STRIP_CATEGORIES = frozenset({"Cc", "Cf", "Co", "Cs", "Cn"})
_KEEP_CONTROL = frozenset({"\n", "\t"})

_RE_HTML_COMMENT = re.compile(r"<!--.*?-->", re.DOTALL)
_RE_ACTIVE_BLOCK = re.compile(
    r"<\s*(script|style|iframe|object|embed|template)\b.*?<\s*/\s*\1\s*>", re.DOTALL | re.IGNORECASE
)
_RE_MANY_NEWLINES = re.compile(r"\n{3,}")
_RE_MANY_SPACES = re.compile(r"[ \t]{3,}")


def clean_text(text: str, max_len: int = 200_000) -> str:
    """Normalise untrusted text: drop invisible characters, HTML comments and active markup."""
    text = unicodedata.normalize("NFC", text)
    text = "".join(
        ch
        for ch in text
        if ch in _KEEP_CONTROL or unicodedata.category(ch) not in _STRIP_CATEGORIES
    )
    text = _RE_HTML_COMMENT.sub(" ", text)
    text = _RE_ACTIVE_BLOCK.sub(" ", text)
    text = _RE_MANY_SPACES.sub("  ", text)
    text = _RE_MANY_NEWLINES.sub("\n\n", text)
    return text.strip()[:max_len]


@dataclass(frozen=True)
class _Pattern:
    name: str
    weight: int
    regex: re.Pattern[str]


def _p(name: str, weight: int, pattern: str) -> _Pattern:
    return _Pattern(name, weight, re.compile(pattern, re.IGNORECASE | re.MULTILINE | re.DOTALL))


_PATTERNS: tuple[_Pattern, ...] = (
    _p(
        "ignore_instructions",
        3,
        r"\b(ignore|disregard|forget|override|bypass)\b[^.\n]{0,40}\b(previous|prior|above|earlier|"
        r"all|any|your|the|these|those)\b[^.\n]{0,30}\b(instructions?|prompts?|rules?|guidelines?|"
        r"directives?|constraints?|context|polic(?:y|ies))\b",
    ),
    _p(
        "reveal_system_prompt",
        3,
        r"\b(reveal|print|show|repeat|output|display|leak|disclose)(?:s|ing|ed)?\b[^.\n]{0,30}"
        r"\b(system|hidden|initial|original|developer)\b[^.\n]{0,15}\b(prompt|instructions?|message)\b",
    ),
    _p(
        "chat_template_tokens",
        3,
        r"<\|?\s*(im_start|im_end|system|endoftext|assistant)\s*\|?>|\[/?INST\]|<<\s*/?SYS\s*>>",
    ),
    _p(
        "exfiltrate_secrets",
        3,
        r"\b(send|post|upload|exfiltrate|forward|transmit|email|leak)\b[^.\n]{0,80}"
        r"\b(api[ _-]?keys?|tokens?|secrets?|credentials?|passwords?)\b[^.\n]{0,40}"
        r"(\bto\b[^.\n]{0,20}(https?://|\S+@\S+\.\S+)|https?://)",
    ),
    _p(
        "exfiltrate_context",
        3,
        r"\b(send|post|upload|exfiltrate|forward|transmit|email|leak)\b[^.\n]{0,80}"
        r"\b(system prompt|conversation)\b",
    ),
    # Analysts legitimately ask how actors steal credentials, so the bare verb + noun is only a
    # weak signal; it needs a second indicator (or a destination, above) to reach the threshold.
    _p(
        "secret_exfil_topic",
        1,
        r"\b(send|post|upload|exfiltrate|forward|transmit|email|leak)\b[^.\n]{0,80}"
        r"\b(api[ _-]?keys?|tokens?|secrets?|credentials?|passwords?)\b",
    ),
    _p(
        "conceal_from_user",
        3,
        r"\bdo not (tell|inform|mention|reveal|alert|notify)\b[^.\n]{0,30}\b(the )?(user|analyst|human|operator)\b",
    ),
    _p(
        "role_hijack",
        2,
        r"\byou are (now|no longer)\b|\bact as (if you are |a |an )?(?!a (member|part))",
    ),
    _p("role_prefix", 2, r"(?:^|[.!?]\s+)\s*(system|assistant|developer)\s*:"),
    _p(
        "disable_safety",
        2,
        r"\b(disable|ignore|remove|turn off|bypass)\b[^.\n]{0,20}\b(safety|safeguards?|guardrails?|"
        r"content filters?|restrictions)\b",
    ),
    _p(
        "jailbreak_terms",
        2,
        r"\bjailbreak(ed)?\b|\bDAN mode\b|\bdeveloper mode\b|\bprompt injection payload\b",
    ),
    _p(
        "tool_or_url_directive",
        2,
        r"\b(call|invoke|run|execute|use)\b[^.\n]{0,30}\b(tool|function|command|shell|curl|wget)\b",
    ),
    _p(
        "disable_security",
        1,
        r"\b(disable|turn off|bypass|stop)\b[^.\n]{0,30}\b(edr|antivirus|logging|monitoring|firewall|security)\b",
    ),
    _p("ai_self_reference", 1, r"\bas an ai( language model)?\b"),
)

#: Score at (or above) which text is treated as an injection attempt.
INJECTION_THRESHOLD = 3


@dataclass(frozen=True)
class InjectionScan:
    score: int
    matches: tuple[str, ...]

    @property
    def flagged(self) -> bool:
        return self.score >= INJECTION_THRESHOLD


# Lookalike letters (Cyrillic / Greek) that attackers substitute to dodge keyword matching.
_CONFUSABLES = str.maketrans(
    "аеорсухіјԁѕԛɡАЕОРСУХІЈЅαεορυνκ",
    "aeopcyxijdsqgAEOPCYXIJSaeopyvk",
)


def _fold(text: str) -> str:
    """Fold compatibility forms (full-width etc.) and common homoglyphs to plain ASCII lookalikes."""
    return unicodedata.normalize("NFKC", text).translate(_CONFUSABLES)


def scan_injection(text: str) -> InjectionScan:
    """Score ``text`` for prompt-injection indicators (heuristic)."""
    text = _fold(text)
    score = 0
    matches: list[str] = []
    for pattern in _PATTERNS:
        if pattern.regex.search(text):
            score += pattern.weight
            matches.append(pattern.name)
    return InjectionScan(score=score, matches=tuple(matches))


def escape_for_prompt(text: str) -> str:
    """Neutralise angle brackets so retrieved text cannot close or open prompt delimiters."""
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
