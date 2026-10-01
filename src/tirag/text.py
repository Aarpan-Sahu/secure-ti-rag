"""Tokenisation helpers shared by the embedder, the lexical index and the retriever."""

from __future__ import annotations

import re

_TOKEN = re.compile(r"[a-z0-9][a-z0-9_\-.]*[a-z0-9]|[a-z0-9]", re.IGNORECASE)

STOPWORDS = frozenset(
    [
        "a",
        "an",
        "and",
        "are",
        "as",
        "at",
        "be",
        "been",
        "but",
        "by",
        "can",
        "could",
        "did",
        "do",
        "does",
        "for",
        "from",
        "had",
        "has",
        "have",
        "how",
        "i",
        "if",
        "in",
        "into",
        "is",
        "it",
        "its",
        "me",
        "my",
        "of",
        "on",
        "or",
        "our",
        "over",
        "say",
        "says",
        "she",
        "should",
        "so",
        "than",
        "that",
        "the",
        "their",
        "them",
        "then",
        "there",
        "these",
        "they",
        "this",
        "those",
        "to",
        "us",
        "was",
        "we",
        "were",
        "what",
        "when",
        "where",
        "which",
        "who",
        "whom",
        "why",
        "will",
        "with",
        "would",
        "you",
        "your",
        "about",
        "any",
        "all",
        "also",
        "we",
        "know",
        "tell",
        "give",
        "show",
        "list",
        "find",
        "use",
        "used",
        "uses",
        "using",
        "does",
        "do",
    ]
)


def tokenize(text: str) -> list[str]:
    """Lower-case tokens; dots/hyphens inside a token are kept so IPs and hostnames stay whole."""
    return [t.lower().strip(".-_") for t in _TOKEN.findall(text) if t.strip(".-_")]


def content_terms(text: str) -> list[str]:
    """Tokens with stop-words removed, de-duplicated, order preserved."""
    seen: set[str] = set()
    terms: list[str] = []
    for tok in tokenize(text):
        if tok in STOPWORDS or len(tok) < 2 or tok in seen:
            continue
        seen.add(tok)
        terms.append(tok)
    return terms


_CONCEPT_GROUPS: tuple[tuple[frozenset[str], frozenset[str]], ...] = (
    # (query terms that must all be present, equivalent tokens as written in CTI reports)
    (
        frozenset({"command", "control"}),
        frozenset({"command", "control", "command-and-control", "c2", "cnc"}),
    ),
    (frozenset({"indicators"}), frozenset({"indicator", "indicators", "ioc", "iocs"})),
    (frozenset({"indicator"}), frozenset({"indicator", "indicators", "ioc", "iocs"})),
    (frozenset({"ioc"}), frozenset({"indicator", "indicators", "ioc", "iocs"})),
    (frozenset({"iocs"}), frozenset({"indicator", "indicators", "ioc", "iocs"})),
)


def query_concepts(terms: list[str]) -> list[frozenset[str]]:
    """Group query terms into *concepts*: sets of interchangeable tokens.

    "command and control" is written "C2" in nearly every report and "indicators of compromise"
    is "IOC". Treating such phrases as one concept (matched if ANY alternative appears) keeps the
    lexical channel and the relevance gate from penalising ordinary phrasing differences.
    """
    present = set(terms)
    used: set[str] = set()
    concepts: list[frozenset[str]] = []
    for required, alternatives in _CONCEPT_GROUPS:
        if required <= present and not (required & used):
            concepts.append(alternatives)
            used |= required
    concepts.extend(frozenset({t}) for t in terms if t not in used)
    return concepts
