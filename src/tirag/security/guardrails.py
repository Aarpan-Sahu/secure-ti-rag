"""Input and output guardrails around the LLM.

Input  : validate size/characters of the analyst query and reject prompt-injection attempts.
Output : the model is *not trusted*. Its answer is validated before it reaches the analyst:

* markup, markdown images and links are stripped (blocks image-URL data exfiltration),
* credential-shaped strings are redacted,
* any IOC that is not present in the retrieved evidence (or the analyst's own question) is
  redacted - a hallucinated IP or hash on a blocklist is an operational hazard,
* network IOCs are defanged so they cannot be clicked or auto-linked.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from tirag.config import Settings
from tirag.security.iocs import defang_text, extract_iocs, redact_unsupported_iocs, refang
from tirag.security.sanitize import clean_text, scan_injection

IOC_PLACEHOLDER = "[unsupported-indicator-removed]"
SECRET_PLACEHOLDER = "[redacted-secret]"  # noqa: S105  # nosec B105 - marker text, not a credential

_SECRET_PATTERNS = (
    re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    re.compile(
        r"-----BEGIN [A-Z ]*PRIVATE KEY-----(?:.|\n)*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)"
    ),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),
    re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
    re.compile(r"(?i)\bbearer\s+[a-z0-9\-._~+/]{20,}=*"),
    re.compile(r"(?i)\b(?:api[_-]?key|secret|password|token)\s*[:=]\s*['\"]?[A-Za-z0-9/+_\-]{16,}"),
)
_MD_IMAGE = re.compile(r"!\[[^\]]*\]\([^)]*\)")
_MD_LINK = re.compile(r"\[([^\]]+)\]\((?:https?:|//|javascript:|data:)[^)]*\)", re.IGNORECASE)
_HTML_TAG = re.compile(r"</?[A-Za-z][^>]{0,200}>")


@dataclass
class QueryCheck:
    allowed: bool
    query: str
    flags: list[str] = field(default_factory=list)
    reason: str | None = None


def check_query(raw: str, settings: Settings) -> QueryCheck:
    flags: list[str] = []
    if len(raw) > settings.max_query_chars:
        return QueryCheck(False, "", ["too_long"], "query exceeds maximum length")
    cleaned = clean_text(raw, settings.max_query_chars)
    if cleaned != raw.strip():
        flags.append("query_normalised")
    if len(cleaned) < 3:
        return QueryCheck(False, "", [*flags, "empty"], "query is empty")
    scan = scan_injection(cleaned)
    if scan.flagged:
        return QueryCheck(
            False, "", [*flags, "prompt_injection", *scan.matches], "query rejected by input policy"
        )
    return QueryCheck(True, cleaned, flags)


@dataclass
class OutputCheck:
    text: str
    flags: list[str] = field(default_factory=list)


def sanitize_output(answer: str, allowed_iocs: set[str], settings: Settings) -> OutputCheck:
    flags: list[str] = []
    text = clean_text(refang(answer), settings.max_answer_chars * 2)

    stripped = _MD_IMAGE.sub("[image removed]", text)
    stripped = _MD_LINK.sub(r"\1", stripped)
    stripped = _HTML_TAG.sub("", stripped)
    if stripped != text:
        flags.append("markup_removed")
    text = stripped

    for pattern in _SECRET_PATTERNS:
        text, n = pattern.subn(SECRET_PLACEHOLDER, text)
        if n:
            flags.append("secret_redacted")

    text, removed = redact_unsupported_iocs(text, allowed_iocs, IOC_PLACEHOLDER)
    if removed:
        flags.append("unsupported_iocs_redacted")

    if settings.defang_output:
        text = defang_text(text)

    if len(text) > settings.max_answer_chars:
        text = text[: settings.max_answer_chars].rstrip() + " [truncated]"
        flags.append("truncated")
    return OutputCheck(text.strip(), flags)


def allowed_iocs_for(contexts: list[str], question: str) -> set[str]:
    allowed = {i.value for text in contexts for i in extract_iocs(text)}
    allowed.update(i.value for i in extract_iocs(question))
    return allowed
