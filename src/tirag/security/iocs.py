"""Indicator-of-compromise extraction, refanging and defanging.

IOCs are the one place where embeddings alone are unreliable (a hash or an IP address has no
"meaning"), so the pipeline extracts them with strict patterns and indexes them for exact match.
Output is defanged by default so an analyst cannot accidentally click a live malicious URL.
"""

from __future__ import annotations

import ipaddress
import re

from tirag.models import IOC, IOCType

# Common file extensions that look like TLDs ("setup.exe", "report.pdf"): never domains.
_FILE_EXTENSIONS = frozenset(
    "exe dll sys bat cmd ps1 psm1 vbs vbe js jse jar py pl rb sh zip rar gz tar tgz iso img lnk "
    "doc docx docm xls xlsx xlsm ppt pptx pdf rtf txt log csv json xml yml yaml html htm php asp "
    "aspx png jpg jpeg gif svg bmp ico dat bin tmp cfg ini conf md".split()
)

_RE_SHA256 = re.compile(r"(?<![A-Fa-f0-9])[A-Fa-f0-9]{64}(?![A-Fa-f0-9])")
_RE_SHA1 = re.compile(r"(?<![A-Fa-f0-9])[A-Fa-f0-9]{40}(?![A-Fa-f0-9])")
_RE_MD5 = re.compile(r"(?<![A-Fa-f0-9])[A-Fa-f0-9]{32}(?![A-Fa-f0-9])")
_RE_URL = re.compile(r"\bhttps?://[^\s<>\"'`\\)\]]+", re.IGNORECASE)
_RE_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,24}\b")
_RE_IPV4 = re.compile(
    r"(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
    r"(?![\d])"
)
_RE_IPV6 = re.compile(r"(?<![A-Fa-f0-9:])(?:[A-Fa-f0-9]{0,4}:){2,7}[A-Fa-f0-9]{0,4}(?![A-Fa-f0-9:])")
_RE_DOMAIN = re.compile(
    r"\b(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,24}\b"
)
_RE_CVE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)

_REFANG_RULES: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"\bhxxp(s?)", re.IGNORECASE), r"http\1"),
    (re.compile(r"\bh\*\*p(s?)", re.IGNORECASE), r"http\1"),
    (re.compile(r"\[\s*://\s*\]|\[:\s*//\s*\]"), "://"),
    (re.compile(r"\[\s*\.\s*\]|\(\s*\.\s*\)|\{\s*\.\s*\}|\[dot\]|\(dot\)", re.IGNORECASE), "."),
    (re.compile(r"\[\s*:\s*\]"), ":"),
    (re.compile(r"\[\s*@\s*\]|\[at\]|\(at\)", re.IGNORECASE), "@"),
)


def refang(text: str) -> str:
    """Undo the common defanging conventions (hxxp, [.], [:], [@])."""
    for pattern, repl in _REFANG_RULES:
        text = pattern.sub(repl, text)
    return text


def _valid_ipv6(candidate: str) -> bool:
    if candidate.count(":") < 2:
        return False
    try:
        ipaddress.IPv6Address(candidate)
    except ValueError:
        return False
    return True


def _normalise_domain(value: str) -> str:
    return value.lower().rstrip(".")


def normalise_ioc(ioc_type: IOCType, value: str) -> str:
    value = refang(value.strip())
    if ioc_type in (IOCType.MD5, IOCType.SHA1, IOCType.SHA256, IOCType.DOMAIN, IOCType.EMAIL):
        return _normalise_domain(value) if ioc_type == IOCType.DOMAIN else value.lower()
    if ioc_type == IOCType.CVE:
        return value.upper()
    if ioc_type == IOCType.IPV6:
        return str(ipaddress.IPv6Address(value))
    if ioc_type == IOCType.URL:
        # Scheme and host are case-insensitive; the path is not.
        match = re.match(r"(?i)(https?)://([^/\s?#]+)(.*)", value)
        if match:
            return f"{match.group(1).lower()}://{match.group(2).lower()}{match.group(3)}"
    return value


def _spans(text: str) -> list[tuple[int, int, IOCType, str]]:
    """Return non-overlapping (start, end, type, normalised value) matches, most specific first."""
    taken: list[tuple[int, int]] = []
    found: list[tuple[int, int, IOCType, str]] = []

    def free(start: int, end: int) -> bool:
        return all(end <= s or start >= e for s, e in taken)

    def add(start: int, end: int, ioc_type: IOCType, value: str) -> None:
        if free(start, end):
            taken.append((start, end))
            found.append((start, end, ioc_type, normalise_ioc(ioc_type, value)))

    for regex, ioc_type in (
        (_RE_URL, IOCType.URL),
        (_RE_EMAIL, IOCType.EMAIL),
        (_RE_SHA256, IOCType.SHA256),
        (_RE_SHA1, IOCType.SHA1),
        (_RE_MD5, IOCType.MD5),
        (_RE_CVE, IOCType.CVE),
        (_RE_IPV4, IOCType.IPV4),
    ):
        for m in regex.finditer(text):
            value = m.group(0).rstrip(".,;:")
            add(m.start(), m.start() + len(value), ioc_type, value)

    for m in _RE_IPV6.finditer(text):
        if _valid_ipv6(m.group(0)):
            add(m.start(), m.end(), IOCType.IPV6, m.group(0))

    for m in _RE_DOMAIN.finditer(text):
        value = m.group(0)
        tld = value.rsplit(".", 1)[-1].lower()
        if tld in _FILE_EXTENSIONS or tld.isdigit():
            continue
        add(m.start(), m.end(), IOCType.DOMAIN, value)

    found.sort(key=lambda t: t[0])
    return found


def extract_iocs(text: str) -> list[IOC]:
    """Extract unique, normalised IOCs from free text (refanging it first)."""
    seen: set[tuple[IOCType, str]] = set()
    result: list[IOC] = []
    for _, _, ioc_type, value in _spans(refang(text)):
        key = (ioc_type, value)
        if key not in seen:
            seen.add(key)
            result.append(IOC(ioc_type, value))
    return result


def _defang_value(ioc_type: IOCType, value: str) -> str:
    if ioc_type == IOCType.URL:
        value = re.sub(r"(?i)^http", "hxxp", value)
        return value.replace("://", "[://]", 1).replace(".", "[.]")
    if ioc_type == IOCType.EMAIL:
        return value.replace("@", "[@]").replace(".", "[.]")
    if ioc_type in (IOCType.IPV4, IOCType.DOMAIN):
        return value.replace(".", "[.]")
    return value


def defang_text(text: str) -> str:
    """Defang network indicators (URLs, IPs, domains, e-mail) in free text."""
    text = refang(text)
    out: list[str] = []
    cursor = 0
    for start, end, ioc_type, _ in _spans(text):
        out.append(text[cursor:start])
        out.append(_defang_value(ioc_type, text[start:end]))
        cursor = end
    out.append(text[cursor:])
    return "".join(out)


def redact_unsupported_iocs(text: str, allowed: set[str], placeholder: str) -> tuple[str, list[str]]:
    """Replace any IOC in ``text`` whose normalised value is not in ``allowed``.

    Used on LLM output: an indicator that is not present in the retrieved evidence (or in the
    analyst's own question) is treated as hallucinated and must never reach a blocklist.
    CVE identifiers are exempt from redaction only if they are in ``allowed`` as well.
    """
    text = refang(text)
    removed: list[str] = []
    out: list[str] = []
    cursor = 0
    for start, end, _ioc_type, value in _spans(text):
        out.append(text[cursor:start])
        if value in allowed:
            out.append(text[start:end])
        else:
            out.append(placeholder)
            removed.append(value)
        cursor = end
    out.append(text[cursor:])
    return "".join(out), removed
