from __future__ import annotations

import pytest

from tirag.models import IOCType
from tirag.security.iocs import (
    defang_text,
    extract_iocs,
    normalise_ioc,
    redact_unsupported_iocs,
    refang,
)

SHA256 = "a" * 64
SHA1 = "b" * 40
MD5 = "c" * 32


def values(text: str) -> dict[IOCType, set[str]]:
    out: dict[IOCType, set[str]] = {}
    for ioc in extract_iocs(text):
        out.setdefault(ioc.type, set()).add(ioc.value)
    return out


def test_extracts_each_ioc_type() -> None:
    text = (
        f"C2 198.51.100.23 and 2001:db8::1, domain Evil.Example.NET, "
        f"url https://Bad.example.org/Path?x=1, mail Bob@Example.com, "
        f"hashes {SHA256} {SHA1} {MD5}, CVE-2099-12345."
    )
    got = values(text)
    assert got[IOCType.IPV4] == {"198.51.100.23"}
    assert got[IOCType.IPV6] == {"2001:db8::1"}
    assert "evil.example.net" in got[IOCType.DOMAIN]
    assert got[IOCType.URL] == {"https://bad.example.org/Path?x=1"}
    assert got[IOCType.EMAIL] == {"bob@example.com"}
    assert got[IOCType.SHA256] == {SHA256}
    assert got[IOCType.SHA1] == {SHA1}
    assert got[IOCType.MD5] == {MD5}
    assert got[IOCType.CVE] == {"CVE-2099-12345"}


def test_hash_lengths_do_not_bleed_into_each_other() -> None:
    got = values(SHA256)
    assert IOCType.MD5 not in got and IOCType.SHA1 not in got


def test_url_host_is_not_double_counted_as_domain() -> None:
    got = values("see https://update-check.example.net/stage2.bin now")
    assert IOCType.URL in got
    assert IOCType.DOMAIN not in got


@pytest.mark.parametrize(
    "text", ["setup.exe", "report.pdf", "payload.dll", "run.ps1", "v1.2.3", "e.g. this"]
)
def test_filenames_and_versions_are_not_domains(text: str) -> None:
    assert extract_iocs(text) == []


def test_refang_and_defang_round_trip() -> None:
    defanged = "hxxps://evil[.]example[.]net/a and 198[.]51[.]100[.]23 and bob[@]example[.]com"
    clean = refang(defanged)
    assert "https://evil.example.net/a" in clean
    assert "198.51.100.23" in clean
    assert "bob@example.com" in clean
    again = defang_text(clean)
    assert "hxxps[://]evil[.]example[.]net/a" in again
    assert "198[.]51[.]100[.]23" in again
    assert "bob[@]example[.]com" in again
    assert "http" not in again.replace("hxxp", "")


def test_extraction_understands_defanged_input() -> None:
    assert values("beacon to 198[.]51[.]100[.]23 via hxxp://x[.]example[.]org")[IOCType.IPV4] == {
        "198.51.100.23"
    }


def test_defang_leaves_cves_hashes_and_plain_text_alone() -> None:
    text = f"CVE-2099-12345 {SHA256} is plain text."
    assert defang_text(text) == text


def test_redact_unsupported_iocs_keeps_only_allowed() -> None:
    text = "Block 198.51.100.23 and 203.0.113.9 plus evil.example.net"
    out, removed = redact_unsupported_iocs(text, {"198.51.100.23"}, "[x]")
    assert "198.51.100.23" in out
    assert "203.0.113.9" not in out and "evil.example.net" not in out
    assert sorted(removed) == ["203.0.113.9", "evil.example.net"]


def test_redaction_catches_defanged_hallucinations() -> None:
    out, removed = redact_unsupported_iocs("use 203[.]0[.]113[.]9", set(), "[x]")
    assert removed == ["203.0.113.9"] and "203" not in out


def test_normalise_ioc_cases() -> None:
    assert normalise_ioc(IOCType.SHA256, SHA256.upper()) == SHA256
    assert normalise_ioc(IOCType.CVE, "cve-2099-1234") == "CVE-2099-1234"
    assert normalise_ioc(IOCType.URL, "HTTP://EXAMPLE.com/Path") == "http://example.com/Path"
    assert normalise_ioc(IOCType.IPV6, "2001:0db8:0000:0000:0000:0000:0000:0001") == "2001:db8::1"
