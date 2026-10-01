"""Domain model shared by connectors, the ingestion pipeline, stores and the RAG chain."""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


class TLP(str, enum.Enum):
    """Traffic Light Protocol 2.0 labels, ordered from least to most restrictive."""

    CLEAR = "CLEAR"
    GREEN = "GREEN"
    AMBER = "AMBER"
    AMBER_STRICT = "AMBER+STRICT"
    RED = "RED"

    @property
    def rank(self) -> int:
        return _TLP_RANK[self]

    @classmethod
    def from_rank(cls, rank: int) -> TLP:
        for tlp, value in _TLP_RANK.items():
            if value == rank:
                return tlp
        raise ValueError(f"invalid TLP rank: {rank}")

    @classmethod
    def parse(cls, raw: str | None, default: TLP | None = None) -> TLP:
        """Parse labels such as ``tlp:white``, ``TLP:AMBER+STRICT`` or ``amber``.

        Unknown or missing labels fall back to ``default`` (which itself defaults to
        AMBER, i.e. fail towards the more restrictive side).
        """
        if raw:
            norm = raw.strip().lower().removeprefix("tlp:").replace("_", "+").replace(" ", "")
            norm = norm.replace("amber-strict", "amber+strict")
            mapping = {
                "white": cls.CLEAR,
                "clear": cls.CLEAR,
                "green": cls.GREEN,
                "amber": cls.AMBER,
                "amber+strict": cls.AMBER_STRICT,
                "red": cls.RED,
            }
            if norm in mapping:
                return mapping[norm]
        return default if default is not None else cls.AMBER

    @classmethod
    def most_restrictive(cls, labels: list[TLP], default: TLP | None = None) -> TLP:
        if not labels:
            return default if default is not None else cls.AMBER
        return max(labels, key=lambda t: t.rank)


_TLP_RANK = {
    TLP.CLEAR: 0,
    TLP.GREEN: 1,
    TLP.AMBER: 2,
    TLP.AMBER_STRICT: 3,
    TLP.RED: 4,
}


class DocType(str, enum.Enum):
    EVENT = "event"  # MISP event summary / narrative
    INDICATOR = "indicator"  # IOC sets
    THREAT_ACTOR = "threat_actor"
    INTRUSION_SET = "intrusion_set"
    MALWARE = "malware"
    CAMPAIGN = "campaign"
    REPORT = "report"


class IOCType(str, enum.Enum):
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    DOMAIN = "domain"
    URL = "url"
    EMAIL = "email"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"
    CVE = "cve"


@dataclass(frozen=True)
class IOC:
    type: IOCType
    value: str  # normalised: refanged, lower-cased where case-insensitive


@dataclass
class ThreatDoc:
    """A normalised threat-intelligence object, independent of its source system."""

    source: str  # "misp" | "opencti" | "fixture"
    source_id: str
    doc_type: DocType
    title: str
    text: str
    tlp: TLP
    url: str | None = None
    created: datetime | None = None
    modified: datetime | None = None
    labels: list[str] = field(default_factory=list)
    iocs: list[IOC] = field(default_factory=list)
    extra: dict[str, Any] = field(default_factory=dict)

    @property
    def doc_id(self) -> str:
        return f"{self.source}:{self.doc_type.value}:{self.source_id}"


@dataclass
class QuarantineRecord:
    doc_id: str
    chunk_idx: int
    reason: str
    preview: str


@dataclass
class IngestReport:
    source: str
    documents_seen: int = 0
    documents_indexed: int = 0
    documents_skipped: int = 0
    chunks_indexed: int = 0
    chunks_quarantined: int = 0
    errors: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "documents_seen": self.documents_seen,
            "documents_indexed": self.documents_indexed,
            "documents_skipped": self.documents_skipped,
            "chunks_indexed": self.chunks_indexed,
            "chunks_quarantined": self.chunks_quarantined,
            "errors": self.errors,
        }
