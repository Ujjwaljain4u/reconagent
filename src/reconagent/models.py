"""
Shared data structures for ReconAgent.

Every collector returns a CollectorResult so the aggregator, correlator,
and reporter can treat all sources uniformly regardless of what API or
library produced the data underneath.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Confidence(str, Enum):
    """How much we trust a given data point / finding."""
    HIGH = "high"          # directly confirmed by an authoritative source (WHOIS, DNS)
    MEDIUM = "medium"       # inferred / cross-referenced from 2+ weak signals
    LOW = "low"             # single weak signal, unverified
    NEEDS_REVIEW = "needs_review"  # collector unsure, human should check


class Severity(str, Enum):
    """For OPSEC findings: how bad is this exposure for the target."""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class Finding:
    """A single atomic piece of intel discovered by a collector."""
    source: str                      # collector name, e.g. "domain_whois"
    category: str                    # e.g. "registrant_email", "subdomain", "gps_coordinate"
    value: Any                       # the actual data
    confidence: Confidence = Confidence.MEDIUM
    raw: dict | None = None          # original raw API response fragment, for audit
    notes: str = ""


@dataclass
class CollectorResult:
    """What every collector module returns."""
    collector: str
    target: str
    ok: bool
    findings: list[Finding] = field(default_factory=list)
    error: str | None = None
    duration_ms: int = 0


@dataclass
class OpsecFinding:
    """A flagged exposure + remediation advice, for the defensive-framing section."""
    title: str
    severity: Severity
    description: str
    remediation: str
    evidence_sources: list[str] = field(default_factory=list)


def timeit(fn):
    """Decorator: wraps a collector's run() to auto-fill duration_ms."""
    def wrapper(*args, **kwargs):
        start = time.time()
        result: CollectorResult = fn(*args, **kwargs)
        result.duration_ms = int((time.time() - start) * 1000)
        return result
    return wrapper
