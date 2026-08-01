"""
Correlator: takes the raw pile of Findings from every collector and looks
for cross-source agreement — e.g. WHOIS registrant country + phone region +
IP geolocation all pointing at India raises confidence that's a real signal
rather than 3 independent coincidences. This is the "beyond limits" value-add
layer: correlation logic, not extra data sources.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass

from reconagent.models import CollectorResult, Confidence


@dataclass
class CorrelationEdge:
    """A link between two findings from different sources that agree."""
    left_source: str
    left_category: str
    right_source: str
    right_category: str
    shared_value: str
    strength: str  # "exact" | "partial"


@dataclass
class CorrelationReport:
    edges: list[CorrelationEdge]
    location_candidates: list[dict]  # merged geo signals with a combined confidence


LOCATION_CATEGORIES = {
    "registrant_country", "region", "ip_country", "ip_city", "ip_region",
    "gps_coordinate", "approx_address", "ip_gps_estimate", "stated_location",
}


def correlate(results: list[CollectorResult]) -> CorrelationReport:
    edges: list[CorrelationEdge] = []
    location_signals: list[dict] = []

    # Flatten all findings with their source collector tagged
    flat = []
    for r in results:
        if not r.ok:
            continue
        for f in r.findings:
            flat.append((r.collector, f))

    # naive but effective: normalize text values, compare pairwise for exact/substring match
    for i in range(len(flat)):
        src_a, finding_a = flat[i]
        for j in range(i + 1, len(flat)):
            src_b, finding_b = flat[j]
            if src_a == src_b:
                continue
            match = _values_overlap(finding_a.value, finding_b.value)
            if match:
                edges.append(CorrelationEdge(
                    left_source=src_a, left_category=finding_a.category,
                    right_source=src_b, right_category=finding_b.category,
                    shared_value=match, strength="exact",
                ))

        if finding_a.category in LOCATION_CATEGORIES:
            location_signals.append({
                "source": src_a,
                "category": finding_a.category,
                "value": finding_a.value,
            })

    # Group location signals into a single confidence-scored cluster.
    # More independent sources agreeing on the same rough location -> higher confidence.
    location_candidates = _cluster_locations(location_signals)

    return CorrelationReport(edges=edges, location_candidates=location_candidates)


def _values_overlap(a, b) -> str | None:
    """Returns the shared string if two finding values meaningfully overlap.
    Uses fuzzy token-set matching (rapidfuzz) rather than plain substring
    checks — the old approach missed genuinely related location signals
    like "Gurugram" vs "Gurgaon, Haryana" (same city, different naming/
    formatting) since neither is a literal substring of the other."""
    a_str = str(a).lower().strip()
    b_str = str(b).lower().strip()
    if not a_str or not b_str or len(a_str) < 3:
        return None
    if a_str == b_str:
        return a_str
    if a_str in b_str or b_str in a_str:
        return a_str if len(a_str) < len(b_str) else b_str

    try:
        from rapidfuzz import fuzz
        score = fuzz.token_set_ratio(a_str, b_str)
        if score >= 80:  # tuned to catch real near-matches without over-matching unrelated short strings
            return a_str if len(a_str) < len(b_str) else b_str
    except ImportError:
        pass  # rapidfuzz not installed — fall back to exact/substring only, still functional
    return None


def _cluster_locations(signals: list[dict]) -> list[dict]:
    """Groups location-ish findings by rough textual similarity and assigns a
    confidence tier by number of independent sources agreeing."""
    if not signals:
        return []

    buckets: dict[str, list[dict]] = defaultdict(list)
    for s in signals:
        key = str(s["value"]).lower()[:20]  # coarse bucketing key
        buckets[key].append(s)

    candidates = []
    for _key, group in buckets.items():
        sources = {g["source"] for g in group}
        if len(sources) >= 3:
            confidence = Confidence.HIGH
        elif len(sources) == 2:
            confidence = Confidence.MEDIUM
        else:
            confidence = Confidence.LOW
        candidates.append({
            "value": group[0]["value"],
            "supporting_sources": sorted(sources),
            "confidence": confidence.value,
        })

    candidates.sort(key=lambda c: len(c["supporting_sources"]), reverse=True)
    return candidates