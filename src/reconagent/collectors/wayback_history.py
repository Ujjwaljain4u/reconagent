from __future__ import annotations

import requests

from reconagent.collectors.base import BaseCollector
from reconagent.models import CollectorResult, Confidence, Finding, timeit


class WaybackCollector(BaseCollector):
    """archive.org's free CDX API — first/last seen snapshot dates and total
    capture count. Useful for recovering deleted content or seeing how long
    a domain/page has existed."""

    accepts = ("domain",)
    name = "wayback_history"

    @timeit
    def run(self, target: str, target_type: str) -> CollectorResult:
        result = CollectorResult(collector=self.name, target=target, ok=False)
        try:
            resp = requests.get(
                "https://web.archive.org/cdx/search/cdx",
                params={"url": target, "output": "json", "collapse": "timestamp:8", "limit": "10000"},
                timeout=25,
            )
            resp.raise_for_status()
            rows = resp.json()
        except Exception as e:  # noqa: BLE001
            result.error = f"Wayback CDX query failed: {e}"
            return result

        result.ok = True
        if len(rows) <= 1:  # first row is the header
            result.findings.append(
                Finding(source=self.name, category="wayback_status", value="no archived snapshots found",
                        confidence=Confidence.HIGH)
            )
            return result

        timestamps = [row[1] for row in rows[1:]]
        result.findings.append(
            Finding(source=self.name, category="first_seen", value=timestamps[0], confidence=Confidence.HIGH)
        )
        result.findings.append(
            Finding(source=self.name, category="last_seen", value=timestamps[-1], confidence=Confidence.HIGH)
        )
        result.findings.append(
            Finding(source=self.name, category="total_snapshots", value=len(timestamps),
                    confidence=Confidence.HIGH)
        )
        return result