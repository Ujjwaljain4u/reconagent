from __future__ import annotations

import time

import requests

from reconagent.collectors.base import BaseCollector
from reconagent.models import CollectorResult, Confidence, Finding, timeit


class CrtshCollector(BaseCollector):
    """Certificate Transparency log search — reveals subdomains that have
    ever had a TLS cert issued, including ones not linked anywhere publicly.
    crt.sh is a free community service and occasionally returns 502/503
    under load — this retries twice with backoff before giving up."""

    accepts = ("domain",)
    name = "crtsh_subdomains"

    @timeit
    def run(self, target: str, target_type: str) -> CollectorResult:
        result = CollectorResult(collector=self.name, target=target, ok=False)
        url = f"https://crt.sh/?q=%25.{target}&output=json"
        headers = {"User-Agent": "reconagent/0.1 (passive-osint-research)"}

        rows = None
        last_error = None
        for attempt in range(3):
            try:
                resp = requests.get(url, timeout=10, headers=headers)
                if resp.status_code == 404:
                    # genuinely means no certificate transparency records exist for this
                    # domain — not a transient failure, don't retry, don't call it "flaky"
                    result.ok = True
                    result.findings.append(
                        Finding(source=self.name, category="subdomains", value=[],
                                confidence=Confidence.HIGH,
                                notes="no certificate transparency records found for this domain")
                    )
                    return result
                if resp.status_code in (502, 503, 504):
                    last_error = f"crt.sh returned HTTP {resp.status_code} (their server, temporary)"
                    time.sleep(0.8 * (attempt + 1))
                    continue
                resp.raise_for_status()
                rows = resp.json()
                last_error = None
                break
            except Exception as e:  # noqa: BLE001
                last_error = f"crt.sh query failed: {e}"
                time.sleep(0.8 * (attempt + 1))

        if last_error:
            result.error = last_error + " — crt.sh is community-run and occasionally flaky; try again shortly"
            return result

        subdomains = set()
        for row in rows:
            name_value = row.get("name_value", "")
            for line in name_value.split("\n"):
                line = line.strip().lstrip("*.")
                if line.endswith(target):
                    subdomains.add(line)

        result.ok = True
        result.findings.append(
            Finding(
                source=self.name,
                category="subdomains",
                value=sorted(subdomains),
                confidence=Confidence.HIGH,
                notes=f"{len(subdomains)} unique subdomains found via certificate transparency logs",
            )
        )
        return result