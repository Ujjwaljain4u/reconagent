from __future__ import annotations

import os

import requests

from reconagent.collectors.base import BaseCollector
from reconagent.models import CollectorResult, Confidence, Finding, timeit


class VirusTotalCollector(BaseCollector):
    """Domain malware/phishing reputation via VirusTotal's Public API —
    verified genuinely free: 500 requests/day, 4/min, no card required.
    Checks the domain against 70+ antivirus/security engines' verdicts,
    real threat-intel signal, not just registry metadata."""

    accepts = ("domain",)
    name = "virustotal"
    requires_key = True
    key_env_var = "VIRUSTOTAL_API_KEY"

    @timeit
    def run(self, target: str, target_type: str) -> CollectorResult:
        result = CollectorResult(collector=self.name, target=target, ok=False)
        if not self.is_configured():
            result.error = (
                "VIRUSTOTAL_API_KEY not set — skipping (free signup, 500 req/day, "
                "no card: virustotal.com/gui/join-us)"
            )
            return result

        try:
            resp = requests.get(
                f"https://www.virustotal.com/api/v3/domains/{target}",
                headers={"x-apikey": os.getenv(self.key_env_var)},
                timeout=15,
            )
        except Exception as e:  # noqa: BLE001
            result.error = f"VirusTotal request failed: {e}"
            return result

        if resp.status_code == 404:
            result.ok = True
            result.findings.append(
                Finding(source=self.name, category="virustotal_status",
                        value="domain not in VirusTotal's database (no history either way)",
                        confidence=Confidence.MEDIUM)
            )
            return result
        if resp.status_code == 429:
            result.error = "VirusTotal rate limit hit (4 req/min free tier) — try again shortly"
            return result
        if resp.status_code != 200:
            result.error = f"VirusTotal returned HTTP {resp.status_code}"
            return result

        attrs = resp.json().get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)

        result.ok = True
        result.findings.append(
            Finding(source=self.name, category="virustotal_verdict",
                    value=f"{malicious} malicious, {suspicious} suspicious "
                          f"(out of {sum(stats.values())} security engines)",
                    confidence=Confidence.HIGH,
                    notes="flagged by real antivirus/threat-intel engines" if malicious else
                          "no security engine currently flags this domain")
        )

        reputation = attrs.get("reputation")
        if reputation is not None:
            result.findings.append(
                Finding(source=self.name, category="virustotal_reputation_score", value=reputation,
                        confidence=Confidence.MEDIUM,
                        notes="community-driven score, negative = poor reputation")
            )

        categories = attrs.get("categories", {})
        if categories:
            result.findings.append(
                Finding(source=self.name, category="virustotal_categories",
                        value=list(set(categories.values())), confidence=Confidence.MEDIUM)
            )

        return result