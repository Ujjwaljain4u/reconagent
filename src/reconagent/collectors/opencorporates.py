from __future__ import annotations

import os

import requests

from reconagent.collectors.base import BaseCollector
from reconagent.models import CollectorResult, Confidence, Finding, timeit


class OpenCorporatesCollector(BaseCollector):
    """Company registry search via OpenCorporates free-tier API. Requires an
    API token (free signup) set as OPENCORPORATES_API_KEY. Skips cleanly if
    not configured — never blocks the rest of the run."""

    accepts = ("domain",)
    name = "opencorporates"
    requires_key = True
    key_env_var = "OPENCORPORATES_API_KEY"

    @timeit
    def run(self, target: str, target_type: str) -> CollectorResult:
        result = CollectorResult(collector=self.name, target=target, ok=False)
        if not self.is_configured():
            result.error = "OPENCORPORATES_API_KEY not set — skipping (free signup at opencorporates.com)"
            return result

        # Use the registered domain's org name (bare label) as the search query.
        company_guess = target.split(".")[0]
        try:
            resp = requests.get(
                "https://api.opencorporates.com/v0.4/companies/search",
                params={"q": company_guess, "api_token": os.getenv(self.key_env_var)},
                timeout=15,
            )
            resp.raise_for_status()
            data = resp.json()
        except Exception as e:  # noqa: BLE001
            result.error = f"OpenCorporates query failed: {e}"
            return result

        companies = data.get("results", {}).get("companies", [])
        result.ok = True
        if not companies:
            result.findings.append(
                Finding(source=self.name, category="registry_status", value="no matching company records",
                        confidence=Confidence.MEDIUM)
            )
            return result

        for entry in companies[:5]:
            c = entry.get("company", {})
            result.findings.append(
                Finding(
                    source=self.name,
                    category="company_registry_match",
                    value={
                        "name": c.get("name"),
                        "jurisdiction": c.get("jurisdiction_code"),
                        "status": c.get("current_status"),
                        "incorporation_date": c.get("incorporation_date"),
                    },
                    confidence=Confidence.MEDIUM,
                    notes="name-based match, verify manually before treating as confirmed",
                )
            )
        return result
