from __future__ import annotations

import os

import requests

from reconagent.collectors.base import BaseCollector
from reconagent.models import CollectorResult, Confidence, Finding, timeit


class AbstractPhoneCollector(BaseCollector):
    """Live phone lookup via Abstract's Phone Intelligence API.

    Verified free tier: 100 requests/month, no card required. Note this is a
    RENAMED/expanded product — Abstract used to call this "Phone Validation
    API" at phonevalidation.abstractapi.com; it now lives at
    phoneintelligence.abstractapi.com with a richer nested response.

    IMPORTANT — this changes the privacy posture documented elsewhere in this
    project: unlike the offline phone_lookup.py collector (which only ever
    returns carrier/region/line-type metadata), this live endpoint CAN return
    a registrant name for US/CA numbers and a count of data breaches the
    number has appeared in. That's closer to identifying-data territory than
    "phone OSINT can't identify a person" — because Abstract licenses this
    from commercial data brokers/carrier records, not because it's scraped
    or unauthorized. Still legal, still passive (one HTTPS call, no scraping),
    but the OPSEC framing for phone results should be updated to reflect that
    this specific collector can surface more than pure carrier metadata.
    """

    accepts = ("phone",)
    name = "abstractapi_phone"
    requires_key = True
    key_env_var = "ABSTRACTAPI_PHONE_KEY"

    @timeit
    def run(self, target: str, target_type: str) -> CollectorResult:
        result = CollectorResult(collector=self.name, target=target, ok=False)
        if not self.is_configured():
            result.error = (
                "ABSTRACTAPI_PHONE_KEY not set — skipping (free signup, 100 req/month, "
                "no card: abstractapi.com/api/phone-validation-api)"
            )
            return result

        try:
            resp = requests.get(
                "https://phoneintelligence.abstractapi.com/v1/",
                params={"api_key": os.getenv(self.key_env_var), "phone": target},
                timeout=10,
            )
            resp.raise_for_status()
            data = resp.json()
        except Exception as e:  # noqa: BLE001
            result.error = f"Abstract API request failed: {e}"
            return result

        result.ok = True

        validation = data.get("phone_validation", {}) or {}
        if not validation.get("is_valid"):
            result.findings.append(
                Finding(source=self.name, category="live_validity", value="not a valid/active number",
                        confidence=Confidence.HIGH, notes="via Abstract Phone Intelligence API")
            )
            return result

        fmt = data.get("phone_format", {}) or {}
        if fmt.get("international"):
            result.findings.append(
                Finding(source=self.name, category="live_e164_format", value=fmt["international"],
                        confidence=Confidence.HIGH)
            )

        carrier = data.get("phone_carrier", {}) or {}
        if carrier.get("name"):
            result.findings.append(
                Finding(source=self.name, category="live_carrier", value=carrier["name"],
                        confidence=Confidence.HIGH, notes="live carrier record, may reflect number porting")
            )
        if carrier.get("line_type"):
            result.findings.append(
                Finding(source=self.name, category="live_line_type", value=carrier["line_type"],
                        confidence=Confidence.HIGH)
            )

        location = data.get("phone_location", {}) or {}
        loc_parts = [location.get(k) for k in ("city", "region", "country_name") if location.get(k)]
        if loc_parts:
            result.findings.append(
                Finding(source=self.name, category="live_location", value=", ".join(loc_parts),
                        confidence=Confidence.HIGH)
            )

        line_status = validation.get("line_status")
        if line_status:
            result.findings.append(
                Finding(source=self.name, category="live_line_status", value=line_status,
                        confidence=Confidence.HIGH,
                        notes="active/inactive/ported — live network status, not available offline")
            )

        # Registrant name and breach data are genuinely identifying — flag them
        # distinctly rather than folding them in quietly, so the OPSEC layer
        # and report reader both see clearly that this crosses into
        # more-sensitive territory than the rest of this tool's findings.
        registration = data.get("phone_registration", {}) or {}
        if registration.get("name"):
            result.findings.append(
                Finding(source=self.name, category="live_registrant_name", value=registration["name"],
                        confidence=Confidence.MEDIUM,
                        notes="US/CA only, sourced from carrier/data-broker records — identifying data, "
                              "handle with the same care as any PII")
            )

        breaches = data.get("phone_breaches", {}) or {}
        total_breaches = breaches.get("total_breaches")
        if total_breaches:
            result.findings.append(
                Finding(source=self.name, category="live_breach_count", value=total_breaches,
                        confidence=Confidence.HIGH,
                        notes="number of known data breaches this phone number has appeared in")
            )

        return result