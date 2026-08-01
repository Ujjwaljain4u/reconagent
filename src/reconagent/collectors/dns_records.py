from __future__ import annotations

import re

import dns.resolver

from reconagent.collectors.base import BaseCollector
from reconagent.models import CollectorResult, Confidence, Finding, timeit

RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT"]


class DnsRecordsCollector(BaseCollector):
    accepts = ("domain", "email")
    name = "dns_records"

    @timeit
    def run(self, target: str, target_type: str) -> CollectorResult:
        domain = target.split("@")[-1] if target_type == "email" else target
        result = CollectorResult(collector=self.name, target=target, ok=False)

        resolver = dns.resolver.Resolver()
        resolver.lifetime = 5.0
        any_success = False

        for rtype in RECORD_TYPES:
            try:
                answers = resolver.resolve(domain, rtype)
                values = sorted(str(r).strip('"') for r in answers)
                any_success = True
                result.findings.append(
                    Finding(source=self.name, category=f"dns_{rtype.lower()}",
                            value=values, confidence=Confidence.HIGH)
                )
                if rtype == "TXT":
                    self._classify_txt(result, values)
            except Exception:  # noqa: BLE001 - missing record type is normal, not an error
                continue

        # DMARC policy lives at _dmarc.<domain>, not the root domain's TXT records —
        # query it directly instead of just telling the user to check it themselves.
        self._check_dmarc(result, domain, resolver)

        result.ok = any_success
        if not any_success:
            result.error = f"no resolvable DNS records for {domain}"
        return result

    def _check_dmarc(self, result: CollectorResult, domain: str, resolver: "dns.resolver.Resolver") -> None:
        try:
            answers = resolver.resolve(f"_dmarc.{domain}", "TXT")
            records = [str(r).strip('"') for r in answers]
            dmarc = next((r for r in records if r.lower().startswith("v=dmarc1")), None)
            if dmarc:
                policy_match = re.search(r"p=(\w+)", dmarc, re.IGNORECASE)
                policy = policy_match.group(1).lower() if policy_match else "unspecified"
                result.findings.append(
                    Finding(source=self.name, category="dmarc_record", value=dmarc,
                            confidence=Confidence.HIGH,
                            notes=f"policy: {policy}" + (" — monitoring only, not enforced" if policy == "none" else ""))
                )
            else:
                result.findings.append(
                    Finding(source=self.name, category="dmarc_status",
                            value="_dmarc subdomain exists but has no valid DMARC TXT record",
                            confidence=Confidence.HIGH)
                )
        except dns.resolver.NXDOMAIN:
            result.findings.append(
                Finding(source=self.name, category="dmarc_status",
                        value="no DMARC record found (_dmarc subdomain does not exist)",
                        confidence=Confidence.HIGH)
            )
        except Exception:  # noqa: BLE001 - DNS timeouts etc. shouldn't break the whole collector
            pass

    def _classify_txt(self, result: CollectorResult, txt_values: list[str]) -> None:
        """Pull SPF/DMARC posture out of raw TXT records — useful for email-spoofing risk."""
        spf = [v for v in txt_values if v.lower().startswith("v=spf1")]
        if spf:
            result.findings.append(
                Finding(source=self.name, category="spf_record", value=spf[0],
                        confidence=Confidence.HIGH)
            )
        dmarc = [v for v in txt_values if "v=dmarc1" in v.lower()]
        if dmarc:
            result.findings.append(
                Finding(source=self.name, category="dmarc_record", value=dmarc[0],
                        confidence=Confidence.HIGH)
            )
        # note: DMARC found here (root TXT) is unusual — it normally lives at
        # _dmarc.<domain>, which _check_dmarc() queries directly below.