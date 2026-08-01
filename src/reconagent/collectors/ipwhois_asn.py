from __future__ import annotations

import socket

from ipwhois import IPWhois

from reconagent.collectors.base import BaseCollector
from reconagent.models import CollectorResult, Confidence, Finding, timeit


class IpWhoisCollector(BaseCollector):
    """Resolves domain -> IP, then RDAP-looks-up the IP for ASN/network/org info."""

    accepts = ("domain",)
    name = "ipwhois_asn"

    @timeit
    def run(self, target: str, target_type: str) -> CollectorResult:
        result = CollectorResult(collector=self.name, target=target, ok=False)
        try:
            ip = socket.gethostbyname(target)
        except Exception as e:  # noqa: BLE001
            result.error = f"could not resolve {target} to an IP: {e}"
            return result

        result.findings.append(
            Finding(source=self.name, category="resolved_ip", value=ip, confidence=Confidence.HIGH)
        )

        try:
            rdap = IPWhois(ip).lookup_rdap(depth=1)
        except Exception as e:  # noqa: BLE001
            result.error = f"RDAP lookup failed for {ip}: {e}"
            result.ok = True  # still return the resolved IP we found above
            return result

        result.ok = True
        asn_fields = {
            "asn": "asn",
            "asn_description": "asn_org",
            "asn_country_code": "asn_country",
            "network": "network_block",
        }
        for key, category in asn_fields.items():
            value = rdap.get(key)
            if value:
                result.findings.append(
                    Finding(source=self.name, category=category, value=value, confidence=Confidence.HIGH)
                )
        return result
