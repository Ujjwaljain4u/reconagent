from __future__ import annotations

import socket

import requests

from reconagent.collectors.base import BaseCollector
from reconagent.models import CollectorResult, Confidence, Finding, timeit


class InternetDbCollector(BaseCollector):
    """Shodan's free, keyless InternetDB endpoint: open ports, known CVEs,
    detected technologies for an IP — fully passive, no scan performed by us."""

    accepts = ("domain",)
    name = "internetdb_shodan"

    @timeit
    def run(self, target: str, target_type: str) -> CollectorResult:
        result = CollectorResult(collector=self.name, target=target, ok=False)
        try:
            ip = socket.gethostbyname(target)
        except Exception as e:  # noqa: BLE001
            result.error = f"could not resolve {target}: {e}"
            return result

        try:
            resp = requests.get(f"https://internetdb.shodan.io/{ip}", timeout=10)
        except Exception as e:  # noqa: BLE001
            result.error = f"InternetDB request failed: {e}"
            return result

        if resp.status_code == 404:
            result.ok = True
            result.findings.append(
                Finding(source=self.name, category="internetdb_status",
                        value="no data on file for this IP", confidence=Confidence.HIGH)
            )
            return result
        if resp.status_code != 200:
            result.error = f"InternetDB returned HTTP {resp.status_code}"
            return result

        data = resp.json()
        result.ok = True
        if data.get("ports"):
            result.findings.append(
                Finding(source=self.name, category="open_ports", value=data["ports"],
                        confidence=Confidence.HIGH, raw=data)
            )
        if data.get("vulns"):
            result.findings.append(
                Finding(source=self.name, category="known_cves", value=data["vulns"],
                        confidence=Confidence.HIGH, raw=data)
            )
        if data.get("cpes"):
            result.findings.append(
                Finding(source=self.name, category="detected_technologies", value=data["cpes"],
                        confidence=Confidence.MEDIUM, raw=data)
            )
        return result
