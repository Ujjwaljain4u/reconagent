from __future__ import annotations

import socket

import dns.resolver

from reconagent.collectors.base import BaseCollector
from reconagent.models import CollectorResult, Confidence, Finding, timeit

# Common DKIM selector names — DKIM records live at <selector>._domainkey.<domain>,
# and the selector name isn't discoverable without guessing (no wildcard lookup
# exists). These cover the selectors used by the most common mail providers.
COMMON_DKIM_SELECTORS = [
    "default", "google", "selector1", "selector2",  # Google Workspace / Microsoft 365
    "k1", "k2",       # Mailchimp / Mandrill
    "s1", "s2",       # SendGrid
    "dkim", "mail",   # generic
]

# Public DNS-based blocklists (DNSBL) — free, no key, standard protocol technique
# used by every mail server on the internet to check sender reputation.
DNSBL_ZONES = [
    "zen.spamhaus.org",
    "bl.spamcop.net",
    "b.barracudacentral.org",
]


class EmailSecurityPostureCollector(BaseCollector):
    """Two real, free, DNS-only checks for the email's domain:
    1. DKIM — probes common selector names to see if DKIM signing is set up
       (email authentication posture, same OPSEC category as SPF/DMARC).
    2. DNSBL — checks the domain's mail server IP against public spam
       blocklists (Spamhaus, SpamCop, Barracuda) — if it's listed, mail from
       this domain may be silently rejected/spam-foldered by recipients."""

    accepts = ("email",)
    name = "email_security_posture"

    @timeit
    def run(self, target: str, target_type: str) -> CollectorResult:
        result = CollectorResult(collector=self.name, target=target, ok=True)
        domain = target.split("@")[-1]
        resolver = dns.resolver.Resolver()
        resolver.lifetime = 5.0

        # --- DKIM selector probe ---
        found_selectors = []
        for selector in COMMON_DKIM_SELECTORS:
            try:
                resolver.resolve(f"{selector}._domainkey.{domain}", "TXT")
                found_selectors.append(selector)
            except Exception:  # noqa: BLE001
                continue
        if found_selectors:
            result.findings.append(
                Finding(source=self.name, category="dkim_selectors_found", value=found_selectors,
                        confidence=Confidence.HIGH,
                        notes="DKIM email-signing is configured for this domain")
            )
        else:
            result.findings.append(
                Finding(source=self.name, category="dkim_status",
                        value="no DKIM record found at common selector names",
                        confidence=Confidence.LOW,
                        notes="not conclusive — DKIM may use a non-standard selector name")
            )

        # --- DNSBL blacklist check on the domain's mail server IP ---
        try:
            mx_records = sorted(resolver.resolve(domain, "MX"), key=lambda r: r.preference)
            mx_host = str(mx_records[0].exchange).rstrip(".")
            mx_ip = socket.gethostbyname(mx_host)
            reversed_ip = ".".join(reversed(mx_ip.split(".")))
        except Exception as e:  # noqa: BLE001
            result.findings.append(
                Finding(source=self.name, category="dnsbl_status", value="could not resolve mail server to check",
                        confidence=Confidence.NEEDS_REVIEW, notes=str(e))
            )
            return result

        listed_on = []
        for zone in DNSBL_ZONES:
            try:
                resolver.resolve(f"{reversed_ip}.{zone}", "A")
                listed_on.append(zone)  # a successful lookup means IT IS listed
            except Exception:  # noqa: BLE001
                continue  # NXDOMAIN (most common outcome) means not listed — normal, not an error

        if listed_on:
            result.findings.append(
                Finding(source=self.name, category="dnsbl_listed", value=listed_on,
                        confidence=Confidence.HIGH,
                        notes=f"mail server {mx_host} ({mx_ip}) is on a public spam blocklist")
            )
        else:
            result.findings.append(
                Finding(source=self.name, category="dnsbl_status",
                        value=f"mail server {mx_host} not listed on checked blocklists",
                        confidence=Confidence.HIGH)
            )
        return result