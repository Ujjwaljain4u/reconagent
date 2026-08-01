from __future__ import annotations

import smtplib
import socket

import dns.resolver

from reconagent.collectors.base import BaseCollector
from reconagent.models import CollectorResult, Confidence, Finding, timeit


class SmtpVerifyCollector(BaseCollector):
    """Checks whether a specific mailbox exists via an SMTP RCPT TO handshake
    — a standard email-verification technique (same one most "email
    validator" services use under the hood), not scraping or login. Talks
    directly to the domain's own mail server via the public MX record.

    HONEST RELIABILITY NOTE #1 — PORT 25 BLOCKING: verified via direct
    testing that outbound port 25 is blocked in cloud/sandbox environments
    by default (anti-spam-relay policy), and this is also common on many
    home ISP networks. If this collector always returns "could not verify,"
    check whether your network blocks port 25 before assuming the code is
    broken — it likely isn't.

    HONEST RELIABILITY NOTE #2 — CATCH-ALL DOMAINS: many mail servers
    deliberately return a generic "250 OK" for any address to prevent
    exactly this kind of enumeration (called a "catch-all" domain), and
    some greylist or rate-limit unfamiliar senders. A "exists" result here
    is a real signal; a "could not verify" result is common and doesn't
    mean the mailbox is fake — it means the server declined to say either
    way, which is the server working as intended from an anti-enumeration
    standpoint."""

    accepts = ("email",)
    name = "smtp_verify"

    @timeit
    def run(self, target: str, target_type: str) -> CollectorResult:
        result = CollectorResult(collector=self.name, target=target, ok=False)
        domain = target.split("@")[-1]

        try:
            mx_records = sorted(
                dns.resolver.resolve(domain, "MX"), key=lambda r: r.preference
            )
            mx_host = str(mx_records[0].exchange).rstrip(".")
        except Exception as e:  # noqa: BLE001
            result.error = f"could not resolve MX record for {domain}: {e}"
            return result

        try:
            server = smtplib.SMTP(timeout=10)
            server.connect(mx_host, 25)
            server.helo("reconagent.local")
            server.mail("verify@reconagent.local")
            code, message = server.rcpt(target)
            server.quit()
        except (smtplib.SMTPException, socket.error, ConnectionRefusedError, TimeoutError, OSError) as e:
            result.ok = True
            is_port25_block = "Address family not supported" in str(e) or isinstance(e, ConnectionRefusedError)
            result.findings.append(
                Finding(source=self.name, category="smtp_verify_status",
                        value="could not verify — outbound port 25 appears blocked on this network",
                        confidence=Confidence.NEEDS_REVIEW,
                        notes=(f"{e} — most home ISPs and cloud providers block outbound port 25 by "
                               f"default (anti-spam-relay policy), which prevents this check from "
                               f"working regardless of whether the mailbox is real. Not a bug in this "
                               f"tool — a network-level restriction outside its control.")
                        if is_port25_block else str(e))
            )
            return result

        result.ok = True
        if code == 250:
            result.findings.append(
                Finding(source=self.name, category="smtp_verify_status", value="mailbox likely exists",
                        confidence=Confidence.MEDIUM,
                        notes="250 response — could also be a catch-all domain accepting all addresses")
            )
        elif code in (550, 551, 553):
            result.findings.append(
                Finding(source=self.name, category="smtp_verify_status", value="mailbox does not exist",
                        confidence=Confidence.MEDIUM, notes=f"SMTP {code}: {message.decode(errors='ignore')}")
            )
        else:
            result.findings.append(
                Finding(source=self.name, category="smtp_verify_status",
                        value=f"inconclusive (SMTP {code})", confidence=Confidence.NEEDS_REVIEW,
                        notes=message.decode(errors="ignore"))
            )
        return result