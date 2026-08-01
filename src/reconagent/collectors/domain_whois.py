from __future__ import annotations

import datetime
import re
import shutil
import subprocess

import requests
import whois

from reconagent.collectors.base import BaseCollector
from reconagent.models import CollectorResult, Confidence, Finding, timeit


def _jsonable(value):
    """python-whois returns creation_date/expiration_date as real datetime
    objects (sometimes a single datetime, sometimes a list of them) —
    json.dumps() can't serialize those natively, which was crashing the
    /api/scan/{job_id} endpoint with 'Object of type datetime is not JSON
    serializable'. Recursively convert any datetime found to an ISO string."""
    if isinstance(value, datetime.datetime):
        return value.isoformat()
    if isinstance(value, (list, set, tuple)):
        return sorted(str(_jsonable(v)) for v in value)
    return value

# Regex fallback parser for raw `whois` CLI text — used only when the
# python-whois library's own socket-based lookup comes up empty. Field names
# vary a lot by registry, so this matches the common ones case-insensitively.
_FIELD_PATTERNS = {
    "registrar": r"^\s*Registrar:\s*(.+)$",
    "creation_date": r"^\s*(?:Creation Date|Registered On|Domain Registration Date):\s*(.+)$",
    "expiration_date": r"^\s*(?:Registry Expiry Date|Expiration Date|Expiry Date):\s*(.+)$",
    "registrant_org": r"^\s*Registrant Organi[sz]ation:\s*(.+)$",
    "registrant_country": r"^\s*Registrant Country:\s*(.+)$",
}
_NAME_SERVER_PATTERN = re.compile(r"^\s*Name Server:\s*(.+)$", re.IGNORECASE | re.MULTILINE)


class DomainWhoisCollector(BaseCollector):
    accepts = ("domain",)
    name = "domain_whois"

    @timeit
    def run(self, target: str, target_type: str) -> CollectorResult:
        result = CollectorResult(collector=self.name, target=target, ok=False)

        # Path 1: python-whois — does its own raw socket (port 43) lookups,
        # does NOT use the system `whois` binary at all.
        findings = self._try_python_whois(target)

        # Path 2: fall back to the system `whois` CLI + regex parsing if the
        # library above returned nothing — this covers cases where python-whois's
        # bundled server list/IANA-referral step fails but the CLI (which may use
        # a different resolution path or just be more current) works fine.
        if not findings and shutil.which("whois"):
            findings = self._try_cli_whois(target)

        # Path 3: RDAP — many newer gTLD registries (e.g. .news, and others run by
        # Identity Digital and similar operators) have dropped legacy port-43 WHOIS
        # entirely in favor of RDAP as part of ICANN's ongoing WHOIS-to-RDAP
        # transition. rdap.org is IANA's public bootstrap service: it looks up the
        # correct registry RDAP endpoint for you, no server-guessing needed, and
        # it's plain HTTPS so it works even when port 43 is blocked or unsupported.
        if not findings:
            findings = self._try_rdap(target)

        if not findings:
            has_cli = bool(shutil.which("whois"))
            result.error = (
                "no whois record returned via python-whois"
                + (", the system whois CLI," if has_cli else "")
                + " or RDAP — registration may be privacy-protected, or this "
                + "registry doesn't expose public data on any of these channels"
            )
            return result

        result.ok = True
        result.findings = findings
        return result

    def _try_python_whois(self, target: str) -> list[Finding]:
        try:
            w = whois.whois(target)
        except Exception:  # noqa: BLE001 - fall through to CLI fallback
            return []
        if not w or not getattr(w, "domain_name", None):
            return []

        field_map = {
            "registrar": "registrar",
            "creation_date": "creation_date",
            "expiration_date": "expiration_date",
            "name_servers": "name_servers",
            "org": "registrant_org",
            "country": "registrant_country",
            "emails": "registrant_email",
        }
        findings = []
        for whois_field, category in field_map.items():
            value = getattr(w, whois_field, None)
            if not value:
                continue
            value = _jsonable(value)
            findings.append(Finding(source=self.name, category=category, value=value,
                                     confidence=Confidence.HIGH))
        return findings

    def _try_cli_whois(self, target: str) -> list[Finding]:
        text = self._run_whois_cli(target)
        if not text:
            return []

        # Some registries (e.g. .news via Identity Digital) return an empty
        # `whois:`/`refer:` field in the IANA stub, so the client never follows
        # to the actual registry server and you just get the TLD-level IANA
        # record back, not the domain's real registration data. Detect that
        # shape and retry directly against whois.nic.<tld> as a fallback.
        if "source:       IANA" in text or "source: IANA" in text:
            tld = target.rsplit(".", 1)[-1]
            retry_text = self._run_whois_cli(target, host=f"whois.nic.{tld}")
            if retry_text:
                text = retry_text

        findings = []
        for category, pattern in _FIELD_PATTERNS.items():
            m = re.search(pattern, text, re.IGNORECASE | re.MULTILINE)
            if m:
                findings.append(Finding(source=self.name, category=category,
                                         value=m.group(1).strip(), confidence=Confidence.HIGH,
                                         notes="via system whois CLI fallback"))
        name_servers = sorted(set(m.strip().lower() for m in _NAME_SERVER_PATTERN.findall(text)))
        if name_servers:
            findings.append(Finding(source=self.name, category="name_servers", value=name_servers,
                                     confidence=Confidence.HIGH, notes="via system whois CLI fallback"))
        return findings

    def _run_whois_cli(self, target: str, host: str | None = None) -> str:
        cmd = ["whois"]
        if host:
            cmd += ["-h", host]
        cmd.append(target)
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            return proc.stdout
        except Exception:  # noqa: BLE001
            return ""

    def _try_rdap(self, target: str) -> list[Finding]:
        try:
            resp = requests.get(f"https://rdap.org/domain/{target}", timeout=15,
                                 headers={"User-Agent": "reconagent/0.1 (passive-osint-research)"})
            if resp.status_code != 200:
                return []
            data = resp.json()
        except Exception:  # noqa: BLE001
            return []

        findings = []

        for entity in data.get("entities", []):
            if "registrar" in entity.get("roles", []):
                vcard = entity.get("vcardArray", [None, []])[1]
                for field in vcard:
                    if field[0] == "fn":
                        findings.append(Finding(source=self.name, category="registrar",
                                                 value=field[3], confidence=Confidence.HIGH,
                                                 notes="via RDAP"))

        for event in data.get("events", []):
            action = event.get("eventAction")
            date = event.get("eventDate")
            if not date:
                continue
            if action == "registration":
                findings.append(Finding(source=self.name, category="creation_date", value=date,
                                         confidence=Confidence.HIGH, notes="via RDAP"))
            elif action == "expiration":
                findings.append(Finding(source=self.name, category="expiration_date", value=date,
                                         confidence=Confidence.HIGH, notes="via RDAP"))

        nameservers = sorted({ns.get("ldhName", "").lower() for ns in data.get("nameservers", [])
                               if ns.get("ldhName")})
        if nameservers:
            findings.append(Finding(source=self.name, category="name_servers", value=nameservers,
                                     confidence=Confidence.HIGH, notes="via RDAP"))

        status = data.get("status")
        if status:
            findings.append(Finding(source=self.name, category="domain_status", value=status,
                                     confidence=Confidence.HIGH, notes="via RDAP"))

        return findings