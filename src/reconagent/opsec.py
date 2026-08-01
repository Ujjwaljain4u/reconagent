"""
OPSEC layer: reframes every finding from "here's data on the target" to
"here's what the target is unknowingly leaking, and how to fix it." This is
what turns the tool from attacker-tooling into defensive-research tooling —
the framing that matters for AI-security / governance job positioning.
"""

from __future__ import annotations

from reconagent.models import CollectorResult, OpsecFinding, Severity

# category -> (title, severity, description template, remediation)
RULES: dict[str, tuple[str, Severity, str, str]] = {
    "registrant_email": (
        "WHOIS registrant email exposed",
        Severity.MEDIUM,
        "Domain WHOIS record exposes a real registrant email address.",
        "Enable WHOIS privacy/proxy protection through your registrar.",
    ),
    "gps_coordinate": (
        "Image contains embedded GPS location",
        Severity.HIGH,
        "An uploaded image embeds exact GPS coordinates of where it was taken.",
        "Strip EXIF metadata before publishing images (most platforms do this "
        "automatically on upload, but direct file shares/emails do not).",
    ),
    "commit_author_emails": (
        "Personal email leaked via git commit metadata",
        Severity.MEDIUM,
        "Public GitHub commits expose a personal email address in author metadata.",
        "Use GitHub's noreply email address (Settings > Emails > Keep my email "
        "address private) and rewrite existing commit history if needed.",
    ),
    "open_ports": (
        "Open ports detected on public IP",
        Severity.MEDIUM,
        "Passive internet-wide scan data shows open ports on the resolved IP.",
        "Close unused ports; restrict access via firewall/security group to "
        "known IPs only.",
    ),
    "known_cves": (
        "Known CVEs associated with detected services",
        Severity.CRITICAL,
        "Passive scan data flags known vulnerabilities on exposed services.",
        "Patch/upgrade the affected service immediately; this is public "
        "intelligence any attacker can also access for free.",
    ),
    "live_registrant_name": (
        "Phone number linked to a registrant name via live carrier/broker data",
        Severity.MEDIUM,
        "A live phone-intelligence lookup returned a registrant name tied to this "
        "number (US/CA only). This is licensed carrier/broker data, not a public "
        "listing — treat it as PII.",
        "This is inherent to how US/CA carriers report registrant data to "
        "licensed lookup providers; no user-side fix exists beyond number "
        "porting/reassignment through the carrier.",
    ),
    "live_breach_count": (
        "Phone number found in known data breaches",
        Severity.MEDIUM,
        "This phone number has appeared in one or more publicly known data breaches.",
        "Treat this number as exposed for SMS-based 2FA/social-engineering risk; "
        "prefer an authenticator app over SMS codes for accounts tied to this number.",
    ),
    "dmarc_status": (
        "Missing or invalid DMARC policy",
        Severity.LOW,
        "No valid DMARC record found at _dmarc.<domain>, increasing email spoofing risk.",
        "Publish a DMARC TXT record at _dmarc.<domain> starting at p=none "
        "for monitoring, then tighten to p=quarantine/p=reject.",
    ),
    "author": (
        "Document metadata exposes author identity",
        Severity.LOW,
        "PDF/document metadata reveals author name or internal software version.",
        "Strip metadata before publishing documents externally "
        "(most office suites have a 'remove personal info' export option).",
    ),
}


def build_opsec_findings(results: list[CollectorResult]) -> list[OpsecFinding]:
    findings: list[OpsecFinding] = []
    for r in results:
        if not r.ok:
            continue
        for f in r.findings:
            rule = RULES.get(f.category)
            if not rule:
                continue
            title, severity, desc, remediation = rule
            findings.append(OpsecFinding(
                title=title, severity=severity, description=desc,
                remediation=remediation, evidence_sources=[r.collector],
            ))
    # de-dupe identical (title, source) pairs
    seen = set()
    deduped = []
    for f in findings:
        key = (f.title, tuple(f.evidence_sources))
        if key not in seen:
            seen.add(key)
            deduped.append(f)
    deduped.sort(key=lambda f: list(Severity).index(f.severity), reverse=True)
    return deduped