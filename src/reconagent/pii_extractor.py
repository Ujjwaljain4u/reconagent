from __future__ import annotations

import re

from reconagent.models import CollectorResult, Confidence, Finding

_PHONE_RE = re.compile(r"\+?\d[\d\s\-\(\)]{7,}\d")
_EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
_ISO_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}([T ]\d{2}:\d{2}:\d{2})?")

# Only scan finding categories that are genuinely free-text (bios,
# descriptions, snippets, meta tags) — the original blanket ">15 chars"
# heuristic was scanning WHOIS dates, DNS status strings, and technical
# fields never meant to hold PII, which is exactly what produced false
# positives (NER tagging "DMARC" as a PERSON, the phone regex matching
# ISO date strings like "1993-04-20"). Restricting to an explicit
# allowlist of real free-text categories fixes both.
# Only scan finding categories that are genuine multi-word PROSE with real
# sentence context — bios and search snippets. Originally this also
# included WHOIS registrant_org/ASN org/ISP fields, but live testing showed
# spaCy's small model returns ZERO entities for a bare field value like
# "NVIDIA Corporation" with no surrounding sentence — NER genuinely needs
# context to work, and a WHOIS org field is already-structured, already-
# labeled data anyway (we already know it's an org name; there's nothing
# to "extract"). Narrowed to where NER actually adds value: real prose.
FREE_TEXT_CATEGORIES = {
    "bio", "gravatar_bio", "bluesky_bio", "ocr_extracted_text",
}

_nlp = None


def _get_nlp():
    """Lazy-load spaCy's small English model — loading it at import time
    would slow down every CLI/web invocation even when PII extraction
    isn't used. Falls back gracefully if the model isn't installed."""
    global _nlp
    if _nlp is None:
        try:
            import spacy
            _nlp = spacy.load("en_core_web_sm")
        except Exception:  # noqa: BLE001
            _nlp = False  # sentinel: tried and failed, don't retry every call
    return _nlp or None


def _looks_like_date(text: str) -> bool:
    return bool(_ISO_DATE_RE.match(text.strip()))


def _extract_text_snippets(results: list[CollectorResult]) -> list[tuple[str, str, str]]:
    """Returns (source_collector, source_category, text) for every genuine
    free-text finding value — restricted to FREE_TEXT_CATEGORIES plus
    search-result snippets, not every string field in every collector."""
    snippets = []
    for r in results:
        if not r.ok:
            continue
        for f in r.findings:
            if isinstance(f.value, str) and f.category in FREE_TEXT_CATEGORIES and len(f.value) > 5:
                snippets.append((r.collector, f.category, f.value))
            elif isinstance(f.value, list):
                for item in f.value:
                    if isinstance(item, dict) and "snippet" in item:
                        snippets.append((r.collector, f"{f.category}.snippet", item["snippet"]))
    return snippets


def extract_pii_findings(results: list[CollectorResult]) -> list[Finding]:
    """Scans genuine free-text fields already collected (bios, WHOIS org
    names, DuckDuckGo search snippets — NOT technical/date/status fields)
    for embedded PII that no collector explicitly extracts — real names,
    organizations, locations via spaCy NER, plus phone numbers and emails
    via regex. Turns unstructured paragraphs into structured findings
    automatically.

    Returns an empty list (not an error) if spaCy's model isn't installed —
    this is additive enrichment, not a required pipeline step."""
    nlp = _get_nlp()
    snippets = _extract_text_snippets(results)
    if not snippets:
        return []

    found_people, found_orgs, found_locations = set(), set(), set()
    found_phones, found_emails = set(), set()

    for _collector, _category, text in snippets:
        for m in _PHONE_RE.finditer(text):
            candidate = m.group().strip()
            if not _looks_like_date(candidate):  # reject "1993-04-20"-shaped false matches
                found_phones.add(candidate)
        found_emails.update(m.group() for m in _EMAIL_RE.finditer(text))

        if nlp:
            doc = nlp(text[:2000])  # cap length, NER on huge blobs is slow and rarely adds value
            for ent in doc.ents:
                if ent.label_ == "PERSON":
                    found_people.add(ent.text.strip())
                elif ent.label_ == "ORG":
                    found_orgs.add(ent.text.strip())
                elif ent.label_ in ("GPE", "LOC"):
                    found_locations.add(ent.text.strip())

    findings = []
    if found_people:
        findings.append(Finding(source="pii_extractor", category="extracted_person_names",
                                 value=sorted(found_people), confidence=Confidence.MEDIUM,
                                 notes="names found via NER in bios/text fields — verify manually"))
    if found_orgs:
        findings.append(Finding(source="pii_extractor", category="extracted_organizations",
                                 value=sorted(found_orgs), confidence=Confidence.MEDIUM))
    if found_locations:
        findings.append(Finding(source="pii_extractor", category="extracted_locations",
                                 value=sorted(found_locations), confidence=Confidence.MEDIUM))
    if found_phones:
        findings.append(Finding(source="pii_extractor", category="extracted_phone_numbers",
                                 value=sorted(found_phones), confidence=Confidence.LOW,
                                 notes="regex-matched digit sequences, may include false positives"))
    if found_emails:
        findings.append(Finding(source="pii_extractor", category="extracted_emails",
                                 value=sorted(found_emails), confidence=Confidence.HIGH))
    return findings