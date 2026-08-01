from __future__ import annotations

import phonenumbers
from phonenumbers import carrier, geocoder, timezone

from reconagent.collectors.base import BaseCollector
from reconagent.models import CollectorResult, Confidence, Finding, timeit

# phonenumbers.PhoneNumberType values are plain module-level integer constants,
# not a real Python Enum — str(phonenumbers.number_type(x)) just gives back the
# bare int (e.g. "1"), which is meaningless without this lookup table.
_LINE_TYPE_LABELS = {
    phonenumbers.PhoneNumberType.FIXED_LINE: "fixed line",
    phonenumbers.PhoneNumberType.MOBILE: "mobile",
    phonenumbers.PhoneNumberType.FIXED_LINE_OR_MOBILE: "fixed line or mobile",
    phonenumbers.PhoneNumberType.TOLL_FREE: "toll free",
    phonenumbers.PhoneNumberType.PREMIUM_RATE: "premium rate",
    phonenumbers.PhoneNumberType.SHARED_COST: "shared cost",
    phonenumbers.PhoneNumberType.VOIP: "VoIP",
    phonenumbers.PhoneNumberType.PERSONAL_NUMBER: "personal number",
    phonenumbers.PhoneNumberType.PAGER: "pager",
    phonenumbers.PhoneNumberType.UAN: "UAN",
    phonenumbers.PhoneNumberType.VOICEMAIL: "voicemail",
    phonenumbers.PhoneNumberType.UNKNOWN: "unknown",
}


class PhoneCollector(BaseCollector):
    """Uses Google's libphonenumber (via the `phonenumbers` package) — fully
    offline, no API call, no reverse-lookup service. Gives region, carrier,
    line type, timezone. Does NOT identify the person — just the number's
    metadata, which is the legal ceiling for phone OSINT without a paid/
    authorized reverse-lookup provider."""

    accepts = ("phone",)
    name = "phone_lookup"

    @timeit
    def run(self, target: str, target_type: str) -> CollectorResult:
        result = CollectorResult(collector=self.name, target=target, ok=False)
        try:
            parsed = phonenumbers.parse(target, None)
        except phonenumbers.NumberParseException as e:
            if "Missing or invalid default region" in str(e) or not target.strip().startswith("+"):
                result.error = (
                    f"could not parse '{target}' — phone numbers need a country code. "
                    f"Prefix with '+' and the country code, e.g. +91XXXXXXXXXX for India, "
                    f"+1XXXXXXXXXX for US/Canada"
                )
            else:
                result.error = f"could not parse phone number: {e}"
            return result
        except Exception as e:  # noqa: BLE001
            result.error = f"could not parse phone number: {e}"
            return result

        if not phonenumbers.is_valid_number(parsed):
            result.ok = True
            result.findings.append(
                Finding(source=self.name, category="validity", value="invalid number format",
                        confidence=Confidence.HIGH)
            )
            return result

        result.ok = True
        result.findings.append(
            Finding(source=self.name, category="e164_format",
                    value=phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164),
                    confidence=Confidence.HIGH)
        )
        result.findings.append(
            Finding(source=self.name, category="region", value=geocoder.description_for_number(parsed, "en"),
                    confidence=Confidence.HIGH)
        )
        carrier_name = carrier.name_for_number(parsed, "en")
        if carrier_name:
            result.findings.append(
                Finding(source=self.name, category="carrier", value=carrier_name, confidence=Confidence.MEDIUM)
            )
        result.findings.append(
            Finding(source=self.name, category="line_type",
                    value=_LINE_TYPE_LABELS.get(phonenumbers.number_type(parsed), "unknown"),
                    confidence=Confidence.HIGH)
        )
        tzs = timezone.time_zones_for_number(parsed)
        if tzs:
            result.findings.append(
                Finding(source=self.name, category="possible_timezones", value=list(tzs),
                        confidence=Confidence.MEDIUM)
            )
        return result