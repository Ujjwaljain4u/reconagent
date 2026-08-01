from __future__ import annotations

import hashlib

import requests

from reconagent.collectors.base import BaseCollector
from reconagent.models import CollectorResult, Confidence, Finding, timeit


class GravatarCollector(BaseCollector):
    """Checks if an email has a Gravatar profile — free, no key, no login.
    Gravatar accounts often leak a real name, bio, location, and linked
    social accounts (Twitter/GitHub/etc) tied to the email address."""

    accepts = ("email",)
    name = "gravatar"

    @timeit
    def run(self, target: str, target_type: str) -> CollectorResult:
        result = CollectorResult(collector=self.name, target=target, ok=False)
        email_hash = hashlib.sha256(target.strip().lower().strip().encode()).hexdigest()

        try:
            avatar_resp = requests.get(
                f"https://www.gravatar.com/avatar/{email_hash}?d=404", timeout=10
            )
        except Exception as e:  # noqa: BLE001
            result.error = f"Gravatar request failed: {e}"
            return result

        if avatar_resp.status_code == 404:
            result.ok = True
            result.findings.append(
                Finding(source=self.name, category="gravatar_status", value="no Gravatar profile found",
                        confidence=Confidence.HIGH)
            )
            return result

        if avatar_resp.status_code in (403, 429, 500, 502, 503):
            result.error = f"Gravatar request blocked/rate-limited (HTTP {avatar_resp.status_code}) — inconclusive"
            return result

        if avatar_resp.status_code != 200:
            result.error = f"Gravatar returned unexpected HTTP {avatar_resp.status_code}"
            return result

        result.ok = True
        result.findings.append(
            Finding(source=self.name, category="gravatar_avatar_url",
                    value=f"https://www.gravatar.com/avatar/{email_hash}", confidence=Confidence.HIGH)
        )

        try:
            profile_resp = requests.get(f"https://www.gravatar.com/{email_hash}.json", timeout=10)
            if profile_resp.status_code == 200:
                entries = profile_resp.json().get("entry", [])
                if entries:
                    profile = entries[0]
                    field_map = {
                        "displayName": "gravatar_display_name",
                        "aboutMe": "gravatar_bio",
                        "currentLocation": "gravatar_location",
                    }
                    for api_field, category in field_map.items():
                        if profile.get(api_field):
                            result.findings.append(
                                Finding(source=self.name, category=category, value=profile[api_field],
                                        confidence=Confidence.HIGH)
                            )
                    accounts = profile.get("accounts", [])
                    if accounts:
                        linked = [f"{a.get('shortname', a.get('domain'))}: {a.get('url')}" for a in accounts]
                        result.findings.append(
                            Finding(source=self.name, category="gravatar_linked_accounts", value=linked,
                                    confidence=Confidence.HIGH,
                                    notes="social accounts the user has explicitly linked to this Gravatar profile")
                        )
        except Exception:  # noqa: BLE001
            pass  # avatar existing is still a useful signal even if profile JSON fails

        return result