from __future__ import annotations

import requests

from reconagent.collectors.base import BaseCollector
from reconagent.models import CollectorResult, Confidence, Finding, timeit


class BlueskyCollector(BaseCollector):
    """Bluesky's AT Protocol exposes a genuinely official, free, no-auth
    public API for profile data — unlike Twitter/X (paid API since 2023,
    $100+/month minimum) or Instagram (no public API, anti-bot walled).
    This is real social media presence data via a documented, stable
    endpoint, not scraping or a login-walled workaround."""

    accepts = ("username",)
    name = "bluesky"

    @timeit
    def run(self, target: str, target_type: str) -> CollectorResult:
        result = CollectorResult(collector=self.name, target=target, ok=False)

        # Bluesky handles look like "name.bsky.social" or a custom domain handle.
        # If the target doesn't look like a handle, try it as one anyway —
        # Bluesky will just 400/404 if it's not a real handle format.
        handle = target if "." in target else f"{target}.bsky.social"

        try:
            resolve_resp = requests.get(
                "https://public.api.bsky.app/xrpc/com.atproto.identity.resolveHandle",
                params={"handle": handle}, timeout=10,
            )
        except Exception as e:  # noqa: BLE001
            result.error = f"Bluesky request failed: {e}"
            return result

        if resolve_resp.status_code == 400:
            # tried "{target}.bsky.social" and it doesn't resolve — try the raw
            # target once more in case it's a custom-domain handle we mis-guessed
            if handle != target:
                try:
                    resolve_resp = requests.get(
                        "https://public.api.bsky.app/xrpc/com.atproto.identity.resolveHandle",
                        params={"handle": target}, timeout=10,
                    )
                    handle = target
                except Exception:  # noqa: BLE001
                    pass

        if resolve_resp.status_code != 200:
            result.ok = True
            result.findings.append(
                Finding(source=self.name, category="bluesky_status", value="no account found",
                        confidence=Confidence.HIGH)
            )
            return result

        did = resolve_resp.json().get("did")
        if not did:
            result.ok = True
            result.findings.append(
                Finding(source=self.name, category="bluesky_status", value="no account found",
                        confidence=Confidence.HIGH)
            )
            return result

        try:
            profile_resp = requests.get(
                "https://public.api.bsky.app/xrpc/app.bsky.actor.getProfile",
                params={"actor": did}, timeout=10,
            )
            profile_resp.raise_for_status()
            profile = profile_resp.json()
        except Exception as e:  # noqa: BLE001
            result.error = f"Bluesky profile fetch failed: {e}"
            return result

        result.ok = True
        result.findings.append(
            Finding(source=self.name, category="bluesky_profile_url",
                    value=f"https://bsky.app/profile/{handle}", confidence=Confidence.HIGH)
        )
        if profile.get("avatar"):
            result.findings.append(
                Finding(source=self.name, category="bluesky_avatar_url", value=profile["avatar"],
                        confidence=Confidence.HIGH)
            )
        if profile.get("displayName"):
            result.findings.append(
                Finding(source=self.name, category="bluesky_display_name", value=profile["displayName"],
                        confidence=Confidence.HIGH)
            )
        if profile.get("description"):
            result.findings.append(
                Finding(source=self.name, category="bluesky_bio", value=profile["description"],
                        confidence=Confidence.HIGH)
            )
        for count_field, category in (("followersCount", "bluesky_followers"),
                                        ("followsCount", "bluesky_following"),
                                        ("postsCount", "bluesky_posts")):
            if count_field in profile:
                result.findings.append(
                    Finding(source=self.name, category=category, value=profile[count_field],
                            confidence=Confidence.HIGH)
                )
        if profile.get("createdAt"):
            result.findings.append(
                Finding(source=self.name, category="bluesky_account_created", value=profile["createdAt"],
                        confidence=Confidence.HIGH)
            )
        return result