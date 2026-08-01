from __future__ import annotations

import re

import requests

from reconagent.collectors.base import BaseCollector
from reconagent.models import CollectorResult, Confidence, Finding, timeit

HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; reconagent/0.1; passive OSINT check)"}
_CHANNEL_META_RE = re.compile(r'"channelMetadataRenderer":\{"title":"([^"]*)"')


class YouTubeCollector(BaseCollector):
    """Checks if a @handle resolves to a real YouTube channel. More reliable
    than Instagram/TikTok/etc: YouTube channel pages include real, distinct
    server-rendered metadata (channelMetadataRenderer) for existing channels,
    and a genuine redirect-to-404 for handles that don't exist — not just a
    generic client-rendered shell either way."""

    accepts = ("username",)
    name = "youtube"

    @timeit
    def run(self, target: str, target_type: str) -> CollectorResult:
        result = CollectorResult(collector=self.name, target=target, ok=True)
        url = f"https://www.youtube.com/@{target}"

        try:
            resp = requests.get(url, headers=HEADERS, timeout=10, allow_redirects=True)
        except Exception as e:  # noqa: BLE001
            result.error = f"YouTube request failed: {e}"
            result.ok = False
            return result

        if resp.status_code in (403, 429, 500, 502, 503):
            result.findings.append(
                Finding(source=self.name, category="youtube_status", value="blocked/rate-limited, inconclusive",
                        confidence=Confidence.NEEDS_REVIEW)
            )
            return result

        if resp.status_code == 404 or "/404" in resp.url:
            result.findings.append(
                Finding(source=self.name, category="youtube_status", value="no channel found",
                        confidence=Confidence.HIGH)
            )
            return result

        match = _CHANNEL_META_RE.search(resp.text)
        if match:
            result.findings.append(
                Finding(source=self.name, category="youtube_channel_url", value=url,
                        confidence=Confidence.HIGH)
            )
            result.findings.append(
                Finding(source=self.name, category="youtube_channel_name", value=match.group(1),
                        confidence=Confidence.HIGH)
            )
        else:
            result.findings.append(
                Finding(source=self.name, category="youtube_status",
                        value="no channel metadata found (likely doesn't exist)",
                        confidence=Confidence.MEDIUM)
            )
        return result