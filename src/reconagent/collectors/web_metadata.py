from __future__ import annotations

import re
from urllib.parse import urlparse

import requests

from reconagent.collectors.base import BaseCollector
from reconagent.models import CollectorResult, Confidence, Finding, timeit
from reconagent.ssrf_guard import SsrfBlockedError, assert_public_host

META_PATTERNS = {
    "generator": r'<meta\s+name=["\']generator["\']\s+content=["\']([^"\']+)["\']',
    "og_site_name": r'<meta\s+property=["\']og:site_name["\']\s+content=["\']([^"\']+)["\']',
    "author": r'<meta\s+name=["\']author["\']\s+content=["\']([^"\']+)["\']',
}


class WebMetadataCollector(BaseCollector):
    """Fetches the target's homepage HTML and pulls meta tags + HTTP headers
    that fingerprint the tech stack (CMS/generator, server software) — plain
    HTTP GET, no scraping-behind-auth, no ToS violation."""

    accepts = ("domain",)
    name = "web_metadata"

    @timeit
    def run(self, target: str, target_type: str) -> CollectorResult:
        result = CollectorResult(collector=self.name, target=target, ok=False)
        url = target if target.startswith("http") else f"https://{target}"

        try:
            assert_public_host(urlparse(url).hostname or target)
        except SsrfBlockedError as e:
            result.error = str(e)
            return result

        try:
            resp = requests.get(url, timeout=10, headers={"User-Agent": "reconagent/0.1"})
        except Exception as e:  # noqa: BLE001
            result.error = f"HTTP request failed: {e}"
            return result

        result.ok = True
        for header in ("Server", "X-Powered-By"):
            if header in resp.headers:
                result.findings.append(
                    Finding(source=self.name, category=f"header_{header.lower().replace('-', '_')}",
                            value=resp.headers[header], confidence=Confidence.HIGH)
                )

        for category, pattern in META_PATTERNS.items():
            m = re.search(pattern, resp.text, re.IGNORECASE)
            if m:
                result.findings.append(
                    Finding(source=self.name, category=f"meta_{category}", value=m.group(1),
                            confidence=Confidence.MEDIUM)
                )
        return result