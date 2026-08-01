from __future__ import annotations

import re

import requests

from reconagent.collectors.base import BaseCollector
from reconagent.models import CollectorResult, Confidence, Finding, timeit

HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; reconagent/0.1; passive OSINT check)"}

_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
_OG_TITLE_RE = re.compile(
    r'<meta[^>]+property=["\']og:title["\'][^>]+content=["\']([^"\']*)["\']', re.IGNORECASE
)


def _extract_title(html: str) -> str:
    og = _OG_TITLE_RE.search(html)
    if og:
        return og.group(1)
    t = _TITLE_RE.search(html)
    return t.group(1) if t else ""


class SocialMetaCheckCollector(BaseCollector):
    """Direct existence check against Instagram/X/TikTok/Pinterest/Snapchat
    themselves — not a third-party mirror site (unlike Sherlock, which
    routes Instagram through imginn.com and Twitter through a Nitter
    instance, since those platforms can't be reliably checked directly).

    Technique: (1) trust a real HTTP 404 status directly when the platform
    gives one (verified live: X returns a genuine 404 for nonexistent
    users), (2) fall back to comparing server-rendered <title>/og:title
    against a known generic string when status alone isn't conclusive
    (needed for platforms that return 200 either way).

    Threads was REMOVED after live testing: it shows "Threads • Log in" for
    every request, real or fake, since anonymous profile viewing is
    login-walled — the meta-tag technique fundamentally cannot distinguish
    real from fake there, unlike a JS-shell problem this could work around.

    STILL EXPERIMENTAL for the remaining sites — verify manually before
    treating a hit as confirmed. Confidence is deliberately kept at
    NEEDS_REVIEW. These platforms change markup without notice.
    """

    accepts = ("username",)
    name = "social_meta_check"

    # generic site-wide titles shown for nonexistent/blocked profiles when
    # status code alone isn't conclusive (some platforms return 200 either way)
    _GENERIC_TITLES = {
        "instagram": {"instagram", "page not found • instagram"},
        "x": {"x", "x. it's what's happening / x", "just a moment...",
              "user profile not found - x | 404 error"},  # confirmed via live test
        "tiktok": {"tiktok - make your day", "tiktok"},
        "pinterest": {"pinterest", "page not found - pinterest"},
        "snapchat": {"snapchat", "snapchat - add me"},
    }

    _SITES = {
        "Instagram": ("https://www.instagram.com/{}/", "instagram"),
        "X/Twitter": ("https://x.com/{}", "x"),
        "TikTok": ("https://www.tiktok.com/@{}", "tiktok"),
        "Pinterest": ("https://www.pinterest.com/{}/", "pinterest"),
        "Snapchat": ("https://www.snapchat.com/add/{}", "snapchat"),
        # Threads removed — confirmed always login-walled, see docstring above
    }

    def _check(self, site: str, url_template: str, site_key: str, username: str):
        url = url_template.format(username)
        try:
            resp = requests.get(url, headers=HEADERS, timeout=8, allow_redirects=True)
        except Exception:  # noqa: BLE001
            return site, None, url

        if resp.status_code in (403, 429, 500, 502, 503):
            return site, None, url  # blocked/rate-limited, not a real signal either way

        # A real 404 is an authoritative "not found" — trust it directly
        # rather than falling through to the (less reliable) title heuristic.
        if resp.status_code == 404:
            return site, False, url

        title = _extract_title(resp.text).strip().lower()
        if not title:
            return site, None, url

        is_generic = title in self._GENERIC_TITLES.get(site_key, set())
        return site, (not is_generic), url

    @timeit
    def run(self, target: str, target_type: str) -> CollectorResult:
        result = CollectorResult(collector=self.name, target=target, ok=True)
        found, unknown = [], []

        for site, (url_template, site_key) in self._SITES.items():
            site_name, exists, url = self._check(site, url_template, site_key, target)
            if exists is True:
                found.append({"site": site_name, "url": url})
            elif exists is None:
                unknown.append(site_name)

        result.findings.append(
            Finding(source=self.name, category="possible_profiles", value=found,
                    confidence=Confidence.NEEDS_REVIEW,
                    notes="EXPERIMENTAL meta-tag heuristic, not a confirmed match — "
                          "verify each manually by opening the link. These platforms "
                          "change markup often; this may become unreliable over time.")
        )
        if unknown:
            result.findings.append(
                Finding(source=self.name, category="inconclusive_sites", value=unknown,
                        confidence=Confidence.NEEDS_REVIEW,
                        notes="blocked/rate-limited or no usable signal — check manually")
            )
        return result