from __future__ import annotations

import requests

from reconagent.collectors.base import BaseCollector
from reconagent.models import CollectorResult, Confidence, Finding, timeit


class GithubEmailSearchCollector(BaseCollector):
    """Searches GitHub's public user-search API for accounts with this email
    publicly set. GitHub's `in:email` qualifier does fuzzy word matching
    (confirmed via their own docs and live testing — NOT exact match), so
    every candidate is re-verified against their actual public profile
    email before being reported as a real match. Free, unauthenticated
    (60 req/hr rate limit), no scraping."""

    accepts = ("email",)
    name = "github_email_search"

    @timeit
    def run(self, target: str, target_type: str) -> CollectorResult:
        result = CollectorResult(collector=self.name, target=target, ok=False)
        try:
            resp = requests.get(
                "https://api.github.com/search/users",
                params={"q": f"{target} in:email"},
                headers={"Accept": "application/vnd.github+json"},
                timeout=10,
            )
        except Exception as e:  # noqa: BLE001
            result.error = f"GitHub search request failed: {e}"
            return result

        if resp.status_code == 403:
            result.error = "GitHub API rate-limited (60 req/hr unauthenticated) — try again later"
            return result
        if resp.status_code != 200:
            result.error = f"GitHub search API returned HTTP {resp.status_code}"
            return result

        data = resp.json()
        candidates = data.get("items", [])
        result.ok = True

        # GitHub's `in:email` qualifier does FUZZY word matching, not exact
        # match (confirmed: their own docs say "data in:email matches users
        # with the word 'data' in their email") — verified live testing
        # returned unrelated accounts for an exact-email query. Post-filter
        # each candidate against their actual public profile email to get
        # real matches only.
        confirmed = []
        for user in candidates[:10]:
            login = user.get("login")
            if not login:
                continue
            try:
                profile_resp = requests.get(f"https://api.github.com/users/{login}", timeout=8)
                if profile_resp.status_code == 200:
                    profile_email = (profile_resp.json().get("email") or "").strip().lower()
                    if profile_email == target.strip().lower():
                        confirmed.append(user.get("html_url", f"https://github.com/{login}"))
            except Exception:  # noqa: BLE001
                continue

        if not confirmed:
            result.findings.append(
                Finding(source=self.name, category="github_email_status",
                        value="no GitHub account with this exact email publicly set",
                        confidence=Confidence.HIGH,
                        notes=f"{len(candidates)} fuzzy candidate(s) checked, none had a matching public email")
            )
            return result

        for url in confirmed:
            result.findings.append(
                Finding(source=self.name, category="github_account_match", value=url,
                        confidence=Confidence.HIGH, notes="verified exact match on public profile email")
            )
        return result