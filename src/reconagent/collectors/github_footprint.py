from __future__ import annotations

import requests

from reconagent.collectors.base import BaseCollector
from reconagent.models import CollectorResult, Confidence, Finding, timeit


class GithubCollector(BaseCollector):
    """Public GitHub REST API (unauthenticated, 60 req/hr). Profile info +
    repo list + commit-author emails often leak real names/emails — a
    genuinely useful pivot point from a throwaway handle to a real identity."""

    accepts = ("username",)
    name = "github_footprint"

    @timeit
    def run(self, target: str, target_type: str) -> CollectorResult:
        result = CollectorResult(collector=self.name, target=target, ok=False)
        try:
            profile = requests.get(f"https://api.github.com/users/{target}", timeout=10)
        except Exception as e:  # noqa: BLE001
            result.error = f"GitHub API request failed: {e}"
            return result

        if profile.status_code == 404:
            result.ok = True
            result.findings.append(
                Finding(source=self.name, category="github_status", value="no account found",
                        confidence=Confidence.HIGH)
            )
            return result
        if profile.status_code != 200:
            result.error = f"GitHub API returned HTTP {profile.status_code} (rate-limited?)"
            return result

        data = profile.json()
        result.ok = True
        profile_fields = {
            "name": "real_name",
            "email": "public_email",
            "company": "company",
            "location": "stated_location",
            "blog": "linked_website",
            "twitter_username": "linked_twitter",
            "bio": "bio",
            "created_at": "account_created",
            "avatar_url": "github_avatar_url",
        }
        for key, category in profile_fields.items():
            value = data.get(key)
            if value:
                result.findings.append(
                    Finding(source=self.name, category=category, value=value,
                            confidence=Confidence.HIGH)
                )

        # Pull commit-author emails from a handful of recent repos — these are
        # frequently the person's real/personal email even when profile email is hidden.
        try:
            repos = requests.get(
                f"https://api.github.com/users/{target}/repos?sort=updated&per_page=5", timeout=10
            ).json()
        except Exception:  # noqa: BLE001
            repos = []

        leaked_emails = set()
        for repo in repos if isinstance(repos, list) else []:
            full_name = repo.get("full_name")
            if not full_name:
                continue
            try:
                commits = requests.get(
                    f"https://api.github.com/repos/{full_name}/commits?per_page=5", timeout=10
                ).json()
            except Exception:  # noqa: BLE001
                continue
            for c in commits if isinstance(commits, list) else []:
                email = c.get("commit", {}).get("author", {}).get("email", "")
                if email and "noreply.github.com" not in email:
                    leaked_emails.add(email)

        if leaked_emails:
            result.findings.append(
                Finding(source=self.name, category="commit_author_emails",
                        value=sorted(leaked_emails), confidence=Confidence.HIGH,
                        notes="found in public commit metadata of recent repos")
            )
        return result