from __future__ import annotations

import concurrent.futures
import re
from html import unescape
from urllib.parse import unquote, urlparse, parse_qs

import requests

from reconagent.collectors.base import BaseCollector
from reconagent.models import CollectorResult, Confidence, Finding, timeit

# DuckDuckGo's HTML (no-JS) results page — the same lightweight endpoint tools
# like theHarvester query. This is a step further than a clean official API:
# there's no free official search API left standing (Google CSE closed to new
# customers, Bing Search API retired), so this queries the public search
# results page directly rather than a documented JSON endpoint. No login, no
# account, no personal-data wall — but flagging the distinction honestly
# rather than presenting it as equivalent to a stable JSON API.
# Matches any <a ...>...</a> tag; we then check the captured attribute string
# for class="result__a" ourselves rather than baking attribute order into the
# regex — DuckDuckGo's actual markup doesn't guarantee class comes before href.
_ANCHOR_RE = re.compile(r'<a\s+([^>]*?)>(.*?)</a>', re.DOTALL)
_HREF_RE = re.compile(r'href="([^"]+)"')
_SNIPPET_ANCHOR_RE = re.compile(r'<a\s+([^>]*?)>(.*?)</a>', re.DOTALL)
_TAG_STRIP_RE = re.compile(r"<[^>]+>")


def _clean(text: str) -> str:
    return unescape(_TAG_STRIP_RE.sub("", text)).strip()


def _resolve_ddg_redirect(href: str) -> str:
    """DuckDuckGo HTML results wrap outbound links in a redirect URL
    (//duckduckgo.com/l/?uddg=<real_url>) — unwrap it to the real target."""
    if href.startswith("//"):
        href = "https:" + href
    parsed = urlparse(href)
    if "duckduckgo.com" in parsed.netloc and parsed.path == "/l/":
        qs = parse_qs(parsed.query)
        real = qs.get("uddg")
        if real:
            return unquote(real[0])
    return href


class DuckDuckGoSearchCollector(BaseCollector):
    """Finds public web pages mentioning the target — the actual high-value
    part of phone/username/domain OSINT (marketplace ads, forum posts,
    business listings, social bios), not just carrier/registry metadata."""

    accepts = ("phone", "domain", "username", "email")
    name = "duckduckgo_search"

    # Site-scoped dork queries for phone — targets platforms where phone
    # numbers actually get publicly posted (marketplace ads, business
    # listings, forum signatures). This is real Google/DuckDuckGo "dorking"
    # technique, just using a free search engine instead of a paid dork API.
    PHONE_DORK_SITES = [
        "olx.in", "quikr.com", "justdial.com",  # India classifieds/business listings
        "facebook.com", "instagram.com",          # social bios often list contact numbers
        "linkedin.com",                            # public LinkedIn posts (search-engine cache
                                                     # only — this queries DuckDuckGo's index of
                                                     # already-public pages, not LinkedIn directly,
                                                     # so it doesn't cross the scraping line we've
                                                     # held elsewhere in this project)
        "reddit.com", "quora.com",                 # forum posts
    ]

    def _query_variants(self, target: str, target_type: str) -> list[str]:
        if target_type == "phone":
            digits_only = target.lstrip("+")
            variants = [f'"{target}"', f'"{digits_only}"']
            variants += [f'"{digits_only}" site:{site}' for site in self.PHONE_DORK_SITES]
            return variants
        return [f'"{target}"']

    @timeit
    def run(self, target: str, target_type: str) -> CollectorResult:
        result = CollectorResult(collector=self.name, target=target, ok=False)
        seen_urls = set()
        hits = []
        errors = []

        def run_query(query: str):
            try:
                resp = requests.post(
                    "https://html.duckduckgo.com/html/",
                    data={"q": query},
                    headers={"User-Agent": "Mozilla/5.0 (reconagent passive OSINT correlation)"},
                    timeout=10,
                )
                resp.raise_for_status()
                return resp.text
            except Exception as e:  # noqa: BLE001
                errors.append(str(e))
                return None

        queries = self._query_variants(target, target_type)
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(len(queries), 6)) as pool:
            for html in pool.map(run_query, queries):
                if html is None:
                    continue
                all_anchors = _ANCHOR_RE.findall(html)
                result_anchors = [(attrs, text) for attrs, text in all_anchors if 'class="result__a"' in attrs]
                snippet_anchors = [(attrs, text) for attrs, text in all_anchors if 'class="result__snippet"' in attrs]

                for i, (attrs, title) in enumerate(result_anchors[:10]):
                    href_match = _HREF_RE.search(attrs)
                    if not href_match:
                        continue
                    url = _resolve_ddg_redirect(href_match.group(1))
                    if url in seen_urls:
                        continue
                    seen_urls.add(url)
                    snippet = _clean(snippet_anchors[i][1]) if i < len(snippet_anchors) else ""
                    hits.append({
                        "title": _clean(title),
                        "url": url,
                        "snippet": snippet[:200],
                    })

        if not hits:
            result.error = "no public pages found mentioning this target via search-engine correlation"
            if errors:
                result.error += f" ({len(errors)}/{len(queries)} queries failed to reach DuckDuckGo)"
            result.ok = True  # a clean "nothing found" is still a successful run
            return result

        result.ok = True
        result.findings.append(
            Finding(source=self.name, category="mentioned_on", value=hits,
                    confidence=Confidence.MEDIUM,
                    notes=f"{len(hits)} public page(s) found mentioning this target via search-engine correlation")
        )
        return result