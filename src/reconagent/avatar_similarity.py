from __future__ import annotations

import io

import requests

from reconagent.models import CollectorResult

# Finding categories across existing collectors that carry a profile-photo
# URL — anywhere one of these shows up, it's a candidate for cross-account
# visual matching.
AVATAR_FINDING_CATEGORIES = {
    "gravatar_avatar_url",
    "github_avatar_url",
    "bluesky_avatar_url",
}

# Hamming distance threshold for two perceptual hashes to count as a real
# visual match — 0 is identical, higher tolerates cropping/resizing/minor
# edits. 8 is a commonly used threshold for "same image, different
# processing" in perceptual-hash literature; tightened slightly since a
# false "same person" claim is a meaningfully worse mistake than a missed one.
HASH_MATCH_THRESHOLD = 8


def _fetch_and_hash(url: str):
    try:
        import imagehash
        from PIL import Image
    except ImportError:
        return None
    try:
        resp = requests.get(url, timeout=10)
        resp.raise_for_status()
        img = Image.open(io.BytesIO(resp.content))
        return imagehash.phash(img)
    except Exception:  # noqa: BLE001
        return None


def correlate_avatars(results: list[CollectorResult]) -> list[dict]:
    """Compares profile photos collected across different sources (GitHub,
    Gravatar, Bluesky) using perceptual hashing (imagehash.phash) — real
    visual similarity, not string/username matching. If two different
    accounts use the same or a near-identical photo, that's a genuinely
    strong signal they belong to the same person, independent of whether
    the usernames look related at all.

    Uses perceptual hashing rather than a deep embedding model (e.g. CLIP)
    deliberately: phash needs no model download, runs instantly, and is
    the same class of technique real reverse-image-search tools use for
    "is this the same photo" — CLIP-style embeddings answer a different,
    fuzzier question ("is this visually similar content") that isn't what
    cross-account identity correlation actually needs.
    """
    avatars = []
    for r in results:
        if not r.ok:
            continue
        for f in r.findings:
            if f.category in AVATAR_FINDING_CATEGORIES and isinstance(f.value, str):
                avatars.append((r.collector, f.value))

    if len(avatars) < 2:
        return []

    hashed = []
    for collector, url in avatars:
        h = _fetch_and_hash(url)
        if h is not None:
            hashed.append((collector, url, h))

    matches = []
    for i in range(len(hashed)):
        for j in range(i + 1, len(hashed)):
            c1, url1, h1 = hashed[i]
            c2, url2, h2 = hashed[j]
            distance = h1 - h2
            if distance <= HASH_MATCH_THRESHOLD:
                matches.append({
                    "source_a": c1, "url_a": url1,
                    "source_b": c2, "url_b": url2,
                    "hash_distance": int(distance),
                    "confidence": "high" if distance <= 2 else "medium",
                })
    return matches