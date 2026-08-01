from __future__ import annotations

import math
import re
from collections import Counter

from reconagent.models import CollectorResult

# Common English function words — their relative frequency is a well-
# established stylometric signal (people unconsciously use function words
# at a consistent personal rate regardless of topic, which is exactly why
# this works even when two bios are about completely different things).
_FUNCTION_WORDS = [
    "the", "a", "an", "and", "or", "but", "of", "in", "on", "at", "to",
    "for", "with", "is", "are", "was", "were", "i", "my", "me", "we",
    "you", "your", "it", "this", "that", "not", "just", "also", "very",
]


def _stylometric_vector(text: str) -> dict:
    words = re.findall(r"[a-zA-Z']+", text.lower())
    if not words:
        return {}
    word_count = len(words)
    sentence_count = max(len(re.findall(r"[.!?]+", text)), 1)

    vec = {
        "avg_word_length": sum(len(w) for w in words) / word_count,
        "avg_sentence_length": word_count / sentence_count,
        "exclamation_ratio": text.count("!") / max(len(text), 1),
    }
    word_freq = Counter(words)
    for fw in _FUNCTION_WORDS:
        vec[f"fw_{fw}"] = word_freq.get(fw, 0) / word_count
    return vec


def _cosine_similarity(v1: dict, v2: dict) -> float:
    keys = set(v1) | set(v2)
    dot = sum(v1.get(k, 0) * v2.get(k, 0) for k in keys)
    norm1 = math.sqrt(sum(v1.get(k, 0) ** 2 for k in keys))
    norm2 = math.sqrt(sum(v2.get(k, 0) ** 2 for k in keys))
    if norm1 == 0 or norm2 == 0:
        return 0.0
    return dot / (norm1 * norm2)


def compare_writing_style(results: list[CollectorResult]) -> list[dict]:
    """Compares bios/text samples collected from different accounts (e.g.
    GitHub bio vs. Bluesky bio) using classical stylometric features —
    function-word frequency, average word/sentence length, punctuation
    habits — a real, decades-old authorship-attribution technique. High
    similarity between two different accounts' writing style is a genuine
    (if soft) signal they may share an author, independent of whether the
    usernames or content topics look related at all.

    This is genuinely weaker evidence than avatar image matching — writing
    style CAN coincidentally overlap between different real people, so
    confidence is capped at 'low' regardless of score, positioned as a
    lead worth manual verification, not a confirmed match."""
    samples = []
    for r in results:
        if not r.ok:
            continue
        for f in r.findings:
            if f.category in ("bio", "gravatar_bio", "bluesky_bio") and isinstance(f.value, str):
                if len(f.value.split()) >= 8:  # too short to extract meaningful stylometric signal
                    samples.append((r.collector, f.value))

    if len(samples) < 2:
        return []

    vectors = [(c, t, _stylometric_vector(t)) for c, t in samples]
    matches = []
    for i in range(len(vectors)):
        for j in range(i + 1, len(vectors)):
            c1, t1, v1 = vectors[i]
            c2, t2, v2 = vectors[j]
            score = _cosine_similarity(v1, v2)
            if score >= 0.9:  # high bar — this is soft evidence, only surface strong matches
                matches.append({
                    "source_a": c1, "source_b": c2,
                    "similarity_score": round(score, 3),
                    "confidence": "low",
                })
    return matches