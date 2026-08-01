"""
LLM layer, two jobs:
1. Summarize the raw findings + correlation report into plain-English recon narrative.
2. Suggest the next pivot (agentic reasoning) — e.g. "GitHub commit leaked an
   email, worth running that through the email/DNS collector next."

Pluggable connector pattern, same as the Red Team Framework: swap backend via
--llm-backend flag. Falls back to a template-based summary (no LLM call) if
neither Ollama nor Groq is reachable/configured, so the tool never hard-fails
just because a model isn't running.
"""

from __future__ import annotations

import json
import os

from reconagent.correlator import CorrelationReport
from reconagent.models import CollectorResult

SYSTEM_PROMPT = """You are a defensive security analyst summarizing a passive OSINT \
recon sweep for the target's own security team. Write in plain English. Be factual, \
don't speculate beyond the data given. Structure your answer as:
1. Summary (3-5 sentences)
2. Key exposures (bullet list)
3. Suggested next pivot (one sentence: what to investigate next and why)
Do not invent data not present in the findings."""


def summarize(results: list[CollectorResult], correlation: CorrelationReport,
              backend: str = "none") -> str:
    findings_json = _results_to_json(results, correlation)

    if backend == "ollama":
        text = _call_ollama(findings_json)
        if text:
            return text
    elif backend == "groq":
        text = _call_groq(findings_json)
        if text:
            return text

    return _template_summary(results, correlation)


def _results_to_json(results: list[CollectorResult], correlation: CorrelationReport) -> str:
    payload = {
        "collectors": [
            {
                "collector": r.collector, "ok": r.ok, "error": r.error,
                "findings": [
                    {"category": f.category, "value": f.value, "confidence": f.confidence.value}
                    for f in r.findings
                ],
            }
            for r in results
        ],
        "location_candidates": correlation.location_candidates,
        "correlation_edge_count": len(correlation.edges),
    }
    return json.dumps(payload, default=str)[:12000]  # keep prompt bounded


def _call_ollama(findings_json: str) -> str | None:
    try:
        import ollama
        resp = ollama.chat(model=os.getenv("RECON_OLLAMA_MODEL", "llama3"), messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": findings_json},
        ])
        return resp["message"]["content"]
    except Exception:  # noqa: BLE001 - Ollama not running/installed -> fall back silently
        return None


def _call_groq(findings_json: str) -> str | None:
    api_key = os.getenv("GROQ_API_KEY")
    if not api_key:
        return None
    try:
        from groq import Groq
        client = Groq(api_key=api_key)
        resp = client.chat.completions.create(
            model=os.getenv("RECON_GROQ_MODEL", "llama-3.1-8b-instant"),
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": findings_json},
            ],
        )
        return resp.choices[0].message.content
    except Exception:  # noqa: BLE001
        return None


def _template_summary(results: list[CollectorResult], correlation: CorrelationReport) -> str:
    """No-LLM fallback: deterministic plain-text summary from raw counts."""
    ok_collectors = [r for r in results if r.ok]
    total_findings = sum(len(r.findings) for r in ok_collectors)
    lines = [
        f"Summary: {len(ok_collectors)}/{len(results)} collectors returned data, "
        f"{total_findings} total findings, {len(correlation.edges)} cross-source correlations.",
        "",
        "Key exposures:",
    ]
    for r in ok_collectors:
        for f in r.findings[:3]:
            lines.append(f"  - [{r.collector}] {f.category}: {str(f.value)[:120]}")
    if correlation.location_candidates:
        top = correlation.location_candidates[0]
        lines.append("")
        lines.append(
            f"Suggested next pivot: strongest location signal is {top['value']} "
            f"(confidence: {top['confidence']}, {len(top['supporting_sources'])} sources agree) "
            f"— worth manual verification."
        )
    return "\n".join(lines)
