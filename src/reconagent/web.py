"""
Web UI for ReconAgent. Thin FastAPI wrapper around the existing CLI
pipeline — reuses aggregator/correlator/opsec/llm_pivot/reporting as-is,
just exposes them over HTTP + a simple frontend instead of the terminal.

Run locally:
    pip install fastapi uvicorn
    uvicorn reconagent.web:app --reload

Deploy free: Render.com (Web Service, free tier) — see README "Deploy" section.
Vercel is not used for the live backend because Vercel's Python runtime is
serverless-function-only (short timeouts, no background jobs) and this tool
runs multi-second network scans; Render/Railway free tiers support a real
long-running process. Vercel can still host a static marketing/demo page
that links to the live Render backend if wanted.

SECURITY NOTES (relevant once this is deployed with a public URL):
- Per-IP rate limiting on /api/scan and /api/scan-file (in-memory sliding
  window) — without this, a public URL invites scripted abuse that burns
  through the free-tier API quotas (VirusTotal 500/day, Abstract 100/month)
  and hammers CPU/bandwidth on Render's free instance.
- File upload size cap (10 MB) — an unbounded upload endpoint on a free
  instance is an easy way to exhaust disk/memory.
- Job store TTL cleanup — the in-memory JOBS dict would otherwise grow
  forever under public traffic; entries older than 1 hour are pruned.
- SSRF protection lives in ssrf_guard.py, used by web_metadata.py (the
  collector that makes a direct HTTP request to the user-supplied domain)
  to refuse targets that resolve to private/internal/cloud-metadata IPs.
"""

from __future__ import annotations

import tempfile
import time
import uuid
from collections import defaultdict
from pathlib import Path

from dotenv import load_dotenv
from fastapi import FastAPI, File, HTTPException, Request as FastAPIRequest, UploadFile, Form
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from starlette.requests import Request

from reconagent.aggregator import run_recon
from reconagent.correlator import correlate
from reconagent.llm_pivot import summarize
from reconagent.opsec import build_opsec_findings
from reconagent.reporting import serialize_results
from reconagent.pii_extractor import extract_pii_findings
from reconagent.avatar_similarity import correlate_avatars
from reconagent.ocr_extraction import extract_text_via_ocr
from reconagent.stylometry import compare_writing_style
from reconagent.models import CollectorResult, Finding, Confidence

BASE_DIR = Path(__file__).resolve().parent.parent.parent / "webapp"  # <repo_root>/webapp/
_env_path = Path(__file__).resolve().parent.parent.parent / ".env"  # <repo_root>/.env
load_dotenv(_env_path)

app = FastAPI(title="ReconAgent")
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))


@app.exception_handler(Exception)
async def catch_all_exception_handler(request: FastAPIRequest, exc: Exception):
    """Without this, any unhandled exception anywhere in the request path
    (not just inside _run_and_store, which already has its own try/except)
    falls through to Starlette's default handler, which returns plain
    text/HTML — not JSON. The frontend always calls resp.json() on scan
    responses, so a plain-text error body crashes with a confusing
    'Unexpected token... is not valid JSON' instead of showing the real
    error. This guarantees every response is valid JSON, even on a genuine
    unhandled crash."""
    return JSONResponse(status_code=500, content={"detail": f"internal error: {exc}"})

# in-memory job store — fine for a demo/portfolio deploy, swap for Redis/DB for real multi-user use
JOBS: dict[str, dict] = {}
JOB_TTL_SECONDS = 3600  # prune job results after 1 hour so the dict doesn't grow forever

VALID_TEXT_TARGET_TYPES = {"domain", "username", "email", "phone"}
VALID_FILE_TARGET_TYPES = {"image", "pdf"}

MAX_UPLOAD_BYTES = 10 * 1024 * 1024  # 10 MB — generous for a photo/PDF, cheap to enforce

# --- simple in-memory per-IP rate limiter (sliding window) ---
# Good enough for a portfolio demo behind a single free-tier instance; a real
# multi-instance production deployment would use Redis instead, but that's
# overkill here — the point is having *some* limit, not perfect distributed
# accuracy.
RATE_LIMIT_WINDOW_S = 60
RATE_LIMIT_MAX_REQUESTS = 10
_request_log: dict[str, list[float]] = defaultdict(list)


def _check_rate_limit(client_ip: str) -> None:
    now = time.time()
    recent = [t for t in _request_log[client_ip] if now - t < RATE_LIMIT_WINDOW_S]
    if len(recent) >= RATE_LIMIT_MAX_REQUESTS:
        raise HTTPException(429, f"Rate limit: max {RATE_LIMIT_MAX_REQUESTS} scans per "
                                  f"{RATE_LIMIT_WINDOW_S}s per IP. Try again shortly.")
    recent.append(now)
    _request_log[client_ip] = recent


def _prune_old_jobs() -> None:
    now = time.time()
    stale = [jid for jid, job in JOBS.items() if now - job.get("_created_at", now) > JOB_TTL_SECONDS]
    for jid in stale:
        JOBS.pop(jid, None)


class ScanRequest(BaseModel):
    target: str
    target_type: str
    llm_backend: str = "none"


def _normalize_target(target: str, target_type: str) -> str:
    """People paste full URLs ('https://example.com/page') into a domain
    field constantly — every collector expects a bare hostname, so without
    this, WHOIS/DNS/crt.sh/etc all get garbage input and either fail or
    (worse) hang for the full timeout on something that was never going to
    resolve. Strip scheme + path down to just the hostname for domain
    targets."""
    if target_type != "domain":
        return target.strip()
    t = target.strip()
    if "://" in t:
        t = t.split("://", 1)[1]
    t = t.split("/", 1)[0]
    t = t.split("?", 1)[0]
    return t.strip().rstrip(".")


def _run_and_store(job_id: str, target: str, target_type: str, llm_backend: str, image_mode: str = "all") -> None:
    """Shared execution path for both text-target and file-upload scans."""
    try:
        results = run_recon(target, target_type, timeout_s=20)

        # AI enrichment step: NER-based PII extraction from free-text fields
        # (bios, WHOIS org names, search snippets) — adds new structured
        # findings that no collector explicitly parses for. Wrapped in a
        # synthetic CollectorResult so it flows through the same
        # serialize_results/reporting path as everything else.
        pii_findings = extract_pii_findings(results)

        # AI enrichment steps for uploaded images: face detection (classical
        # CV, detection only — never identification) and OCR text extraction
        # (real trained model, Tesseract) feeding straight into PII extraction.
        # Done BEFORE the pii_extractor CollectorResult is created below, so
        # OCR-derived PII findings end up in the same result card rather than
        # silently dropped if there was no bio-based PII to begin with.
        if target_type == "image" and image_mode in ("all", "ocr"):
            ocr_findings = extract_text_via_ocr(target)
            if ocr_findings:
                results.append(CollectorResult(collector="ocr_extraction", target=target, ok=True,
                                                findings=ocr_findings))
                pii_findings.extend(extract_pii_findings(
                    [CollectorResult(collector="ocr_extraction", target=target, ok=True, findings=ocr_findings)]
                ))

        if pii_findings:
            results.append(CollectorResult(collector="pii_extractor", target=target, ok=True,
                                            findings=pii_findings))

        # AI enrichment step: cross-account avatar image similarity via
        # perceptual hashing — flags when two different accounts
        # (GitHub/Gravatar/Bluesky) use the same or near-identical photo,
        # a real visual signal independent of username/text matching.
        avatar_matches = correlate_avatars(results)
        if avatar_matches:
            results.append(CollectorResult(
                collector="avatar_similarity", target=target, ok=True,
                findings=[Finding(source="avatar_similarity", category="matched_avatars",
                                   value=avatar_matches, confidence=Confidence.MEDIUM,
                                   notes="perceptual-hash matches across different accounts' profile photos")]
            ))

        # AI enrichment step: stylometric writing-style comparison across
        # bios from different accounts — classical authorship-attribution
        # technique (function-word frequency, sentence-length patterns).
        # Soft evidence, capped at low confidence, but a real signal no
        # other collector produces.
        style_matches = compare_writing_style(results)
        if style_matches:
            results.append(CollectorResult(
                collector="stylometry", target=target, ok=True,
                findings=[Finding(source="stylometry", category="writing_style_matches",
                                   value=style_matches, confidence=Confidence.LOW,
                                   notes="function-word/sentence-pattern similarity across bios — soft signal, verify manually")]
            ))

        correlation = correlate(results)
        opsec_findings = build_opsec_findings(results)
        llm_summary = summarize(results, correlation, backend=llm_backend)

        JOBS[job_id].update({
            "status": "done",
            "results": serialize_results(results),
            "location_candidates": correlation.location_candidates,
            "opsec_findings": [
                {"title": f.title, "severity": f.severity.value, "description": f.description,
                 "remediation": f.remediation, "evidence_sources": f.evidence_sources}
                for f in opsec_findings
            ],
            "llm_summary": llm_summary,
        })
    except Exception as e:  # noqa: BLE001 - surface the error to the frontend, don't 500 silently
        JOBS[job_id].update({"status": "error", "error": str(e)})


@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    return templates.TemplateResponse(request, "index.html", {})


@app.post("/api/scan")
def start_scan(req: ScanRequest, http_request: FastAPIRequest):
    _prune_old_jobs()
    client_ip = http_request.client.host if http_request.client else "unknown"
    _check_rate_limit(client_ip)

    if req.target_type not in VALID_TEXT_TARGET_TYPES:
        raise HTTPException(400, f"target_type must be one of {sorted(VALID_TEXT_TARGET_TYPES)}")

    normalized_target = _normalize_target(req.target, req.target_type)

    job_id = str(uuid.uuid4())[:8]
    JOBS[job_id] = {"status": "running", "target": normalized_target, "target_type": req.target_type,
                     "_created_at": time.time()}
    _run_and_store(job_id, normalized_target, req.target_type, req.llm_backend)
    return {"job_id": job_id, "status": JOBS[job_id]["status"]}


@app.post("/api/scan-file")
def start_file_scan(
    http_request: FastAPIRequest,
    target_type: str = Form(...),
    llm_backend: str = Form("none"),
    image_mode: str = Form("all"),
    file: UploadFile = File(...),
):
    """Runs image/PDF collectors (EXIF GPS+device metadata, PDF author/software
    metadata) against an uploaded file. Files are written to a temp path for
    the duration of the scan only, then deleted — nothing persists server-side.

    image_mode lets the caller scope an image scan to just one concern
    (face detection / OCR / metadata) instead of always running everything —
    added after real user feedback that running all 3 on every image made
    it harder to get a precise answer to a specific question."""
    _prune_old_jobs()
    client_ip = http_request.client.host if http_request.client else "unknown"
    _check_rate_limit(client_ip)

    if target_type not in VALID_FILE_TARGET_TYPES:
        raise HTTPException(400, f"target_type must be one of {sorted(VALID_FILE_TARGET_TYPES)}")

    job_id = str(uuid.uuid4())[:8]
    JOBS[job_id] = {"status": "running", "target": file.filename, "target_type": target_type,
                     "_created_at": time.time()}

    suffix = Path(file.filename or "").suffix
    total_bytes = 0
    with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as tmp:
        while chunk := file.file.read(1024 * 1024):
            total_bytes += len(chunk)
            if total_bytes > MAX_UPLOAD_BYTES:
                tmp.close()
                Path(tmp.name).unlink(missing_ok=True)
                raise HTTPException(413, f"File too large — max {MAX_UPLOAD_BYTES // (1024*1024)} MB")
            tmp.write(chunk)
        tmp_path = tmp.name

    try:
        _run_and_store(job_id, tmp_path, target_type, llm_backend, image_mode=image_mode)
    finally:
        Path(tmp_path).unlink(missing_ok=True)  # always clean up, even on error

    return {"job_id": job_id, "status": JOBS[job_id]["status"]}


@app.get("/api/scan/{job_id}")
def get_scan(job_id: str):
    job = JOBS.get(job_id)
    if not job:
        raise HTTPException(404, "job not found")
    # Safety net: json.dumps(default=str) here means if ANY collector ever
    # leaks a non-JSON-native object (datetime, a custom class, etc — this
    # is exactly what domain_whois.py did with raw datetime objects from
    # python-whois, which crashed this endpoint with a 500 until fixed at
    # the source), it gets stringified instead of crashing the whole
    # response. Fixing the root cause in each collector is still correct,
    # but this stops a similar bug in some future collector from taking
    # down the same endpoint the same way.
    import json
    return JSONResponse(content=json.loads(json.dumps(job, default=str)))


@app.get("/api/collectors")
def list_collectors():
    from reconagent.collectors import REGISTRY
    return {
        target_type: [{"name": c.name, "requires_key": c.requires_key} for c in collectors]
        for target_type, collectors in REGISTRY.items()
    }