# ReconAgent — AI-Powered Passive OSINT Recon Framework

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](pyproject.toml)

**Live demo:** _add your Render URL here once deployed, e.g. https://reconagent-web.onrender.com_

![ReconAgent UI](docs/screenshots/screenshot_1_home.png)

Automated reconnaissance tool that aggregates **public, passive-only** data
across domain, username, email, phone, and file-metadata vectors, cross-
correlates findings for higher-confidence signal (e.g. location clustering),
flags what the target is unknowingly exposing (OPSEC layer), and generates
an LLM-summarized recon report.

Companion project to an LLM Prompt Injection & Red-Team Testing Framework
(not yet published — link added here once it's live) —
same modular plugin architecture, same honesty-over-certainty detection
philosophy, applied to OSINT instead of adversarial LLM testing.

## What makes this "not a toy"

- **25+ real collectors** across domain, username, email, phone, image, and
  PDF targets — most free/no-key, a handful optional-key (VirusTotal,
  Abstract Phone Intelligence, Telegram Bot API) — every one backed by a
  genuinely free, currently-working public API or offline library, verified
  as of July 2026 (see `docs/SOURCES.md` for the full audit, including
  sources deliberately excluded and why — e.g. OpenCorporates turned out to
  require a paid plan and was removed after being wrongly assumed free).
- **Passive only.** No login-wall scraping, no breach-DB credential lookups,
  no dark-web access. Every source here is one an unauthenticated visitor
  or a public API could reach. This is a deliberate legal/ethical boundary,
  not a limitation of what was possible to build — see `docs/SCOPE.md`.
- **Cross-source correlation**, not just data dumping — `correlator.py`
  clusters agreeing signals (e.g. WHOIS country + IP geolocation + phone
  region) into a confidence-scored location estimate.
- **OPSEC framing** — every finding that represents an exposure gets mapped
  to a remediation recommendation, turning this from "recon tool" into
  "defensive security tooling."
- **Security-hardened for public deployment** — per-IP rate limiting,
  upload size caps, job-store expiry, and SSRF protection (blocks requests
  to private/internal/cloud-metadata IP ranges) — see `docs/SCOPE.md`.
- **LLM-agnostic summarizer** — Ollama (local) or Groq (API) for narrative
  summary + next-pivot suggestion; degrades gracefully to a deterministic
  template if no LLM backend is configured, so the tool never hard-fails.

## Web UI

A dark-console web UI (`webapp/`) wraps the same pipeline over FastAPI —
run scans from a browser instead of the terminal, including drag-drop image
and PDF upload for EXIF/metadata analysis.

```bash
git clone <this-repo>
cd osint-recon-agent
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[web]"
cp .env.example .env   # optional — fill in keys for the optional-key collectors
uvicorn reconagent.web:app --reload
# open http://127.0.0.1:8000
```

### Optional API keys

All keyed collectors skip cleanly with a clear message if their key is
missing — nothing crashes, you just get fewer findings for that source.
Add whichever you want to `.env` (never commit this file — it's gitignored):

```bash
ABSTRACTAPI_PHONE_KEY=...   # abstractapi.com - free, 100 req/month, no card
TELEGRAM_BOT_TOKEN=...      # message @BotFather on Telegram, /newbot - free, instant
VIRUSTOTAL_API_KEY=...      # virustotal.com/gui/join-us - free, 500 req/day, no card
GROQ_API_KEY=...            # console.groq.com - free tier, for --llm-backend groq
```

### Deploy free

**Render.com (recommended)** — `render.yaml` is included.
1. Push this repo to GitHub.
2. On render.com → New → Blueprint → connect the repo → it reads `render.yaml`
   automatically → Free plan → deploy.
3. Add your env vars in Render's dashboard (Environment tab), not in the repo.
4. Live URL looks like `https://reconagent-web.onrender.com`.

Why not GitHub Pages or Vercel for the backend: GitHub Pages only serves
static files, no server-side code at all. Vercel's Python support is
serverless-function-only (cold starts, short execution limits), and this
tool runs multi-second live network scans across many collectors in
parallel — that needs a real long-running process, which Render/Railway's
free tier gives you. You can still host a static landing page on GitHub
Pages/Vercel that links to the live Render backend if you want a
`yourname.github.io` or `yourname.vercel.app` URL to share.

**Railway** works the same way as Render if you prefer it — same
buildCommand/startCommand from `render.yaml`, just paste them into Railway's
service settings.

## Quickstart (CLI)

```bash
pip install -e .
reconagent list-collectors
reconagent run --target example.com --type domain --out report --format html --format json
reconagent run --target octocat --type username --out report
```

## AI/ML enrichment (real techniques, not LLM-summary buzzwords)

- **NER-based PII extraction** (spaCy) — pulls names/orgs/locations/phones/
  emails out of bios and OCR'd text automatically
- **Avatar image-similarity matching** (perceptual hashing) — flags when two
  different accounts use the same profile photo, a real cross-platform
  identity signal independent of usernames
- **OCR text extraction** (Tesseract, with real image preprocessing) — turns
  uploaded screenshots/documents/business cards into searchable text, which
  then feeds into PII extraction
- **Stylometric writing-style comparison** (classical NLP) — soft signal
  comparing bio writing patterns across accounts
- **Fuzzy correlation** (rapidfuzz) — catches location/entity matches that
  exact-string comparison misses

Honestly: 1 of these (spaCy NER) is genuine machine learning; the rest are
real, valuable classical algorithms (signal processing, string similarity,
feature engineering) — not "AI" in the trained-model sense. Labeled
accurately rather than oversold. A face-detection module was built, fixed
through a real OpenCV 5.0 API-removal bug, then deliberately removed after
concluding it added no value for this tool's single-image-upload interface
(see `docs/SOURCES.md` for the full reasoning).

## Architecture

```
Collector layer (25+ pluggable modules, one per source)
        |
        v
Aggregator (parallel run, per-collector fault isolation, timeouts)
        |
        v
Correlator (cross-source agreement -> confidence-scored location clusters)
        |
        v
OPSEC layer (finding -> exposure title + severity + remediation)
        |
        v
LLM summarizer (Ollama/Groq/template fallback)
        |
        v
Reporting (JSON + dark-themed HTML report, or the web UI)
```

See `docs/ARCHITECTURE.md` for the full design doc.

## Scope & legal boundary

This tool intentionally does not implement: dark-web scraping, breach-DB
credential lookups without an authorized paid API, login-walled social
scraping, or people-search-broker aggregation. These aren't missing
features — they're a documented boundary. See `docs/SCOPE.md`.

## Documentation

- `docs/ARCHITECTURE.md` — full design doc and rationale for key decisions
- `docs/SOURCES.md` — audit of every data source, verified-free status, and
  what was deliberately excluded (and why)
- `docs/SCOPE.md` — the legal/ethical boundary this tool holds, explained
- `docs/INTERVIEW_QA.md` — real bugs found and fixed during development,
  written as interview-prep answers

## License

MIT — see LICENSE.