# Architecture

```
                    ┌─────────────────────────────┐
                    │   CLI (cli.py)               │
                    │   reconagent run --target …  │
                    └───────────────┬──────────────┘
                                    │
                                    ▼
                    ┌─────────────────────────────┐
                    │ Aggregator (aggregator.py)   │
                    │ - looks up collectors for    │
                    │   target_type via registry   │
                    │ - runs all in a thread pool  │
                    │ - per-collector timeout +    │
                    │   exception isolation        │
                    └───────────────┬──────────────┘
                                    │  list[CollectorResult]
                     ┌──────────────┼──────────────┐
                     ▼              ▼              ▼
              collectors/    collectors/    collectors/
              domain_whois   username_...   exif_metadata
              dns_records    github_...     pdf_metadata
              crtsh_...                     ...
              (13 total, one file each, BaseCollector interface)
                     │              │              │
                     └──────────────┼──────────────┘
                                    ▼
                    ┌─────────────────────────────┐
                    │ Correlator (correlator.py)   │
                    │ - pairwise value overlap     │
                    │   across different sources   │
                    │ - location signal clustering │
                    │   with confidence scoring    │
                    └───────────────┬──────────────┘
                                    ▼
                    ┌─────────────────────────────┐
                    │ OPSEC layer (opsec.py)       │
                    │ - rule table: finding        │
                    │   category → exposure title  │
                    │   + severity + remediation    │
                    └───────────────┬──────────────┘
                                    ▼
                    ┌─────────────────────────────┐
                    │ LLM summarizer (llm_pivot.py)│
                    │ - Ollama / Groq / template    │
                    │   fallback (never hard-fails) │
                    └───────────────┬──────────────┘
                                    ▼
                    ┌─────────────────────────────┐
                    │ Reporting (reporting.py)     │
                    │ - JSON (machine-readable)     │
                    │ - HTML (dark, recruiter-facing│
                    └─────────────────────────────┘
```

## Design decisions worth defending in an interview

**Why per-collector fault isolation instead of one big try/except?**
One flaky API (rate-limited, timed out, deprecated) shouldn't silently kill
the entire recon run. Each collector's failure is captured in its own
`CollectorResult.error` field and shown to the user — transparent, not
swallowed.

**Why a registry dict instead of auto-discovery/plugin loading?**
Explicit is better than magic for a security tool — you can see exactly
which collectors run for which target type by reading one file
(`collectors/__init__.py`), no import-time side effects, no accidentally
running a collector you didn't mean to enable.

**Why rule-based OPSEC mapping instead of an LLM judgment call?**
Same philosophy as the Red Team Framework's detector: deterministic,
explainable, free to run, and every verdict traces back to a specific rule
you can point to and defend — not a model's opinion that could vary run to
run.

**Why does the LLM layer degrade to a template instead of failing?**
A recon tool that hard-fails because Ollama isn't running defeats the
purpose of a portfolio project someone else might try to run. The
deterministic fallback guarantees the CLI always produces a usable report.

**Why is location correlation confidence-scored rather than a single guess?**
One weak signal (e.g. IP geolocation, which is only city-level and often
wrong) shouldn't be presented with the same confidence as three independent
sources agreeing. The `Confidence` enum threading through every layer keeps
that distinction visible all the way to the final report.
