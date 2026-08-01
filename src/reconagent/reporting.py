"""
Report generation: JSON (machine-readable, for CI/tooling) and HTML
(recruiter/human-facing, dark "signal intelligence" visual style).
"""

from __future__ import annotations

import json
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

from jinja2 import Environment, BaseLoader, select_autoescape

from reconagent.correlator import CorrelationReport
from reconagent.models import CollectorResult, OpsecFinding

HTML_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>ReconAgent Report — {{ target }}</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
  :root{
    --bg:#0a0e17; --panel:#101623; --panel-hi:#151d2e; --line:#233047;
    --text:#e6ecf5; --muted:#7f8ba3; --cyan:#5be3ff; --violet:#a97dff;
    --high:#ff5d7a; --medium:#ffb454; --low:#5be3ff; --info:#7f8ba3;
    --mono:'IBM Plex Mono', ui-monospace, SFMono-Regular, Menlo, monospace;
    --sans:'Space Grotesk', 'Inter', system-ui, sans-serif;
  }
  *{box-sizing:border-box;}
  body{
    margin:0; background:var(--bg); color:var(--text); font-family:var(--sans);
    background-image:
      linear-gradient(var(--line) 1px, transparent 1px),
      linear-gradient(90deg, var(--line) 1px, transparent 1px);
    background-size:48px 48px; background-position:-1px -1px;
  }
  .wrap{max-width:1100px; margin:0 auto; padding:48px 24px 96px;}
  header{display:flex; align-items:baseline; justify-content:space-between; border-bottom:1px solid var(--line); padding-bottom:24px; margin-bottom:32px;}
  .eyebrow{font-family:var(--mono); font-size:12px; letter-spacing:.14em; color:var(--cyan); text-transform:uppercase;}
  h1{font-size:32px; margin:6px 0 0; font-weight:600; letter-spacing:-0.01em;}
  .meta{font-family:var(--mono); font-size:12px; color:var(--muted); text-align:right; line-height:1.7;}
  .scan{position:relative; height:2px; background:linear-gradient(90deg, transparent, var(--cyan), var(--violet), transparent); margin:0 0 40px; overflow:hidden;}
  .scan::after{content:''; position:absolute; inset:0; background:linear-gradient(90deg, transparent, #fff, transparent); width:30%; animation:sweep 3.2s ease-in-out infinite;}
  @keyframes sweep{0%{transform:translateX(-120%);}100%{transform:translateX(420%);}}
  @media (prefers-reduced-motion: reduce){.scan::after{animation:none;}}
  section{margin-bottom:40px;}
  .section-title{font-family:var(--mono); font-size:13px; letter-spacing:.08em; text-transform:uppercase; color:var(--muted); margin-bottom:14px; display:flex; align-items:center; gap:10px;}
  .section-title::before{content:''; width:8px; height:8px; background:var(--cyan); border-radius:1px; box-shadow:0 0 8px var(--cyan);}
  .summary-box{background:var(--panel); border:1px solid var(--line); border-radius:10px; padding:20px 24px; white-space:pre-wrap; font-family:var(--mono); font-size:13.5px; line-height:1.7; color:#d3dbea;}
  .grid{display:grid; grid-template-columns:repeat(auto-fit, minmax(260px,1fr)); gap:16px;}
  .card{background:var(--panel); border:1px solid var(--line); border-radius:10px; padding:18px 20px;}
  .card h3{margin:0 0 12px; font-size:14px; font-family:var(--mono); color:var(--cyan); display:flex; justify-content:space-between;}
  .card .status{font-size:11px; padding:2px 8px; border-radius:20px; font-family:var(--mono);}
  .status.ok{background:rgba(91,227,255,.12); color:var(--cyan);}
  .status.fail{background:rgba(255,93,122,.12); color:var(--high);}
  dl{margin:0; font-size:13px;}
  dt{color:var(--muted); font-family:var(--mono); font-size:11px; margin-top:10px; text-transform:uppercase; letter-spacing:.04em;}
  dd{margin:2px 0 0; word-break:break-word;}
  .opsec-item{border-left:3px solid var(--info); background:var(--panel); border-radius:0 10px 10px 0; padding:14px 18px; margin-bottom:12px;}
  .opsec-item.critical{border-color:var(--high);} .opsec-item.high{border-color:var(--high);}
  .opsec-item.medium{border-color:var(--medium);} .opsec-item.low{border-color:var(--low);}
  .sev-badge{font-family:var(--mono); font-size:10px; text-transform:uppercase; letter-spacing:.06em; padding:2px 8px; border-radius:20px; margin-right:8px;}
  .sev-badge.critical, .sev-badge.high{background:rgba(255,93,122,.15); color:var(--high);}
  .sev-badge.medium{background:rgba(255,180,84,.15); color:var(--medium);}
  .sev-badge.low{background:rgba(91,227,255,.15); color:var(--low);}
  .opsec-item h4{margin:6px 0 6px; font-size:15px;}
  .opsec-item p{margin:4px 0; font-size:13px; color:#c7d0e0;}
  .opsec-item .fix{color:var(--cyan);}
  .loc-row{display:flex; justify-content:space-between; align-items:center; padding:10px 0; border-bottom:1px solid var(--line); font-size:13px;}
  .loc-row:last-child{border-bottom:none;}
  .conf-tag{font-family:var(--mono); font-size:11px; padding:2px 8px; border-radius:20px;}
  .conf-tag.high{background:rgba(91,227,255,.15); color:var(--cyan);}
  .conf-tag.medium{background:rgba(169,125,255,.15); color:var(--violet);}
  .conf-tag.low{background:rgba(127,139,163,.15); color:var(--muted);}
  footer{margin-top:56px; padding-top:24px; border-top:1px solid var(--line); font-family:var(--mono); font-size:11px; color:var(--muted); text-align:center;}
</style>
</head>
<body>
<div class="wrap">
  <header>
    <div>
      <div class="eyebrow">ReconAgent // Passive OSINT Sweep</div>
      <h1>{{ target }}</h1>
    </div>
    <div class="meta">
      target_type: {{ target_type }}<br>
      generated: {{ generated_at }}<br>
      collectors_run: {{ results|length }}
    </div>
  </header>
  <div class="scan"></div>

  <section>
    <div class="section-title">AI Summary</div>
    <div class="summary-box">{{ llm_summary }}</div>
  </section>

  {% if location_candidates %}
  <section>
    <div class="section-title">Location Correlation</div>
    <div class="card">
      {% for loc in location_candidates %}
      <div class="loc-row">
        <span>{{ loc.value }}</span>
        <span>
          <span class="muted" style="font-family:var(--mono); font-size:11px; color:var(--muted);">{{ loc.supporting_sources|join(', ') }}</span>
          <span class="conf-tag {{ loc.confidence }}">{{ loc.confidence }}</span>
        </span>
      </div>
      {% endfor %}
    </div>
  </section>
  {% endif %}

  {% if opsec_findings %}
  <section>
    <div class="section-title">OPSEC Findings &amp; Remediation</div>
    {% for f in opsec_findings %}
    <div class="opsec-item {{ f.severity.value }}">
      <span class="sev-badge {{ f.severity.value }}">{{ f.severity.value }}</span>
      <h4>{{ f.title }}</h4>
      <p>{{ f.description }}</p>
      <p class="fix">Fix: {{ f.remediation }}</p>
      <p style="color:var(--muted); font-size:11px;">source: {{ f.evidence_sources|join(', ') }}</p>
    </div>
    {% endfor %}
  </section>
  {% endif %}

  <section>
    <div class="section-title">Collector Results</div>
    <div class="grid">
      {% for r in results %}
      <div class="card">
        <h3>{{ r.collector }} <span class="status {{ 'ok' if r.ok else 'fail' }}">{{ 'OK' if r.ok else 'N/A' }}</span></h3>
        {% if r.error %}
          <p style="color:var(--muted); font-size:12px;">{{ r.error }}</p>
        {% endif %}
        <dl>
          {% for f in r.findings %}
            <dt>{{ f.category }}</dt>
            <dd>{{ f.value }}</dd>
          {% endfor %}
        </dl>
      </div>
      {% endfor %}
    </div>
  </section>

  <footer>
    Passive, publicly-sourced data only. Generated by ReconAgent v0.1 for authorized security research use.
  </footer>
</div>
</body>
</html>
"""


def serialize_results(results: list[CollectorResult]) -> list[dict]:
    out = []
    for r in results:
        out.append({
            "collector": r.collector, "target": r.target, "ok": r.ok, "error": r.error,
            "duration_ms": r.duration_ms,
            "findings": [
                {"source": f.source, "category": f.category, "value": f.value,
                 "confidence": f.confidence.value, "notes": f.notes}
                for f in r.findings
            ],
        })
    return out


def write_json_report(path: str, target: str, target_type: str,
                       results: list[CollectorResult], correlation: CorrelationReport,
                       opsec_findings: list[OpsecFinding], llm_summary: str) -> None:
    payload = {
        "target": target,
        "target_type": target_type,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "llm_summary": llm_summary,
        "results": serialize_results(results),
        "location_candidates": correlation.location_candidates,
        "correlation_edges": [asdict(e) for e in correlation.edges],
        "opsec_findings": [
            {"title": f.title, "severity": f.severity.value, "description": f.description,
             "remediation": f.remediation, "evidence_sources": f.evidence_sources}
            for f in opsec_findings
        ],
    }
    Path(path).write_text(json.dumps(payload, indent=2, default=str))


def write_html_report(path: str, target: str, target_type: str,
                       results: list[CollectorResult], correlation: CorrelationReport,
                       opsec_findings: list[OpsecFinding], llm_summary: str) -> None:
    env = Environment(loader=BaseLoader(), autoescape=select_autoescape())
    template = env.from_string(HTML_TEMPLATE)
    html = template.render(
        target=target, target_type=target_type,
        generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        results=results, location_candidates=correlation.location_candidates,
        opsec_findings=opsec_findings, llm_summary=llm_summary,
    )
    Path(path).write_text(html)
