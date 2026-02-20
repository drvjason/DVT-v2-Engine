from __future__ import annotations

import json
from datetime import datetime, timezone


def _timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def build_professional_html_report(payload: dict, title: str) -> str:
    """Dark-theme report suitable for browser print-to-PDF export."""
    return f"""
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>{title}</title>
<style>
:root {{
  color-scheme: dark;
  --bg:#0b0f14; --panel:#111722; --text:#edf2f7; --muted:#9aa6b2;
  --line:#253244; --accent:#20c997; --warn:#f59f00; --critical:#e03131;
}}
* {{ box-sizing:border-box; }}
body {{ margin:0; background:var(--bg); color:var(--text); font-family: "IBM Plex Sans", "Segoe UI", sans-serif; }}
.wrap {{ max-width:1040px; margin:0 auto; padding:32px; }}
.card {{ background:var(--panel); border:1px solid var(--line); border-radius:14px; padding:18px; margin-bottom:14px; }}
h1,h2,h3 {{ margin:0 0 10px; }}
pre {{ white-space:pre-wrap; background:#0e1520; border:1px solid var(--line); border-radius:10px; padding:12px; }}
.small {{ color:var(--muted); font-size:12px; }}
@media print {{
  @page {{ size: A4; margin: 0.5in; }}
  body {{ background:#000; color:#fff; }}
  .card {{ break-inside:avoid; }}
}}
</style>
</head>
<body>
<div class="wrap">
  <h1>{title}</h1>
  <div class="small">Generated {_timestamp()}</div>
  <div class="card"><h2>Executive Summary</h2><pre>{json.dumps(payload.get('executive_summary', {}), indent=2)}</pre></div>
  <div class="card"><h2>Technical Analysis</h2><pre>{json.dumps(payload.get('technical_analysis', {}), indent=2)}</pre></div>
  <div class="card"><h2>IOC Tables</h2><pre>{json.dumps(payload.get('ioc_tables', {}), indent=2)}</pre></div>
  <div class="card"><h2>Detection Queries</h2><pre>{json.dumps(payload.get('detection_queries', {}), indent=2)}</pre></div>
  <div class="card"><h2>Hunt Workflow</h2><pre>{json.dumps(payload.get('hunt_workflow', {}), indent=2)}</pre></div>
  <div class="card"><h2>Risk & Strategy</h2><pre>{json.dumps(payload.get('risk_and_recommendations', {}), indent=2)}</pre></div>
</div>
</body>
</html>
""".strip()


def build_executive_summary(payload: dict) -> str:
    return json.dumps(payload.get("executive_summary", {}), indent=2)


def build_word_technical_guide(payload: dict) -> str:
    """Return doc-compatible HTML content (download as .doc)."""
    tech = payload.get("technical_analysis", {})
    return f"<html><body><h1>Technical Guide</h1><pre>{json.dumps(tech, indent=2)}</pre></body></html>"


def build_detection_engineering_report(payload: dict) -> str:
    return json.dumps(payload.get("detection_queries", {}), indent=2)


def build_json(payload: dict) -> str:
    return json.dumps(payload, indent=2)
