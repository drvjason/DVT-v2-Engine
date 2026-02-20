from __future__ import annotations

import json
from datetime import datetime, timezone


def build_detection_playbook(
    scenario: str,
    techniques: list[str],
    query_templates: list[str],
    automation_logic: str,
) -> dict:
    return {
        "name": f"Playbook - {scenario[:40] or 'Untitled Scenario'}",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "scenario": scenario,
        "mitre_techniques": techniques,
        "query_templates": query_templates,
        "automation_logic": automation_logic,
        "workflow": [
            "Ingest scenario indicators",
            "Enrich with threat intelligence",
            "Deploy detection queries",
            "Validate hit quality",
            "Escalate to SOAR workflow",
            "Generate analyst documentation",
        ],
        "soar_export": {
            "trigger": "new_detection_match",
            "actions": [
                "enrich_host",
                "isolate_endpoint_if_high_risk",
                "create_ticket",
                "notify_on_call",
            ],
        },
    }


def to_json(playbook: dict) -> str:
    return json.dumps(playbook, indent=2)


def to_markdown(playbook: dict) -> str:
    lines = [f"# {playbook['name']}", "", "## Scenario", playbook["scenario"], ""]
    lines.extend(["## MITRE Techniques", ", ".join(playbook["mitre_techniques"]) or "None", ""])
    lines.append("## Query Templates")
    for q in playbook["query_templates"]:
        lines.append(f"- `{q}`")
    lines.append("")
    lines.append("## Workflow")
    for step in playbook["workflow"]:
        lines.append(f"- {step}")
    lines.append("")
    lines.append("## Automation Logic")
    lines.append(playbook["automation_logic"])
    return "\n".join(lines)
