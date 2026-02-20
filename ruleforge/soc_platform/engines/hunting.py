from __future__ import annotations

import json
from dataclasses import asdict

from soc_platform.models import HuntingPlaybook, IntelligencePackage


def spectra_severity_model(package: IntelligencePackage) -> dict:
    """Weighted severity score 0-10 for SPECTRA lifecycle outputs."""
    weights = {
        "ioc_density": 0.20,
        "mitre_coverage": 0.20,
        "behavioral_complexity": 0.20,
        "infrastructure_reuse": 0.20,
        "confidence": 0.20,
    }
    ioc_density = min((len(package.iocs.ips) + len(package.iocs.domains) + len(package.iocs.hashes)) / 20, 1.0)
    mitre_coverage = min(len(package.summary.mitre_techniques) / 10, 1.0)
    behavioral_complexity = min(len(package.behavior_patterns) / 5, 1.0)
    infra_reuse = 0.8 if package.campaign_context else 0.4
    confidence = package.summary.confidence

    normalized = (
        ioc_density * weights["ioc_density"]
        + mitre_coverage * weights["mitre_coverage"]
        + behavioral_complexity * weights["behavioral_complexity"]
        + infra_reuse * weights["infrastructure_reuse"]
        + confidence * weights["confidence"]
    )
    score = round(normalized * 10, 2)
    return {
        "score_0_10": score,
        "weights": weights,
        "components": {
            "ioc_density": round(ioc_density, 2),
            "mitre_coverage": round(mitre_coverage, 2),
            "behavioral_complexity": round(behavioral_complexity, 2),
            "infrastructure_reuse": round(infra_reuse, 2),
            "confidence": round(confidence, 2),
        },
        "response_tier": response_tier(score),
    }


def response_tier(score: float) -> str:
    if score >= 8:
        return "Critical - Immediate Containment"
    if score >= 6:
        return "High - Accelerated Investigation"
    if score >= 4:
        return "Medium - Full Hunt Workflow"
    return "Low - Monitor and Enrich"


def build_spectra_report(package: IntelligencePackage) -> dict:
    severity = spectra_severity_model(package)
    playbook: HuntingPlaybook = package.hunting_playbook
    return {
        "framework": "SPECTRA v2.0",
        "lifecycle": {
            "Prepare": [
                "Confirm telemetry availability and retention windows.",
                "Load IOC watchlists and prior campaign notes.",
            ],
            "Execute": playbook.pivots,
            "Act": playbook.containment,
            "Knowledge": [
                "Document confirmed TTPs and update hunting heuristics.",
                "Version detection logic and capture lessons learned.",
            ],
        },
        "mitre_mapping": package.summary.mitre_techniques,
        "multi_tool_queries": [asdict(query) for query in package.detection_queries],
        "severity": severity,
        "workflow": asdict(playbook),
        "operational_procedures": [
            "Triage affected assets",
            "Pivot across identity/network/endpoint telemetry",
            "Escalate to incident response if score >= 8",
            "Archive hunt artifacts for replay",
        ],
        "installation": [
            "pip install -r requirements.txt",
            "streamlit run app.py",
            "Use JSON/TXT export from this page for CLI workflows",
        ],
    }


def export_spectra_json(report: dict) -> str:
    return json.dumps(report, indent=2)


def export_spectra_txt(report: dict) -> str:
    lines = ["Project SPECTRA Threat Hunting Report", "=" * 40, ""]
    lines.append(f"Response Tier: {report['severity']['response_tier']}")
    lines.append(f"Score (0-10): {report['severity']['score_0_10']}")
    lines.append("")
    for phase, items in report["lifecycle"].items():
        lines.append(f"{phase}:")
        for item in items:
            lines.append(f"- {item}")
        lines.append("")
    return "\n".join(lines)
