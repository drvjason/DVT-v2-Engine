import json

from soc_platform.engines.hunting import build_spectra_report
from soc_platform.engines.intelligence import build_intelligence_package
from soc_platform.engines.mitre import build_coverage, weighted_coverage_score
from soc_platform.engines.playbook import build_detection_playbook
from soc_platform.exports import build_professional_html_report


def test_integration_threat_intel_to_hunting_to_exports():
    input_text = (
        "actor=APT-42 campaign=NightPulse T1071 T1059 "
        "8.8.8.8 bad.example https://bad.example/c2"
    )
    package = build_intelligence_package(input_text, "Raw Threat Description")

    assert package.summary.actor == "APT-42"
    assert package.summary.campaign == "NightPulse"
    assert package.iocs.domains

    report = build_spectra_report(package)
    assert report["framework"] == "SPECTRA v2.0"

    coverage = build_coverage(package.summary.mitre_techniques)
    score = weighted_coverage_score(coverage)
    assert 0 <= score <= 100

    playbook = build_detection_playbook(
        scenario="NightPulse beaconing",
        techniques=package.summary.mitre_techniques,
        query_templates=[q.query for q in package.detection_queries[:2]],
        automation_logic="Contain if score >= 8",
    )
    assert playbook["mitre_techniques"]

    payload = {
        "executive_summary": package.summary.__dict__,
        "technical_analysis": {"context": package.campaign_context},
        "ioc_tables": package.iocs.__dict__,
        "detection_queries": [q.__dict__ for q in package.detection_queries],
        "hunt_workflow": package.hunting_playbook.__dict__,
        "risk_and_recommendations": {"risk_score": package.risk_score},
    }
    html = build_professional_html_report(payload, "Integration Report")
    assert "Integration Report" in html
    assert "Executive Summary" in html

    # Confirm serializability for API/export compatibility
    json.dumps(payload)
