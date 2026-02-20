from soc_platform.exports import (
    build_detection_engineering_report,
    build_executive_summary,
    build_json,
    build_professional_html_report,
    build_word_technical_guide,
)


def _sample_payload() -> dict:
    return {
        "executive_summary": {"severity": 8, "actor": "APT-X"},
        "technical_analysis": {"techniques": ["T1071"]},
        "ioc_tables": {"ips": ["8.8.8.8"]},
        "detection_queries": [{"platform": "Splunk", "query": "index=*"}],
        "hunt_workflow": {"steps": ["triage"]},
        "risk_and_recommendations": {"risk_score": 8.1},
    }


def test_export_formatting_json_pdf_word():
    payload = _sample_payload()

    html = build_professional_html_report(payload, "Test Report")
    summary = build_executive_summary(payload)
    word = build_word_technical_guide(payload)
    det = build_detection_engineering_report(payload)
    obj_json = build_json(payload)

    assert "<html" in html.lower()
    assert "color-scheme: dark" in html
    assert '"severity": 8' in summary
    assert "<h1>Technical Guide</h1>" in word
    assert '"platform": "Splunk"' in det
    assert '"risk_score": 8.1' in obj_json
