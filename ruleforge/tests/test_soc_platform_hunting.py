from soc_platform.engines.hunting import (
    build_spectra_report,
    export_spectra_json,
    export_spectra_txt,
    response_tier,
    spectra_severity_model,
)
from soc_platform.engines.intelligence import build_intelligence_package


def test_spectra_lifecycle_structure_present():
    package = build_intelligence_package("T1071 8.8.8.8 bad.example", "Raw Threat Description")
    report = build_spectra_report(package)

    assert report["framework"] == "SPECTRA v2.0"
    assert set(report["lifecycle"].keys()) == {"Prepare", "Execute", "Act", "Knowledge"}
    assert report["severity"]["score_0_10"] >= 0


def test_weighted_severity_scoring_and_response_tier():
    package = build_intelligence_package("T1071 T1059 8.8.8.8 bad.example", "Campaign Name")
    severity = spectra_severity_model(package)

    assert 0 <= severity["score_0_10"] <= 10
    assert severity["response_tier"] in {
        "Critical - Immediate Containment",
        "High - Accelerated Investigation",
        "Medium - Full Hunt Workflow",
        "Low - Monitor and Enrich",
    }


def test_response_tier_boundaries():
    assert response_tier(8.1) == "Critical - Immediate Containment"
    assert response_tier(6.5) == "High - Accelerated Investigation"
    assert response_tier(4.2) == "Medium - Full Hunt Workflow"
    assert response_tier(2.2) == "Low - Monitor and Enrich"


def test_spectra_exports_json_and_txt_formatting():
    package = build_intelligence_package("T1071 bad.example", "Domain")
    report = build_spectra_report(package)

    json_out = export_spectra_json(report)
    txt_out = export_spectra_txt(report)

    assert '"framework": "SPECTRA v2.0"' in json_out
    assert "Project SPECTRA Threat Hunting Report" in txt_out
    assert "Response Tier:" in txt_out
