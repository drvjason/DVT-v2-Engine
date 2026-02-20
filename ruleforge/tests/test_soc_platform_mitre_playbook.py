from soc_platform.engines.mitre import build_coverage, extract_techniques, weighted_coverage_score
from soc_platform.engines.playbook import build_detection_playbook, to_json, to_markdown


def test_extract_techniques_deduplicates_subtechniques():
    text = "T1059.001 T1059 T1071 T1071.001"
    techniques = extract_techniques(text)
    assert "T1059" in techniques
    assert "T1071" in techniques
    assert len(techniques) == 2


def test_mitre_coverage_scoring_and_rows():
    rows = build_coverage(["T1071", "T1059", "T1105"])
    assert len(rows) > 0
    assert 0 <= weighted_coverage_score(rows) <= 100
    assert all("tactic" in row and "coverage_score" in row for row in rows)


def test_playbook_builder_and_exports():
    playbook = build_detection_playbook(
        scenario="Suspicious beaconing from finance endpoints",
        techniques=["T1071", "T1059"],
        query_templates=["index=* beacon=true", "DeviceNetworkEvents | where RemoteIP != ''"],
        automation_logic="If risk_score >= 8 then isolate endpoint.",
    )

    assert playbook["scenario"].startswith("Suspicious beaconing")
    assert "T1071" in playbook["mitre_techniques"]

    json_out = to_json(playbook)
    md_out = to_markdown(playbook)

    assert "Playbook -" in json_out
    assert "# Playbook -" in md_out
    assert "## Workflow" in md_out
