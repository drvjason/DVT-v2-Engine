import os

import pytest

streamlit_testing = pytest.importorskip("streamlit.testing.v1")
AppTest = streamlit_testing.AppTest

pytestmark = [pytest.mark.integration]


def _apptest(project_root, monkeypatch):
    monkeypatch.setenv("RF_USER_ROLE", "admin")
    monkeypatch.setenv("RF_DEFAULT_MODEL", "local:deterministic")
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("GOOGLE_API_KEY", raising=False)
    return AppTest.from_file(str(project_root / "app.py"))


def _set_nav_page(at: AppTest, page_name: str) -> None:
    nav_radio = at.radio[0]
    nav_radio.set_value(page_name)
    at.run()


def test_navigation_and_theme_toggle(project_root, monkeypatch):
    at = _apptest(project_root, monkeypatch)
    at.run()

    assert at.radio[0].value == "Home / Intelligence Hub"

    # Light Mode toggle (top nav)
    light_toggle = [t for t in at.toggle if t.label == "Light Mode"][0]
    light_toggle.set_value(True)
    at.run()

    _set_nav_page(at, "MITRE ATT&CK Coverage Engine")
    assert at.radio[0].value == "MITRE ATT&CK Coverage Engine"


def test_model_selection_persistence(project_root, monkeypatch):
    at = _apptest(project_root, monkeypatch)
    at.run()

    model_box = [s for s in at.selectbox if s.label == "Active AI Model"][0]
    model_box.set_value("local:deterministic")
    at.run()

    _set_nav_page(at, "Threat Hunting Engine v2.0 (SPECTRA)")
    _set_nav_page(at, "Home / Intelligence Hub")

    model_box = [s for s in at.selectbox if s.label == "Active AI Model"][0]
    assert model_box.value == "local:deterministic"


def test_intelligence_result_rendering_and_exports(project_root, monkeypatch):
    at = _apptest(project_root, monkeypatch)
    at.run()

    _set_nav_page(at, "Threat Intelligence Engine")

    intel_input = [a for a in at.text_area if a.label == "Intelligence Input"][0]
    intel_input.set_value("actor=APT-X campaign=Night T1071 8.8.8.8 bad.example")
    at.run()

    run_button = [b for b in at.button if b.label == "Run Intelligence Enrichment"][0]
    run_button.click()
    at.run()

    # Results should render once package exists
    metric_labels = {m.label for m in at.metric}
    assert "Risk Severity" in metric_labels
    assert "Confidence" in metric_labels

    download_labels = {d.label for d in at.download_button}
    assert "JSON" in download_labels
    assert "STIX Format" in download_labels


def test_error_state_missing_provider_key(project_root, monkeypatch):
    at = _apptest(project_root, monkeypatch)
    at.run()

    # Force openai model without key and run generation to trigger provider error path
    model_box = [s for s in at.selectbox if s.label == "Active AI Model"][0]
    model_box.set_value("openai:gpt-4o")
    at.run()

    _set_nav_page(at, "Threat Intelligence Engine")
    intel_input = [a for a in at.text_area if a.label == "Intelligence Input"][0]
    intel_input.set_value("T1071 8.8.8.8 bad.example")
    at.run()

    [b for b in at.button if b.label == "Run Intelligence Enrichment"][0].click()
    at.run()

    warning_text = "\n".join(w.value for w in at.warning)
    assert "OPENAI_API_KEY is required" in warning_text


def test_playbook_flow_and_back_navigation(project_root, monkeypatch):
    at = _apptest(project_root, monkeypatch)
    at.run()

    _set_nav_page(at, "Playbook Builder")

    [i for i in at.text_input if i.label == "Threat Scenario"][0].set_value("Credential theft campaign")
    at.run()
    [b for b in at.button if b.label == "Generate Playbook"][0].click()
    at.run()

    # Back-to-home button appears after playbook generation
    [b for b in at.button if b.label == "Back to Home"][0].click()
    at.run()
    assert at.radio[0].value == "Home / Intelligence Hub"
