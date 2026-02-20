#!/usr/bin/env python3
"""RuleForge SOC-Grade Threat Intelligence & Threat Hunting Platform."""

from __future__ import annotations

import json
import os
import re
from dataclasses import asdict

import streamlit as st

from soc_platform.ai.providers import MODEL_REGISTRY, create_provider, model_choices
from soc_platform.ai.providers.base import AIProviderError
from soc_platform.config import load_config
from soc_platform.engines.intelligence import build_intelligence_package, package_to_stix_like
from soc_platform.engines.hunting import build_spectra_report, export_spectra_json, export_spectra_txt
from soc_platform.engines.mitre import build_coverage, extract_techniques, weighted_coverage_score
from soc_platform.engines.playbook import build_detection_playbook, to_json, to_markdown
from soc_platform.exports import (
    build_detection_engineering_report,
    build_executive_summary,
    build_json,
    build_professional_html_report,
    build_word_technical_guide,
)
from soc_platform.governance import (
    TokenMonitor,
    audit_ai_request,
    can_use_model,
    default_rate_limiter,
    policy_for_role,
)
from soc_platform.ui import inject_theme, section_card, top_nav


PAGES = [
    "Home / Intelligence Hub",
    "Threat Intelligence Engine",
    "Threat Hunting Engine v2.0 (SPECTRA)",
    "MITRE ATT&CK Coverage Engine",
    "Playbook Builder",
]

INTEL_INPUT_TYPES = [
    "URL",
    "Domain",
    "IP Address",
    "File Hash (MD5/SHA1/SHA256)",
    "Malware Sample Reference",
    "Campaign Name",
    "Raw Threat Description",
    "Arbitrary Intelligence Text",
]


st.set_page_config(
    page_title="RuleForge SOC Intelligence Platform",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed",
)


config = load_config()

if "theme" not in st.session_state:
    st.session_state["theme"] = config.default_theme
if "active_page" not in st.session_state:
    st.session_state["active_page"] = PAGES[0]
if "intel_package" not in st.session_state:
    st.session_state["intel_package"] = None
if "detection_versions" not in st.session_state:
    st.session_state["detection_versions"] = []
if "analyst_notes" not in st.session_state:
    st.session_state["analyst_notes"] = ""
if "model_choice" not in st.session_state:
    st.session_state["model_choice"] = (
        config.default_model if config.default_model in model_choices() else "local:deterministic"
    )
if "model_temperature" not in st.session_state:
    st.session_state["model_temperature"] = 0.2
if "model_streaming" not in st.session_state:
    st.session_state["model_streaming"] = False
if "model_max_tokens" not in st.session_state:
    st.session_state["model_max_tokens"] = 1200
if "system_prompt" not in st.session_state:
    st.session_state["system_prompt"] = (
        "You are a SOC analyst assistant. Produce concise, operationally actionable outputs."
    )
if "ai_audit_trail" not in st.session_state:
    st.session_state["ai_audit_trail"] = []
if "rate_limiter" not in st.session_state:
    st.session_state["rate_limiter"] = default_rate_limiter()
if "token_monitor" not in st.session_state:
    st.session_state["token_monitor"] = TokenMonitor()
if "current_playbook" not in st.session_state:
    st.session_state["current_playbook"] = None
if "last_report_ai" not in st.session_state:
    st.session_state["last_report_ai"] = ""

inject_theme(st.session_state["theme"])
selected_page = top_nav(config.app_name, PAGES, st.session_state["active_page"])
st.session_state["active_page"] = selected_page

if not config.has_llm_keys:
    st.info(
        "LLM keys are not configured in environment secrets. "
        "Set `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, and/or `GOOGLE_API_KEY` in env or Streamlit secrets."
    )


def _run_ai_action(action: str, prompt: str):
    principal = os.environ.get("RF_PRINCIPAL", "local-user")
    role = config.user_role
    model_key = st.session_state["model_choice"]
    if not can_use_model(role, model_key):
        audit_ai_request(principal, role, action, model_key, False, 0)
        return None, "Your role cannot use this model."
    if not st.session_state["rate_limiter"].allow(principal):
        audit_ai_request(principal, role, action, model_key, False, 0)
        return None, "Rate limit exceeded. Try again shortly."

    provider = create_provider(
        model_key,
        temperature=st.session_state["model_temperature"],
        streaming=st.session_state["model_streaming"],
        max_tokens=int(st.session_state["model_max_tokens"]),
        system_prompt=str(st.session_state["system_prompt"]),
    )
    try:
        result = getattr(provider, action)(prompt)
    except AIProviderError as exc:
        audit_ai_request(principal, role, action, model_key, False, 0)
        return None, f"{exc.provider}/{exc.model}: {exc}"
    except Exception as exc:  # noqa: BLE001
        audit_ai_request(principal, role, action, model_key, False, 0)
        return None, f"Unhandled AI provider failure: {exc}"
    st.session_state["token_monitor"].add(principal, result.estimated_tokens)
    trail_event = {
        "action": action,
        "provider": result.provider,
        "model": result.model,
        "tokens": result.estimated_tokens,
    }
    st.session_state["ai_audit_trail"].append(trail_event)
    audit_ai_request(principal, role, action, model_key, True, result.estimated_tokens)
    return result, None


policy = policy_for_role(config.user_role)
allowed_models = [k for k in model_choices() if can_use_model(config.user_role, k)]
if not allowed_models:
    allowed_models = ["local:deterministic"]
if st.session_state["model_choice"] not in allowed_models:
    st.session_state["model_choice"] = allowed_models[0]

cp1, cp2, cp3, cp4, cp5 = st.columns([2.2, 1.0, 1.0, 1.0, 1.6])
with cp1:
    selected_model = st.selectbox(
        "Active AI Model",
        allowed_models,
        index=allowed_models.index(st.session_state["model_choice"]),
        format_func=lambda k: MODEL_REGISTRY[k].label,
        disabled=not policy.allow_model_selection,
    )
    st.session_state["model_choice"] = selected_model
with cp2:
    st.session_state["model_temperature"] = st.slider(
        "Temperature",
        min_value=0.0,
        max_value=1.0,
        value=float(st.session_state["model_temperature"]),
        step=0.05,
    )
with cp3:
    st.session_state["model_streaming"] = st.toggle(
        "Streaming",
        value=bool(st.session_state["model_streaming"]),
    )
with cp4:
    st.session_state["model_max_tokens"] = st.number_input(
        "Max Tokens",
        min_value=128,
        max_value=8192,
        value=int(st.session_state["model_max_tokens"]),
        step=64,
    )
with cp5:
    st.metric("Token Usage (session)", st.session_state["token_monitor"].get("local-user"))
st.session_state["system_prompt"] = st.text_area(
    "System Prompt",
    value=str(st.session_state["system_prompt"]),
    height=72,
)
st.caption(
    f"Role: `{config.user_role}` | Model Selection: "
    f"{'enabled' if policy.allow_model_selection else 'restricted'} | "
    f"High-Cost Models: {'allowed' if policy.allow_high_cost_models else 'blocked'}"
)


if selected_page == "Home / Intelligence Hub":
    st.markdown("## SOC Intelligence Hub")
    st.caption("Dark-first, AI-driven threat intelligence and threat hunting operations workspace.")

    c1, c2, c3, c4 = st.columns(4)
    with c1:
        st.metric("Platform Mode", "Production-Ready", "Modular")
    with c2:
        st.metric("Theme", st.session_state["theme"].title(), "WCAG AA")
    with c3:
        intel_count = 1 if st.session_state.get("intel_package") else 0
        st.metric("Intel Packages", intel_count)
    with c4:
        st.metric("Detection Versions", len(st.session_state["detection_versions"]))

    st.markdown("### Capability Tiles")
    cols = st.columns(3)
    with cols[0]:
        section_card(
            "Threat Intelligence Engine",
            "Ingest indicators and narrative intel, extract IOCs/TTPs, map ATT&CK, and operationalize detections.",
        )
    with cols[1]:
        section_card(
            "Project SPECTRA",
            "Framework-driven hunt lifecycle: Prepare -> Execute -> Act -> Knowledge with weighted severity scoring.",
        )
    with cols[2]:
        section_card(
            "Coverage & Playbooks",
            "Validate MITRE detection coverage and generate structured SOC playbooks with SOAR exports.",
        )

    st.markdown("### Quick Actions")
    q1, q2, q3 = st.columns(3)
    with q1:
        if st.button("Go to Threat Intelligence", use_container_width=True):
            st.session_state["active_page"] = PAGES[1]
            st.rerun()
    with q2:
        if st.button("Go to SPECTRA Hunt", use_container_width=True):
            st.session_state["active_page"] = PAGES[2]
            st.rerun()
    with q3:
        if st.button("Go to MITRE Coverage", use_container_width=True):
            st.session_state["active_page"] = PAGES[3]
            st.rerun()


if selected_page == "Threat Intelligence Engine":
    st.markdown("## Threat Intelligence Engine")
    st.caption("AI-assisted enrichment, IOC extraction, ATT&CK mapping, and detection operationalization.")

    left, right = st.columns([2.2, 1.2])
    with left:
        input_kind = st.selectbox("Input Type", INTEL_INPUT_TYPES)
        intel_input = st.text_area(
            "Intelligence Input",
            height=220,
            placeholder=(
                "Paste URL/domain/IP/hash/campaign text or incident narrative.\n"
                "Example: actor=UNC1234 campaign=NightGlass T1071 C2 via hxxps://bad.example[.]com"
            ),
        )
    with right:
        st.markdown("<div class='rf-card'>", unsafe_allow_html=True)
        st.markdown("#### Intake Guidance")
        st.write("- Include observed indicators, timelines, and affected assets.")
        st.write("- Add ATT&CK IDs when known for stronger scoring.")
        st.write("- Add telemetry context for better query tuning.")
        st.markdown("</div>", unsafe_allow_html=True)

    run = st.button("Run Intelligence Enrichment", type="primary")

    if run and intel_input.strip():
        ai_result, ai_error = _run_ai_action("generate_intelligence", intel_input.strip())
        if ai_error:
            st.warning(ai_error)
        package = build_intelligence_package(intel_input.strip(), input_kind)
        if ai_result:
            package.campaign_context.insert(
                0, f"AI enrichment ({ai_result.provider}/{ai_result.model}): {ai_result.content[:220]}"
            )
        st.session_state["intel_package"] = package
        st.session_state["detection_versions"].append(
            {
                "version": f"v{len(st.session_state['detection_versions']) + 1}",
                "risk_score": package.risk_score,
                "confidence": package.summary.confidence,
                "mitre_count": len(package.summary.mitre_techniques),
                "model": st.session_state["model_choice"],
            }
        )

    package = st.session_state.get("intel_package")
    if package:
        st.divider()
        st.markdown("### Threat Summary Dashboard")
        k1, k2, k3, k4, k5 = st.columns(5)
        with k1:
            st.metric("Risk Severity", f"{package.summary.severity}/10")
        with k2:
            st.metric("Confidence", f"{int(package.summary.confidence * 100)}%")
        with k3:
            st.metric("MITRE Techniques", len(package.summary.mitre_techniques))
        with k4:
            st.metric("Indicators", len(package.iocs.ips) + len(package.iocs.domains) + len(package.iocs.hashes))
        with k5:
            st.metric("Actor", package.summary.actor)

        ioc_tab, behavior_tab, detection_tab, export_tab = st.tabs(
            ["IOC Breakdown", "Behavior & Attack Graph", "Detection Operationalization", "Export & Reporting"]
        )

        with ioc_tab:
            st.markdown("#### Expandable IOC Pivots")
            iocs_dict = asdict(package.iocs)
            for category, values in iocs_dict.items():
                with st.expander(f"{category.replace('_', ' ').title()} ({len(values)})", expanded=False):
                    if values:
                        for v in values:
                            st.code(v)
                    else:
                        st.caption("No artifacts extracted.")

        with behavior_tab:
            st.markdown("#### Behavioral Pattern Visualization")
            st.write("- " + "\n- ".join(package.behavior_patterns))

            st.markdown("#### Attack Path Flow Diagram")
            st.code("\n".join(package.attack_path), language="text")

            st.markdown("#### Infrastructure Relationship Graph")
            graph_edges = []
            for domain in package.iocs.domains[:6]:
                for ip in package.iocs.ips[:6]:
                    graph_edges.append({"source": domain, "target": ip})
            st.dataframe(graph_edges, use_container_width=True)

            st.markdown("#### MITRE Heatmap (Condensed)")
            heat_rows = build_coverage(package.summary.mitre_techniques)
            st.dataframe(heat_rows, use_container_width=True)
            st.metric("Detection Coverage Scoring", f"{weighted_coverage_score(heat_rows)}%")

        with detection_tab:
            st.markdown("#### Detection Engineering Output")
            for query in package.detection_queries:
                with st.expander(query.platform, expanded=False):
                    st.caption(
                        f"MITRE: {', '.join(query.mitre)} | Confidence: {int(query.confidence * 100)}%"
                    )
                    st.code(query.query, language="sql")
                    st.write(f"Tuning Guidance: {query.tuning_guidance}")
                    st.write(f"False-Positive Considerations: {query.false_positive_notes}")

            st.markdown("#### Threat Hunting Playbook")
            st.json(asdict(package.hunting_playbook), expanded=False)

            st.markdown("#### Behavior-Based Detection Generation")
            behavior_input = st.text_area(
                "Knowledge Base / Internal Docs Input",
                height=140,
                key="behavior_detection_input",
                placeholder="Paste internal behavior notes for detection-as-code conversion.",
            )
            if st.button("Generate Detection-as-Code Rules"):
                det_result, det_error = _run_ai_action("generate_detections", behavior_input)
                if det_error:
                    st.warning(det_error)
                techniques = extract_techniques(behavior_input) or package.summary.mitre_techniques
                rules = [
                    {
                        "rule_id": f"RF-SOC-{i+1:03d}",
                        "logic": f"behavior_contains('{line[:70]}')",
                        "mitre": techniques,
                    }
                    for i, line in enumerate([ln for ln in behavior_input.splitlines() if ln.strip()][:5])
                ]
                if det_result:
                    rules.append(
                        {
                            "rule_id": f"RF-SOC-AI-{len(rules) + 1:03d}",
                            "logic": det_result.content[:180],
                            "mitre": techniques,
                        }
                    )
                coverage = build_coverage(techniques)
                st.write("Generated Rules")
                st.json(rules, expanded=False)
                st.write("MITRE Technique Coverage")
                st.dataframe(coverage, use_container_width=True)
                st.metric("Coverage Score", f"{weighted_coverage_score(coverage)}%")

            st.markdown("#### Operational Actions")
            oa1, oa2, oa3 = st.columns(3)
            with oa1:
                soar_payload = {
                    "summary": asdict(package.summary),
                    "iocs": asdict(package.iocs),
                    "queries": [asdict(q) for q in package.detection_queries],
                }
                st.download_button(
                    "One-Click SOAR Export",
                    data=json.dumps(soar_payload, indent=2),
                    file_name="soar_export.json",
                    mime="application/json",
                    use_container_width=True,
                )
            with oa2:
                if st.button("Rule Deployment Button", use_container_width=True):
                    if policy.allow_deploy_generated_rules:
                        st.success("Queued deployment request to detection-as-code pipeline.")
                    else:
                        st.error("Your role is not permitted to deploy generated detections.")
            with oa3:
                if st.button("Back to Home", use_container_width=True):
                    st.session_state["active_page"] = PAGES[0]
                    st.rerun()

            st.markdown("#### Analyst Notes")
            st.session_state["analyst_notes"] = st.text_area(
                "Notes",
                value=st.session_state["analyst_notes"],
                height=120,
                key="analyst_notes_area",
            )

            st.markdown("#### Version-Controlled Detection Tracking")
            st.dataframe(st.session_state["detection_versions"], use_container_width=True)

        with export_tab:
            if st.button("Generate AI Report Narrative"):
                report_ai, report_ai_error = _run_ai_action(
                    "generate_report",
                    json.dumps(
                        {
                            "summary": asdict(package.summary),
                            "iocs": asdict(package.iocs),
                            "mitre": package.summary.mitre_techniques,
                        }
                    ),
                )
                if report_ai_error:
                    st.warning(report_ai_error)
                elif report_ai:
                    st.session_state["last_report_ai"] = report_ai.content
            payload = {
                "executive_summary": asdict(package.summary),
                "technical_analysis": {
                    "behavior_patterns": package.behavior_patterns,
                    "attack_path": package.attack_path,
                    "campaign_context": package.campaign_context,
                    "ai_report": st.session_state["last_report_ai"],
                },
                "ioc_tables": asdict(package.iocs),
                "detection_queries": [asdict(q) for q in package.detection_queries],
                "hunt_workflow": asdict(package.hunting_playbook),
                "risk_and_recommendations": {
                    "risk_score": package.risk_score,
                    "confidence": package.summary.confidence,
                    "recommendations": package.hunting_playbook.containment,
                },
                "mitre_coverage_matrix": build_coverage(package.summary.mitre_techniques),
            }
            html_report = build_professional_html_report(payload, "RuleForge SOC Intelligence Report")
            st.download_button(
                "Professional PDF Report (Print-Ready HTML)",
                data=html_report,
                file_name="soc_professional_report.html",
                mime="text/html",
            )
            st.download_button(
                "Executive Summary",
                data=build_executive_summary(payload),
                file_name="executive_summary.txt",
                mime="text/plain",
            )
            st.download_button(
                "Word Technical Guide",
                data=build_word_technical_guide(payload),
                file_name="technical_guide.doc",
                mime="application/msword",
            )
            st.download_button(
                "Detection Engineering Report",
                data=build_detection_engineering_report(payload),
                file_name="detection_engineering_report.json",
                mime="application/json",
            )
            st.download_button(
                "MITRE Coverage Matrix",
                data=json.dumps(payload["mitre_coverage_matrix"], indent=2),
                file_name="mitre_coverage_matrix.json",
                mime="application/json",
            )
            st.download_button(
                "JSON",
                data=build_json(payload),
                file_name="intel_package.json",
                mime="application/json",
            )
            st.download_button(
                "STIX Format",
                data=json.dumps(package_to_stix_like(package), indent=2),
                file_name="intel_stix_bundle.json",
                mime="application/json",
            )
            st.markdown("#### AI Audit Trail")
            st.dataframe(st.session_state["ai_audit_trail"], use_container_width=True)


if selected_page == "Threat Hunting Engine v2.0 (SPECTRA)":
    st.markdown("## Threat Hunting Engine v2.0 - Project SPECTRA")
    st.caption("Lifecycle workflow: Prepare -> Execute -> Act -> Knowledge")

    package = st.session_state.get("intel_package")
    if not package:
        st.warning("No intelligence package found. Generate one in Threat Intelligence Engine first.")
    else:
        report = build_spectra_report(package)
        if st.button("Run AI Behavioral Analysis"):
            behavior_result, behavior_error = _run_ai_action("analyze_behavior", package.input_text)
            if behavior_error:
                st.warning(behavior_error)
            elif behavior_result:
                st.info(f"AI Behavioral Analysis ({behavior_result.provider}/{behavior_result.model})")
                st.code(behavior_result.content, language="text")

        p, e, a, k = st.tabs(["Prepare", "Execute", "Act", "Knowledge"])
        with p:
            st.write("### Installation Instructions")
            st.code("\n".join(report["installation"]), language="bash")
            st.write("### Workflow Documentation")
            st.json(report["lifecycle"]["Prepare"], expanded=False)
        with e:
            st.write("### Multi-Tool Query Generation")
            st.dataframe(report["multi_tool_queries"], use_container_width=True)
            st.write("### IOC Extraction Engine")
            st.json(asdict(package.iocs), expanded=False)
        with a:
            st.write("### Severity Scoring (0-10 Weighted Model)")
            st.json(report["severity"], expanded=False)
            st.write("### Severity Response Matrix")
            matrix = [
                {"range": "0-3.9", "response": "Monitor and enrich"},
                {"range": "4.0-5.9", "response": "Full hunt workflow"},
                {"range": "6.0-7.9", "response": "Accelerated investigation"},
                {"range": "8.0-10", "response": "Immediate containment"},
            ]
            st.dataframe(matrix, use_container_width=True)
            st.write("### Operational Procedures")
            st.write("- " + "\n- ".join(report["operational_procedures"]))
        with k:
            st.write("### Structured Report Output")
            st.json(report, expanded=False)
            st.download_button(
                "Export JSON",
                data=export_spectra_json(report),
                file_name="spectra_report.json",
                mime="application/json",
            )
            st.download_button(
                "Export TXT",
                data=export_spectra_txt(report),
                file_name="spectra_report.txt",
                mime="text/plain",
            )
            st.caption("CLI + script mode compatible: exported JSON/TXT can be consumed by automation pipelines.")


if selected_page == "MITRE ATT&CK Coverage Engine":
    st.markdown("## MITRE ATT&CK Coverage Engine (Draft)")
    st.caption("Placeholder draft with interactive mapping, scoring, filtering, and export.")

    raw_rules = st.text_area(
        "Detection Rule Input",
        height=200,
        placeholder="Paste detection content containing ATT&CK IDs like T1059, T1071, T1105...",
    )
    tactic_filter = st.multiselect(
        "Filter Tactics",
        options=[
            "Execution",
            "Persistence",
            "Defense Evasion",
            "Credential Access",
            "Command and Control",
            "Exfiltration",
            "Initial Access",
        ],
        default=[],
    )

    techniques = extract_techniques(raw_rules)
    coverage = build_coverage(techniques)
    if tactic_filter:
        coverage = [r for r in coverage if r["tactic"] in tactic_filter]

    if st.button("AI-Assisted MITRE Mapping"):
        mitre_ai, mitre_err = _run_ai_action("generate_intelligence", raw_rules or "No rule text provided")
        if mitre_err:
            st.warning(mitre_err)
        elif mitre_ai:
            st.info(f"Mapping generated by {mitre_ai.provider}/{mitre_ai.model}")
            st.code(mitre_ai.content, language="text")

    st.dataframe(coverage, use_container_width=True)
    st.metric("Weighted Coverage Score", f"{weighted_coverage_score(coverage)}%")
    confidence_index = round(
        sum(r["confidence_index"] for r in coverage) / len(coverage), 2
    ) if coverage else 0.0
    st.metric("Detection Confidence Index", f"{int(confidence_index * 100)}%")

    drill = st.selectbox("Drill-down Tactic", [r["tactic"] for r in coverage] or ["None"])
    selected = next((r for r in coverage if r["tactic"] == drill), None)
    if selected:
        st.json(selected, expanded=False)

    st.download_button(
        "Export Coverage Matrix",
        data=json.dumps(coverage, indent=2),
        file_name="mitre_coverage_matrix.json",
        mime="application/json",
    )


if selected_page == "Playbook Builder":
    st.markdown("## Playbook Builder")
    st.caption("Structured detection playbook creation with MITRE mapping, query templates, and SOAR export.")

    scenario = st.text_input("Threat Scenario")
    mitre_input = st.text_input("MITRE Techniques (comma-separated)", value="T1059,T1071")
    query_templates_raw = st.text_area(
        "Query Templates (one per line)",
        height=120,
        placeholder="index=* process_name=rundll32.exe\nDeviceNetworkEvents | where RemoteIP == ...",
    )
    automation_logic = st.text_area(
        "Automation Logic",
        height=100,
        placeholder="If risk_score >= 8 then isolate endpoint and create P1 incident.",
    )

    if st.button("Generate Playbook", type="primary"):
        playbook_ai, playbook_error = _run_ai_action(
            "generate_playbook",
            f"scenario={scenario}\nmitre={mitre_input}\nqueries={query_templates_raw}\nautomation={automation_logic}",
        )
        if playbook_error:
            st.warning(playbook_error)
        techniques = [t.strip() for t in mitre_input.split(",") if re.match(r"^T\d{4}(?:\.\d{3})?$", t.strip())]
        query_templates = [q.strip() for q in query_templates_raw.splitlines() if q.strip()]
        playbook = build_detection_playbook(scenario, techniques, query_templates, automation_logic)
        if playbook_ai:
            playbook["ai_summary"] = playbook_ai.content
            playbook["ai_model"] = f"{playbook_ai.provider}:{playbook_ai.model}"
        st.session_state["current_playbook"] = playbook

    playbook = st.session_state.get("current_playbook")
    if playbook:
        st.json(playbook, expanded=False)

        c1, c2, c3 = st.columns(3)
        with c1:
            st.download_button(
                "SOAR Export",
                data=to_json(playbook),
                file_name="playbook_soar.json",
                mime="application/json",
                use_container_width=True,
            )
        with c2:
            st.download_button(
                "Documentation Generator",
                data=to_markdown(playbook),
                file_name="playbook_documentation.md",
                mime="text/markdown",
                use_container_width=True,
            )
        with c3:
            if st.button("Back to Home", use_container_width=True):
                st.session_state["active_page"] = PAGES[0]
                st.rerun()
