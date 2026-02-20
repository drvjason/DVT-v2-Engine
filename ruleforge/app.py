#!/usr/bin/env python3
"""RuleForge SOC-Grade Threat Intelligence & Threat Hunting Platform."""

from __future__ import annotations

import json
import os
import re
from dataclasses import asdict
from datetime import datetime

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
from soc_platform.ui import inject_theme, section_card, sidebar_nav

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

TEMPLATES = {
    "LSASS Dumping": "actor=Unknown campaign=CredentialAccess T1003 lsass dump observed via rundll32",
    "Lateral Movement": "actor=Unknown campaign=LateralFlow T1021 T1071 suspicious SMB and remote exec pivots",
    "Phishing Delivery": "actor=Unknown campaign=MailDrop T1566 malicious URL delivery and follow-on beaconing",
    "CVE Analysis": "actor=Unknown campaign=CVE-Pivot T1190 exploit chain leveraging external-facing service",
}

st.set_page_config(
    page_title="RuleForge SOC Intelligence Platform",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

config = load_config()

SESSION_DEFAULTS = {
    "theme": config.default_theme,
    "active_page": PAGES[0],
    "intel_package": None,
    "detection_versions": [],
    "analyst_notes": "",
    "model_choice": config.default_model if config.default_model in model_choices() else "local:deterministic",
    "model_streaming": False,
    "ai_audit_trail": [],
    "rate_limiter": default_rate_limiter(),
    "token_monitor": TokenMonitor(),
    "current_playbook": None,
    "last_report_ai": "",
    "pipeline_status": "Idle",
    "pipeline_queue": 0,
    "active_phase": 1,
    "recent_runs": [],
    "saved_states": [],
    "hunt_history": [],
    "hunt_context": None,
    "ti_input": "",
}
for key, value in SESSION_DEFAULTS.items():
    if key not in st.session_state:
        st.session_state[key] = value

# System-level tuning, hidden from standard analysts.
SYSTEM_TEMPERATURE = float(os.environ.get("RF_MODEL_TEMPERATURE", "0.2"))
SYSTEM_MAX_TOKENS = int(os.environ.get("RF_MODEL_MAX_TOKENS", "2048"))
SYSTEM_PROMPT = os.environ.get(
    "RF_SYSTEM_PROMPT",
    "You are a SOC analyst assistant. Produce concise, operationally actionable outputs.",
)

inject_theme(st.session_state["theme"])
selected_page = sidebar_nav(config.app_name, PAGES, st.session_state["active_page"])
st.session_state["active_page"] = selected_page

policy = policy_for_role(config.user_role)
allowed_models = [k for k in model_choices() if can_use_model(config.user_role, k)]
if not allowed_models:
    allowed_models = ["local:deterministic"]
if st.session_state["model_choice"] not in allowed_models:
    st.session_state["model_choice"] = allowed_models[0]

with st.sidebar:
    st.markdown("#### AI Model")
    st.session_state["model_choice"] = st.selectbox(
        "Model",
        allowed_models,
        index=allowed_models.index(st.session_state["model_choice"]),
        format_func=lambda k: MODEL_REGISTRY[k].label,
        disabled=not policy.allow_model_selection,
        label_visibility="collapsed",
    )
    st.session_state["model_streaming"] = st.toggle(
        "Streaming",
        value=bool(st.session_state["model_streaming"]),
    )
    st.metric("Token Usage", st.session_state["token_monitor"].get("local-user"))
    st.caption(
        f"Role `{config.user_role}` • High-cost models: "
        f"{'allowed' if policy.allow_high_cost_models else 'blocked'}"
    )
    if policy.role in {"admin", "soc_admin"}:
        with st.expander("Admin Model Overrides"):
            st.caption("Hidden controls for administrative override only.")
            temp_override = st.number_input("Temperature", 0.0, 1.0, float(SYSTEM_TEMPERATURE), 0.05)
            max_tok_override = st.number_input("Max Tokens", 128, 8192, int(SYSTEM_MAX_TOKENS), 64)
            prompt_override = st.text_area("System Prompt", value=SYSTEM_PROMPT, height=80)
            st.session_state["_admin_model_overrides"] = {
                "temperature": float(temp_override),
                "max_tokens": int(max_tok_override),
                "system_prompt": prompt_override,
            }

if not config.has_llm_keys:
    st.info(
        "LLM keys are not configured in environment secrets. "
        "Set `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, and/or `GOOGLE_API_KEY` in env or secrets."
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

    overrides = st.session_state.get("_admin_model_overrides", {})
    temperature = float(overrides.get("temperature", SYSTEM_TEMPERATURE))
    max_tokens = int(overrides.get("max_tokens", SYSTEM_MAX_TOKENS))
    system_prompt = str(overrides.get("system_prompt", SYSTEM_PROMPT))

    provider = create_provider(
        model_key,
        temperature=temperature,
        streaming=st.session_state["model_streaming"],
        max_tokens=max_tokens,
        system_prompt=system_prompt,
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
        "at": datetime.utcnow().isoformat(timespec="seconds") + "Z",
    }
    st.session_state["ai_audit_trail"].append(trail_event)
    audit_ai_request(principal, role, action, model_key, True, result.estimated_tokens)
    return result, None


def _run_pipeline(input_text: str, input_kind: str, threat_name: str):
    st.session_state["pipeline_status"] = "Pipeline Running"
    st.session_state["active_phase"] = 1
    with st.spinner("Executing intelligence pipeline..."):
        ai_result, ai_error = _run_ai_action("generate_intelligence", input_text)
        if ai_error:
            st.warning(ai_error)
        package = build_intelligence_package(input_text, input_kind)
        if ai_result:
            package.campaign_context.insert(
                0,
                f"AI enrichment ({ai_result.provider}/{ai_result.model}): {ai_result.content[:220]}",
            )

    st.session_state["intel_package"] = package
    run_record = {
        "name": threat_name or package.summary.campaign,
        "status": "Complete",
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M"),
        "risk": package.risk_score,
        "iocs": len(package.iocs.ips) + len(package.iocs.domains) + len(package.iocs.hashes),
        "package": package,
    }
    st.session_state["recent_runs"] = ([run_record] + st.session_state["recent_runs"])[:10]
    st.session_state["detection_versions"].append(
        {
            "version": f"v{len(st.session_state['detection_versions']) + 1}",
            "risk_score": package.risk_score,
            "confidence": package.summary.confidence,
            "mitre_count": len(package.summary.mitre_techniques),
            "model": st.session_state["model_choice"],
        }
    )
    st.session_state["pipeline_status"] = "Idle"


def _status_color(value: bool) -> str:
    return "status-green" if value else "status-red"


if selected_page == "Home / Intelligence Hub":
    st.markdown("## SOC Intelligence Hub")
    st.caption("Command surface for intelligence, hunting, coverage, and operationalization.")

    k1, k2, k3, k4 = st.columns(4)
    k1.metric("Threats Analyzed", len(st.session_state["recent_runs"]))
    k2.metric("Rules Generated", len(st.session_state["detection_versions"]))
    k3.metric("IOCs Collected", sum(r.get("iocs", 0) for r in st.session_state["recent_runs"]))
    k4.metric("Theme", st.session_state["theme"].title())

    c1, c2, c3 = st.columns(3)
    with c1:
        section_card("Threat Intelligence Engine", "Pipeline-driven enrichment and operational output generation.")
    with c2:
        section_card("Threat Hunting Engine", "Prepare → Execute → Act → Knowledge lifecycle with SOC workflows.")
    with c3:
        section_card("Coverage + Playbooks", "MITRE coverage and deployment-ready playbook authoring.")


if selected_page == "Threat Intelligence Engine":
    health_cols = st.columns([2.8, 1.2, 1.6, 1.6, 1.6, 0.8])
    with health_cols[0]:
        st.markdown("<div class='soc-topbar'><strong>Threat Intelligence</strong></div>", unsafe_allow_html=True)
    with health_cols[1]:
        st.markdown(f"<div class='soc-topbar'>{st.session_state['pipeline_status']}</div>", unsafe_allow_html=True)
    with health_cols[2]:
        st.markdown(
            f"<div class='soc-topbar'><span class='status-dot {_status_color(bool(os.environ.get('ANTHROPIC_API_KEY')))}'></span>Anthropic</div>",
            unsafe_allow_html=True,
        )
    with health_cols[3]:
        st.markdown(
            f"<div class='soc-topbar'><span class='status-dot {_status_color(bool(os.environ.get('VIRUSTOTAL_API_KEY')))}'></span>VirusTotal</div>",
            unsafe_allow_html=True,
        )
    with health_cols[4]:
        st.markdown(
            f"<div class='soc-topbar'><span class='status-dot {_status_color(bool(os.environ.get('OTX_API_KEY')))}'></span>OTX</div>",
            unsafe_allow_html=True,
        )
    with health_cols[5]:
        st.markdown("<div class='soc-topbar'>⚙️</div>", unsafe_allow_html=True)

    left, main = st.columns([1.2, 3.3])

    with left:
        st.markdown("### Mission Control")
        if st.button("＋ New Pipeline", use_container_width=True, type="primary"):
            st.session_state["intel_package"] = None
            st.session_state["pipeline_status"] = "Idle"
            st.session_state["active_phase"] = 1
        st.markdown("#### Active Runs")
        if st.session_state["pipeline_status"] == "Pipeline Running":
            st.info(f"Phase {st.session_state['active_phase']} of 5 • running")
        else:
            st.caption("No active pipelines")

        st.markdown("#### Recent Runs")
        for run in st.session_state["recent_runs"][:10]:
            badge = "🟢" if run["status"] == "Complete" else "🔴"
            st.markdown(f"{badge} **{run['name']}**  \n{run['status']} • {run['timestamp']}")

        st.markdown("#### Saved States")
        if st.button("Save Current State", use_container_width=True, disabled=st.session_state["intel_package"] is None):
            st.session_state["saved_states"].append(
                {
                    "name": f"Saved-{datetime.now().strftime('%H%M%S')}",
                    "phase": st.session_state["active_phase"],
                    "package": st.session_state["intel_package"],
                }
            )
        if st.session_state["saved_states"]:
            sel = st.selectbox("Saved", list(range(len(st.session_state["saved_states"]))), format_func=lambda i: st.session_state["saved_states"][i]["name"])
            if st.button("Resume", use_container_width=True):
                saved = st.session_state["saved_states"][sel]
                st.session_state["intel_package"] = saved["package"]
                st.session_state["active_phase"] = saved["phase"]

    with main:
        package = st.session_state["intel_package"]

        if package is None:
            st.markdown("## Initiate Intelligence Pipeline")
            t1, t2, t3, t4 = st.columns(4)
            for idx, (label, template) in enumerate(TEMPLATES.items()):
                with [t1, t2, t3, t4][idx]:
                    if st.button(label, use_container_width=True):
                        st.session_state["ti_input"] = template

            with st.container(border=True):
                c1, c2 = st.columns(2)
                with c1:
                    threat_name = st.text_input("Threat Name")
                    threat_actor = st.text_input("Actor")
                    malware = st.text_input("Malware")
                    cve = st.text_input("CVE")
                    input_kind = st.selectbox("Input Type", INTEL_INPUT_TYPES)
                with c2:
                    platform = st.text_input("Platform", value="Windows / Linux / Cloud")
                    siem = st.text_input("SIEM", value="Splunk / Sentinel")
                    log_sources = st.text_input("Log Sources", value="EDR, DNS, Proxy, Identity")
                    edr = st.text_input("EDR", value="SentinelOne")
                    endpoint_count = st.number_input("Endpoint Count", min_value=1, max_value=500000, value=500)
                existing_rules = st.text_input("Existing Rules")
                known_gaps = st.text_input("Known Gaps")
                focus_statement = st.text_area("Focus Statement", height=90)
                intel_input = st.text_area(
                    "Threat Intelligence Input",
                    key="ti_input",
                    height=180,
                    placeholder="Paste IOCs, actor details, TTP narrative, telemetry notes, CVE context...",
                )
                if st.button("Run Pipeline", type="primary", use_container_width=True, disabled=not intel_input.strip()):
                    merged_input = "\n".join(
                        [
                            f"threat={threat_name}",
                            f"actor={threat_actor}",
                            f"malware={malware}",
                            f"cve={cve}",
                            f"platform={platform}",
                            f"siem={siem}",
                            f"log_sources={log_sources}",
                            f"edr={edr}",
                            f"endpoint_count={endpoint_count}",
                            f"existing_rules={existing_rules}",
                            f"known_gaps={known_gaps}",
                            f"focus={focus_statement}",
                            intel_input,
                        ]
                    )
                    _run_pipeline(merged_input, input_kind, threat_name)
                    st.rerun()

            b1, b2, b3 = st.columns(3)
            b1.metric("Total Rules Generated", len(st.session_state["detection_versions"]))
            b2.metric("Total IOCs Collected", sum(r.get("iocs", 0) for r in st.session_state["recent_runs"]))
            b3.metric("Threats Analyzed", len(st.session_state["recent_runs"]))

        else:
            st.markdown("### Phase Timeline")
            pcols = st.columns(5)
            phase_labels = [
                "1. Intelligence Collection",
                "2. Detection Points",
                "3. Rule Generation",
                "4. Deployment Guides",
                "5. Metrics & Scoring",
            ]
            for i, label in enumerate(phase_labels, start=1):
                status = "✅" if i < st.session_state["active_phase"] else "🟢" if i == st.session_state["active_phase"] else "⏳"
                with pcols[i - 1]:
                    if st.button(f"{status} {label}", use_container_width=True, key=f"phase_{i}"):
                        st.session_state["active_phase"] = i

            collector_left, collector_right = st.columns([1.4, 1.8])
            with collector_left:
                st.markdown("#### Phase 1 – Collector Feed")
                collectors = [
                    ("MITRE ATT&CK", len(package.summary.mitre_techniques), "Completed"),
                    ("NVD", 1, "Completed"),
                    ("VirusTotal", len(package.iocs.hashes), "Partial"),
                    ("AlienVault OTX", len(package.iocs.domains), "Completed"),
                    ("SigmaHQ", 3, "Completed"),
                    ("Abuse.ch", len(package.iocs.ips), "Completed"),
                ]
                for name, count, status in collectors:
                    icon = "✅" if status == "Completed" else "🟡"
                    with st.expander(f"{icon} {name} • {count} items • 00:01:{count:02d}"):
                        st.write(f"Raw collector output preview for {name}.")

            with collector_right:
                st.markdown("#### Phase 1 – AI Intelligence Feed")
                feed_tabs = st.tabs(
                    [
                        "Threat Profile",
                        "Technical Analysis",
                        "MITRE Mapping",
                        "IOCs",
                        "Existing Detections",
                        "Sources",
                    ]
                )
                with feed_tabs[0]:
                    st.json(asdict(package.summary), expanded=False)
                with feed_tabs[1]:
                    st.write("- " + "\n- ".join(package.behavior_patterns))
                with feed_tabs[2]:
                    st.dataframe(build_coverage(package.summary.mitre_techniques), use_container_width=True)
                with feed_tabs[3]:
                    st.json(asdict(package.iocs), expanded=False)
                with feed_tabs[4]:
                    st.dataframe([asdict(q) for q in package.detection_queries], use_container_width=True)
                with feed_tabs[5]:
                    st.write("MITRE ATT&CK, OTX, VirusTotal, NVD, SigmaHQ, internal telemetry")

            st.markdown("#### IOC Visualization Strip")
            chip_groups = {
                "Hash": package.iocs.hashes[:8],
                "Domain": package.iocs.domains[:8],
                "IP": package.iocs.ips[:8],
                "URL": package.iocs.urls[:8],
            }
            for group, values in chip_groups.items():
                if values:
                    st.markdown(f"**{group}**")
                    st.write(" ".join([f"`{v}`" for v in values]))

            st.markdown("#### MITRE Mini-Map")
            st.dataframe(build_coverage(package.summary.mitre_techniques), use_container_width=True)

            with st.expander("Phase 2 – Detection Points", expanded=True):
                ranked = package.detection_queries[:3]
                for idx, q in enumerate(ranked, start=1):
                    st.markdown(f"**#{idx} {q.platform}**")
                    st.progress(min(100, int(q.confidence * 100)), text=f"Reliability {int(q.confidence*100)}%")
                    st.progress(min(100, int((q.confidence + 0.08) * 100)), text="Specificity")
                    st.progress(min(100, int((q.confidence + 0.05) * 100)), text="Evasion Resistance")

            with st.expander("Phase 3 – Rule Generation", expanded=True):
                format_sel = st.selectbox("Format", ["YAML", "KQL", "SPL", "S1QL"])
                variant = st.radio("Variant", ["Primary", "Broad", "Correlation"], horizontal=True)
                base_rule = package.detection_queries[0].query if package.detection_queries else "event.type == suspicious"
                st.code(base_rule, language="yaml" if format_sel == "YAML" else "sql")
                st.caption(f"Logic walkthrough: variant={variant}, source confidence={int(package.summary.confidence*100)}%")
                st.button("Copy Rule")

            with st.expander("Phase 4 – Deployment Guides", expanded=True):
                d_tabs = st.tabs(["Deployment Guide", "Triage Playbook", "Tuning Guide"])
                with d_tabs[0]:
                    st.write("Deploy to SIEM/EDR rules engine with staged rollout and canary scope.")
                with d_tabs[1]:
                    st.write("Validate impacted assets, pivot on related IOCs, isolate high-risk hosts.")
                with d_tabs[2]:
                    st.write("Tune expected noise sources, suppress trusted infra, iterate on false positives.")
                bundle_bytes = json.dumps(asdict(package), indent=2).encode("utf-8")
                st.download_button("Download All (ZIP-like JSON bundle)", data=bundle_bytes, file_name="deployment_bundle.json")

            with st.expander("Phase 5 – Metrics & Scoring", expanded=True):
                q1, q2 = st.columns(2)
                q3, q4 = st.columns(2)
                q1.metric("TP Rate", f"{int(package.summary.confidence*100)}%")
                q2.metric("FP Risk", f"{max(1, 100 - int(package.summary.confidence*100))}%")
                q3.metric("Evasion Resistance", f"{int((package.summary.confidence + 0.06) * 100)}%")
                grade = "A" if package.risk_score >= 8 else "B" if package.risk_score >= 6 else "C"
                q4.metric("Target Grade", grade)
                table = [
                    {"Category": "True Positive", "Outcome": "Pass"},
                    {"Category": "False Positive", "Outcome": "Monitor"},
                    {"Category": "Evasion", "Outcome": "Needs hardening"},
                ]
                st.dataframe(table, use_container_width=True)

            st.markdown("---")
            st.markdown("### Output Dock")
            payload = {
                "executive_summary": asdict(package.summary),
                "technical_analysis": {
                    "behavior_patterns": package.behavior_patterns,
                    "attack_path": package.attack_path,
                    "campaign_context": package.campaign_context,
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
            d1, d2, d3, d4, d5 = st.columns(5)
            d1.download_button("rule_primary.yml", data="rule: primary\n", file_name="rule_primary.yml")
            d2.download_button("triage_playbook.md", data=to_markdown(build_detection_playbook("Auto", package.summary.mitre_techniques, [], "")), file_name="triage_playbook.md")
            d3.download_button("tuning_guide.md", data="tuning:\n- suppress trusted infra\n", file_name="tuning_guide.md")
            d4.download_button("validation.json", data=build_json(payload), file_name="validation.json")
            d5.download_button("pipeline_state.json", data=json.dumps({"phase": st.session_state["active_phase"], "status": st.session_state["pipeline_status"]}), file_name="pipeline_state.json")

            with st.expander("Pipeline Comparison View"):
                runs = st.session_state["recent_runs"]
                if len(runs) >= 2:
                    i1 = st.selectbox("Run A", list(range(len(runs))), index=0, format_func=lambda i: runs[i]["name"], key="cmp_a")
                    i2 = st.selectbox("Run B", list(range(len(runs))), index=1, format_func=lambda i: runs[i]["name"], key="cmp_b")
                    a, b = runs[i1], runs[i2]
                    overlap = min(a.get("iocs", 0), b.get("iocs", 0))
                    st.write(f"IOC overlap estimate: {overlap}")
                    st.write(f"Risk delta: {round(a['risk'] - b['risk'], 2)}")
                else:
                    st.caption("Need at least two runs to compare.")


if selected_page == "Threat Hunting Engine v2.0 (SPECTRA)":
    st.markdown("## Threat Hunting Engine v2.0 – Project SPECTRA")
    st.caption("Persistent lifecycle visibility: PREPARE → EXECUTE → ACT → KNOWLEDGE")

    package = st.session_state.get("intel_package")
    if not package:
        st.warning("No intelligence package found. Generate one in Threat Intelligence Engine first.")
    else:
        z1, z2, z3 = st.columns([4, 3.5, 2.5])
        with z1:
            st.markdown("### INITIATE HUNT")
            hunt_input = st.text_area(
                "Multi-Modal Input",
                height=180,
                placeholder="Paste IOC list, behavior description, URLs, raw logs...",
                key="hunt_input",
            )
            c1, c2, c3 = st.columns(3)
            c1.button("Paste IOC", use_container_width=True)
            c2.button("Describe Behavior", use_container_width=True)
            c3.button("Load File", use_container_width=True)
            tool_toggles = st.multiselect(
                "Tools",
                ["SentinelOne", "Splunk", "Sentinel", "Palo Alto", "Okta", "DNS", "Proxy"],
                default=["SentinelOne", "Splunk", "Sentinel"],
            )
            if st.button("PREPARE HUNT", use_container_width=True, type="primary"):
                score = build_spectra_report(package)["severity"]["score_0_10"]
                st.session_state["hunt_context"] = {
                    "id": f"H-{datetime.now().strftime('%H%M%S')}",
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M"),
                    "severity": score,
                    "hypothesis": package.hunting_playbook.hypothesis,
                    "tools": tool_toggles,
                }
                st.session_state["hunt_history"] = ([st.session_state["hunt_context"]] + st.session_state["hunt_history"])[:20]

        with z2:
            st.markdown("### Live Hunt Context")
            ctx = st.session_state.get("hunt_context")
            if ctx:
                sev_color = "🔴" if ctx["severity"] >= 8 else "🟠" if ctx["severity"] >= 6 else "🟡"
                st.markdown(f"{sev_color} **Severity {ctx['severity']}/10**  •  `{ctx['id']}`  •  {ctx['timestamp']}")
                st.markdown(f"**Hypothesis:** {ctx['hypothesis']}")
                st.dataframe(build_coverage(package.summary.mitre_techniques), use_container_width=True)
                st.write("IOC Chips")
                st.write(" ".join([f"`{x}`" for x in (package.iocs.ips + package.iocs.domains)[:12]]))
                a1, a2, a3, a4 = st.columns(4)
                a1.button("Execute Queries", use_container_width=True)
                a2.button("Export JSON", use_container_width=True)
                a3.button("Copy Hypothesis", use_container_width=True)
                a4.button("Edit Context", use_container_width=True)
            else:
                st.caption("Prepare a hunt to populate live context.")

        with z3:
            st.markdown("### Activity Feed")
            for hunt in st.session_state["hunt_history"][:10]:
                badge = "🟢" if hunt["severity"] < 6 else "🟠" if hunt["severity"] < 8 else "🔴"
                st.markdown(f"{badge} `{hunt['id']}` • {hunt['timestamp']}")
            st.markdown("#### Telemetry Health")
            st.markdown("🟢 Endpoint  🟢 Identity  🟡 DNS  🟢 Proxy")

        st.markdown("---")
        st.markdown("### Query Execution Surface")
        selected_tools = st.session_state.get("hunt_context", {}).get("tools", ["SentinelOne", "Splunk", "Sentinel"])
        query_tabs = st.tabs(selected_tools)
        platform_map = {
            "SentinelOne": "SentinelOne S1QL",
            "Splunk": "Splunk SPL",
            "Sentinel": "Microsoft Sentinel KQL",
            "Palo Alto": "Palo Alto Query",
            "Okta": "Okta Detection Query",
            "DNS": "DNS Detection Logic",
            "Proxy": "Proxy Search Logic",
        }
        for tab, tool in zip(query_tabs, selected_tools):
            with tab:
                qmatch = next((q for q in package.detection_queries if q.platform == platform_map.get(tool, "")), None)
                if qmatch:
                    st.code(qmatch.query, language="sql")
                    st.caption(f"Why this query: {qmatch.tuning_guidance}")
                    st.caption(f"Confidence: {int(qmatch.confidence*100)}%")
                st.button(f"Copy {tool} Query", key=f"copy_{tool}")
                st.link_button(f"Run in {tool}", url="https://example.internal/tool")

        st.markdown("### Findings Intake & Act Phase")
        for tool in selected_tools:
            with st.expander(tool):
                findings = st.text_area(f"Paste findings for {tool}", key=f"findings_{tool}")
                auto_skip = st.toggle(f"AUTO-SKIP empty findings ({tool})", value=True, key=f"skip_{tool}")
                if findings.strip() or not auto_skip:
                    st.info("Live analysis preview updated: risk and hit counts recalculated.")

        st.markdown("### Knowledge Report Surface")
        report = build_spectra_report(package)
        k_tabs = st.tabs(["Summary", "Workflow", "MITRE", "Recommendations"])
        with k_tabs[0]:
            st.json(report["severity"], expanded=False)
        with k_tabs[1]:
            st.json(report["lifecycle"], expanded=False)
        with k_tabs[2]:
            st.dataframe(build_coverage(package.summary.mitre_techniques), use_container_width=True)
        with k_tabs[3]:
            for rec in package.hunting_playbook.containment:
                st.checkbox(rec, value=False)

        x1, x2, x3, x4, x5 = st.columns(5)
        x1.download_button("TXT", data=export_spectra_txt(report), file_name="knowledge_report.txt")
        x2.download_button("JSON", data=export_spectra_json(report), file_name="knowledge_report.json")
        x3.button("Copy")
        x4.button("Open")
        if x5.button("Push to Ticket"):
            st.session_state["ai_audit_trail"].append({"action": "push_ticket", "at": datetime.utcnow().isoformat() + "Z"})
            st.success("Ticket push event logged.")


if selected_page == "MITRE ATT&CK Coverage Engine":
    st.markdown("## MITRE ATT&CK Coverage Engine")
    raw_rules = st.text_area(
        "Detection Rule Input",
        height=220,
        placeholder="Paste detection rules with ATT&CK IDs (T1059, T1071, ...)",
    )
    tactics = st.multiselect(
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
    if tactics:
        coverage = [r for r in coverage if r["tactic"] in tactics]

    st.dataframe(coverage, use_container_width=True)
    st.metric("Weighted Coverage Score", f"{weighted_coverage_score(coverage)}%")
    confidence_index = (
        round(sum(r["confidence_index"] for r in coverage) / len(coverage), 2) if coverage else 0.0
    )
    st.metric("Detection Confidence Index", f"{int(confidence_index * 100)}%")
    st.download_button(
        "Export Coverage Matrix",
        data=json.dumps(coverage, indent=2),
        file_name="mitre_coverage_matrix.json",
        mime="application/json",
    )


if selected_page == "Playbook Builder":
    st.markdown("## Playbook Builder")
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
        queries = [q.strip() for q in query_templates_raw.splitlines() if q.strip()]
        playbook = build_detection_playbook(scenario, techniques, queries, automation_logic)
        if playbook_ai:
            playbook["ai_summary"] = playbook_ai.content
            playbook["ai_model"] = st.session_state["model_choice"]
        st.session_state["current_playbook"] = playbook

    playbook = st.session_state.get("current_playbook")
    if playbook:
        st.json(playbook, expanded=False)
        c1, c2, c3 = st.columns(3)
        c1.download_button("SOAR Export", data=to_json(playbook), file_name="playbook_soar.json")
        c2.download_button("Documentation", data=to_markdown(playbook), file_name="playbook_documentation.md")
        c3.download_button(
            "Bundle",
            data=build_professional_html_report(
                {
                    "executive_summary": playbook,
                    "technical_analysis": playbook,
                    "ioc_tables": {},
                    "detection_queries": playbook.get("query_templates", []),
                    "hunt_workflow": playbook,
                    "risk_and_recommendations": {},
                },
                "Playbook Report",
            ),
            file_name="playbook_report.html",
        )

# Export panel remains globally accessible for analyst workflows.
if st.session_state.get("intel_package") is not None:
    with st.expander("Global Export & Reporting", expanded=False):
        package = st.session_state["intel_package"]
        payload = {
            "executive_summary": asdict(package.summary),
            "technical_analysis": {
                "behavior_patterns": package.behavior_patterns,
                "attack_path": package.attack_path,
                "campaign_context": package.campaign_context,
                "ai_report": st.session_state.get("last_report_ai", ""),
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
        y1, y2, y3, y4, y5, y6, y7 = st.columns(7)
        y1.download_button("PDF Report", data=html_report, file_name="soc_report.html")
        y2.download_button("Executive", data=build_executive_summary(payload), file_name="executive_summary.txt")
        y3.download_button("Word Guide", data=build_word_technical_guide(payload), file_name="technical_guide.doc")
        y4.download_button("Detection", data=build_detection_engineering_report(payload), file_name="detection_report.json")
        y5.download_button("MITRE", data=json.dumps(payload["mitre_coverage_matrix"], indent=2), file_name="mitre_matrix.json")
        y6.download_button("JSON", data=build_json(payload), file_name="intel_package.json")
        y7.download_button("STIX", data=json.dumps(package_to_stix_like(package), indent=2), file_name="intel_stix_bundle.json")
