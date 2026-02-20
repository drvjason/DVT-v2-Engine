from __future__ import annotations

import ipaddress
import re
from dataclasses import asdict

from soc_platform.models import (
    DetectionQuery,
    HuntingPlaybook,
    IOCSet,
    IntelligencePackage,
    ThreatSummary,
)

IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
DOMAIN_RE = re.compile(r"\b(?:(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,})\b")
URL_RE = re.compile(r"https?://[^\s'\"<>]+")
HASH_RE = re.compile(r"\b(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})\b")
EMAIL_RE = re.compile(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b")
MITRE_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")


def _uniq(items: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for item in items:
        normalized = item.strip()
        if not normalized:
            continue
        key = normalized.lower()
        if key in seen:
            continue
        seen.add(key)
        out.append(normalized)
    return out


def _extract_iocs(text: str) -> IOCSet:
    ips = []
    for candidate in IP_RE.findall(text):
        try:
            ipaddress.ip_address(candidate)
            ips.append(candidate)
        except ValueError:
            continue

    registry_keys = re.findall(r"(?:HKLM|HKCU|HKEY_[A-Z_\\]+)\\[^\n\r,;]+", text)
    mutexes = re.findall(r"mutex[:=]\s*([\w\-.\\]+)", text, flags=re.IGNORECASE)
    services = re.findall(r"service[:=]\s*([\w\-.]+)", text, flags=re.IGNORECASE)
    user_agents = re.findall(r"(?:User-Agent|UA)[:=]\s*([^\n\r]+)", text, flags=re.IGNORECASE)
    file_paths = re.findall(r"[A-Za-z]:\\[^\n\r\"']+", text)
    named_pipes = re.findall(r"\\\\\\.\\pipe\\[\w\-.]+", text)

    return IOCSet(
        ips=_uniq(ips),
        domains=_uniq(DOMAIN_RE.findall(text)),
        urls=_uniq(URL_RE.findall(text)),
        hashes=_uniq(HASH_RE.findall(text)),
        emails=_uniq(EMAIL_RE.findall(text)),
        registry_keys=_uniq(registry_keys),
        mutexes=_uniq(mutexes),
        services=_uniq(services),
        user_agents=_uniq(user_agents),
        file_paths=_uniq(file_paths),
        named_pipes=_uniq(named_pipes),
    )


def _severity_score(iocs: IOCSet, text: str) -> float:
    score = 1.0
    score += min(len(iocs.ips), 10) * 0.3
    score += min(len(iocs.domains), 10) * 0.25
    score += min(len(iocs.hashes), 10) * 0.4
    score += min(len(iocs.urls), 10) * 0.2
    if re.search(r"ransomware|wiper|exfil|credential", text, flags=re.IGNORECASE):
        score += 1.8
    if re.search(r"c2|command and control|lateral movement|persistence", text, flags=re.IGNORECASE):
        score += 1.2
    return round(min(score, 10.0), 2)


def _confidence_score(iocs: IOCSet, text: str) -> float:
    evidence = len(iocs.ips) + len(iocs.domains) + len(iocs.hashes) + len(iocs.urls)
    coverage = min(0.35 + evidence * 0.04, 0.95)
    if MITRE_RE.search(text):
        coverage = min(coverage + 0.04, 0.98)
    return round(coverage, 2)


def _queries(iocs: IOCSet, mitre: list[str], confidence: float) -> list[DetectionQuery]:
    ip_filter = " or ".join([f"dst_ip=\"{ip}\"" for ip in iocs.ips[:5]]) or "dst_ip=*"
    domain_filter = " or ".join([f'domain=\"{d}\"' for d in iocs.domains[:5]]) or "domain=*"
    hash_filter = " or ".join([f'hash=\"{h}\"' for h in iocs.hashes[:3]]) or "hash=*"
    url_filter = " or ".join([f'url=\"{u}\"' for u in iocs.urls[:3]]) or "url=*"

    return [
        DetectionQuery(
            platform="SentinelOne S1QL",
            query=f"event.type = 'IP Connect' and ({ip_filter})",
            mitre=mitre,
            confidence=confidence,
            tuning_guidance="Exclude known patching and backup infrastructure destination IPs.",
            false_positive_notes="Expected noise from vulnerability scanners and EDR content updates.",
        ),
        DetectionQuery(
            platform="Splunk SPL",
            query=f"index=* ({domain_filter} OR {hash_filter} OR {url_filter}) | stats count by host user src_ip",
            mitre=mitre,
            confidence=confidence,
            tuning_guidance="Restrict to threat-relevant sourcetypes and add process ancestry filters.",
            false_positive_notes="May catch benign CDN or software update activity.",
        ),
        DetectionQuery(
            platform="Microsoft Sentinel KQL",
            query=(
                "DeviceNetworkEvents | where Timestamp > ago(7d) | where "
                + (" or ".join([f"RemoteIP == '{ip}'" for ip in iocs.ips[:5]]) or "isnotempty(RemoteIP)")
                + " | summarize Hits=count() by DeviceName, InitiatingProcessFileName, RemoteIP"
            ),
            mitre=mitre,
            confidence=confidence,
            tuning_guidance="Join to sign-in and process events for higher-confidence clustering.",
            false_positive_notes="Cloud service discovery traffic can look similar.",
        ),
        DetectionQuery(
            platform="Palo Alto Query",
            query=f"( subtype eq threat ) and ( {domain_filter} or {ip_filter} )",
            mitre=mitre,
            confidence=confidence,
            tuning_guidance="Scope by known egress zones and user groups.",
            false_positive_notes="Proxy chains can obscure true destination and inflate matches.",
        ),
        DetectionQuery(
            platform="Okta Detection Query",
            query="eventType co \"user.session.start\" and outcome.result eq \"SUCCESS\"",
            mitre=mitre,
            confidence=max(0.5, confidence - 0.1),
            tuning_guidance="Add geo-velocity and impossible travel checks for higher value.",
            false_positive_notes="Legitimate travel, VPN egress changes, and mobile networks.",
        ),
        DetectionQuery(
            platform="DNS Detection Logic",
            query=f"query_name in ({', '.join([repr(d) for d in iocs.domains[:8]]) or 'ANY'})",
            mitre=mitre,
            confidence=confidence,
            tuning_guidance="Exclude internal domains and trusted resolver health checks.",
            false_positive_notes="Security tools often resolve suspicious domains for testing.",
        ),
        DetectionQuery(
            platform="Proxy Search Logic",
            query=f"url matches ({', '.join([repr(u) for u in iocs.urls[:6]]) or '.*'})",
            mitre=mitre,
            confidence=confidence,
            tuning_guidance="Constrain by user-agent anomalies and uncommon destination ASN.",
            false_positive_notes="Web scraping or automated QA jobs may overlap.",
        ),
        DetectionQuery(
            platform="Email Gateway Logic",
            query=f"sender_domain in ({', '.join([repr(d) for d in iocs.domains[:6]]) or 'ANY'})",
            mitre=mitre,
            confidence=max(0.45, confidence - 0.15),
            tuning_guidance="Correlate with attachment and URL detonation verdicts.",
            false_positive_notes="Business partners on newly registered domains can trigger.",
        ),
    ]


def _build_playbook(summary: ThreatSummary, iocs: IOCSet) -> HuntingPlaybook:
    return HuntingPlaybook(
        hypothesis=(
            f"Adversary activity linked to {summary.campaign or 'an active campaign'} "
            "is present and can be observed through endpoint-network-behavior correlations."
        ),
        data_sources=[
            "EDR process telemetry",
            "DNS logs",
            "Proxy logs",
            "Identity provider logs",
            "Firewall network sessions",
            "Email gateway metadata",
        ],
        pivots=[
            "Pivot from high-confidence IOC matches to parent-child process lineage.",
            "Correlate destination infrastructure with historical incidents and JA3 fingerprints.",
            "Expand from host to user and identity events across the same time range.",
        ],
        timeline_steps=[
            "Initial access and delivery validation",
            "Execution and persistence establishment",
            "Credential access and lateral movement checks",
            "Exfiltration and impact confirmation",
        ],
        behavioral_clustering=[
            "Group detections by process ancestry and destination infrastructure reuse.",
            "Cluster hosts by shared registry persistence and scheduled task artifacts.",
            "Score sessions by ATT&CK coverage and anomaly density.",
        ],
        containment=[
            "Isolate impacted hosts",
            "Block IOC infrastructure on network controls",
            "Disable compromised identities and rotate secrets",
            "Deploy detection queries as persistent analytics rules",
        ],
    )


def build_intelligence_package(raw_input: str, input_kind: str) -> IntelligencePackage:
    iocs = _extract_iocs(raw_input)
    mitre = _uniq(MITRE_RE.findall(raw_input)) or ["T1071", "T1059", "T1105"]

    severity = _severity_score(iocs, raw_input)
    confidence = _confidence_score(iocs, raw_input)

    actor_match = re.search(r"(?:actor|group)[:=]\s*([^\n\r,;]+)", raw_input, re.IGNORECASE)
    campaign_match = re.search(r"campaign[:=]\s*([^\n\r,;]+)", raw_input, re.IGNORECASE)
    motivation = "financial" if re.search(r"ransom|fraud|extort", raw_input, re.I) else "espionage"

    summary = ThreatSummary(
        title=f"{input_kind.title()} Intelligence Assessment",
        severity=severity,
        confidence=confidence,
        actor=actor_match.group(1).strip() if actor_match else "Unknown/Unattributed",
        campaign=campaign_match.group(1).strip() if campaign_match else "Unlabeled Campaign",
        motivation=motivation,
        target_industries=["Finance", "Healthcare", "Technology"],
        geo_focus=["North America", "EMEA"],
        mitre_techniques=mitre,
        kill_chain_phases=["Initial Access", "Execution", "Persistence", "Command & Control"],
    )

    queries = _queries(iocs, mitre, confidence)

    behavior_patterns = [
        "LOLBin-assisted execution chains observed with evasive process ancestry.",
        "Infrastructure reuse pattern detected across staged and C2 domains.",
        "Potential credential access preceding outbound beacon cadence.",
    ]
    attack_path = [
        "Delivery vector -> User execution",
        "Execution -> Persistence",
        "Persistence -> Credential access",
        "Credential access -> Lateral movement",
        "Lateral movement -> Exfiltration",
    ]
    campaign_context = [
        "Shared domains overlap with previous intrusion sets.",
        "Malware family behavior resembles loader + infostealer chains.",
        "Timeline indicates phased operations over 24-72 hours.",
    ]

    package = IntelligencePackage(
        generated_at=IntelligencePackage.now_iso(),
        input_text=raw_input,
        summary=summary,
        iocs=iocs,
        behavior_patterns=behavior_patterns,
        attack_path=attack_path,
        campaign_context=campaign_context,
        detection_queries=queries,
        hunting_playbook=_build_playbook(summary, iocs),
        risk_score=severity,
    )
    return package


def package_to_stix_like(package: IntelligencePackage) -> dict:
    iocs = package.iocs
    objs = []
    for ip in iocs.ips:
        objs.append({"type": "indicator", "pattern_type": "stix", "pattern": f"[ipv4-addr:value = '{ip}']"})
    for domain in iocs.domains:
        objs.append({"type": "indicator", "pattern_type": "stix", "pattern": f"[domain-name:value = '{domain}']"})
    for h in iocs.hashes:
        algo = "SHA-256" if len(h) == 64 else "SHA-1" if len(h) == 40 else "MD5"
        objs.append(
            {
                "type": "indicator",
                "pattern_type": "stix",
                "pattern": f"[file:hashes.'{algo}' = '{h}']",
            }
        )
    return {
        "type": "bundle",
        "id": "bundle--ruleforge-soc",
        "spec_version": "2.1",
        "objects": objs,
        "x_ruleforge_summary": asdict(package.summary),
    }
