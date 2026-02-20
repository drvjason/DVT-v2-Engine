from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone


@dataclass
class IOCSet:
    ips: list[str] = field(default_factory=list)
    domains: list[str] = field(default_factory=list)
    urls: list[str] = field(default_factory=list)
    hashes: list[str] = field(default_factory=list)
    emails: list[str] = field(default_factory=list)
    registry_keys: list[str] = field(default_factory=list)
    mutexes: list[str] = field(default_factory=list)
    services: list[str] = field(default_factory=list)
    user_agents: list[str] = field(default_factory=list)
    file_paths: list[str] = field(default_factory=list)
    named_pipes: list[str] = field(default_factory=list)


@dataclass
class ThreatSummary:
    title: str
    severity: float
    confidence: float
    actor: str
    campaign: str
    motivation: str
    target_industries: list[str] = field(default_factory=list)
    geo_focus: list[str] = field(default_factory=list)
    mitre_techniques: list[str] = field(default_factory=list)
    kill_chain_phases: list[str] = field(default_factory=list)


@dataclass
class DetectionQuery:
    platform: str
    query: str
    mitre: list[str]
    confidence: float
    tuning_guidance: str
    false_positive_notes: str


@dataclass
class HuntingPlaybook:
    hypothesis: str
    data_sources: list[str]
    pivots: list[str]
    timeline_steps: list[str]
    behavioral_clustering: list[str]
    containment: list[str]


@dataclass
class IntelligencePackage:
    generated_at: str
    input_text: str
    summary: ThreatSummary
    iocs: IOCSet
    behavior_patterns: list[str]
    attack_path: list[str]
    campaign_context: list[str]
    detection_queries: list[DetectionQuery]
    hunting_playbook: HuntingPlaybook
    risk_score: float

    def to_dict(self) -> dict:
        return asdict(self)

    @staticmethod
    def now_iso() -> str:
        return datetime.now(timezone.utc).isoformat()
