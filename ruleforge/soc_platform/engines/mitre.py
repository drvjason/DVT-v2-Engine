from __future__ import annotations

import re

TACTIC_ORDER = [
    "Reconnaissance",
    "Resource Development",
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact",
]

TECHNIQUE_TO_TACTIC = {
    "T1071": "Command and Control",
    "T1059": "Execution",
    "T1105": "Command and Control",
    "T1027": "Defense Evasion",
    "T1110": "Credential Access",
    "T1190": "Initial Access",
    "T1041": "Exfiltration",
    "T1053": "Persistence",
    "T1547": "Persistence",
}


MITRE_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")


def extract_techniques(text: str) -> list[str]:
    found = MITRE_RE.findall(text)
    uniq: list[str] = []
    seen: set[str] = set()
    for item in found:
        root = item.split(".")[0]
        if root in seen:
            continue
        seen.add(root)
        uniq.append(root)
    return uniq


def build_coverage(techniques: list[str]) -> list[dict]:
    rows: list[dict] = []
    for tactic in TACTIC_ORDER:
        mapped = [t for t in techniques if TECHNIQUE_TO_TACTIC.get(t) == tactic]
        score = round(min(len(mapped) / 3, 1.0), 2)
        confidence = round(0.45 + (score * 0.5), 2) if mapped else 0.25
        rows.append(
            {
                "tactic": tactic,
                "techniques": mapped,
                "coverage_score": score,
                "confidence_index": confidence,
            }
        )
    return rows


def weighted_coverage_score(rows: list[dict]) -> float:
    if not rows:
        return 0.0
    return round(sum(r["coverage_score"] for r in rows) / len(rows) * 100, 2)
