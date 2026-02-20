#!/usr/bin/env python3
"""
kb_split.py — Splits vendor_kb_combined.json into individual platform KB files.

Usage:
    python scripts/kb_split.py
    python scripts/kb_split.py --source /path/to/vendor_kb_combined.json
    python scripts/kb_split.py --dry-run
"""
import argparse
import json
import re
import sys
from datetime import date
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent
DEFAULT_SOURCE = PROJECT_ROOT / "vendor_kb_combined.json"
OUTPUT_DIR = PROJECT_ROOT / "knowledge_bases"

PLATFORM_MAP = {
    "armis":      "armis_centrix_knowledge_base.json",
    "cribl":      "cribl_datalake_detection_knowledge_base.json",
    "obsidian":   "obsidian_security_detection_knowledge_base.json",
    "okta":       "okta_detection_engineering_knowledge_base.json",
    "palo_alto":  "palo_alto_firewall_knowledge_base.json",
    "proofpoint": "proofpoint_email_security_knowledge_base.json",
    "sentinelone":"sentinelone_knowledge_base.json",
}

PLATFORM_NAMES = {
    "armis": "Armis Centrix", "cribl": "Cribl Data Lake",
    "obsidian": "Obsidian Security", "okta": "Okta",
    "palo_alto": "Palo Alto Firewall", "proofpoint": "Proofpoint Email Security",
    "sentinelone": "SentinelOne",
}

def fix_json(raw: str) -> str:
    raw = raw.replace('\u201c', '"').replace('\u201d', '"')
    raw = raw.replace('\u2018', "'").replace('\u2019', "'")
    raw = re.sub(r'"field":\s*""([^"]+)"', r'"field": "\1"', raw)
    return raw

def load_combined(path: Path) -> dict:
    print(f"Loading: {path}")
    with open(path, "rb") as f:
        raw = f.read().decode("utf-8", errors="replace")
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        print("  Applying JSON repairs...")
        return json.loads(fix_json(raw))

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--source", type=Path, default=DEFAULT_SOURCE)
    ap.add_argument("--output-dir", type=Path, default=OUTPUT_DIR)
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    if not args.source.exists():
        print(f"ERROR: {args.source} not found"); sys.exit(1)

    combined = load_combined(args.source)
    missing = [k for k in PLATFORM_MAP if k not in combined]
    if missing:
        print(f"ERROR: Missing platform sections: {missing}"); sys.exit(1)

    if not args.dry_run:
        args.output_dir.mkdir(parents=True, exist_ok=True)

    for key, fname in PLATFORM_MAP.items():
        kb = {"metadata": {"platform": PLATFORM_NAMES[key], "schema_version": "1.0",
                           "kb_updated_at": date.today().isoformat()}, **combined[key]}
        out = args.output_dir / fname
        size = len(json.dumps(kb))
        if args.dry_run:
            print(f"  [DRY-RUN] {fname} ({size:,} bytes)")
        else:
            out.write_text(json.dumps(kb, indent=2, ensure_ascii=False))
            print(f"  OK {fname} ({size:,} bytes)")

    print(f"\n{'DRY-RUN: ' if args.dry_run else ''}All 7 KB files {'would be ' if args.dry_run else ''}written.")
    print("Run: pytest tests/test_kb.py -v  to validate")

if __name__ == "__main__":
    main()
