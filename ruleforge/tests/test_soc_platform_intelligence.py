from soc_platform.engines.intelligence import build_intelligence_package, package_to_stix_like


def test_ioc_extraction_accuracy_core_fields():
    text = (
        "actor=APT-TEST campaign=BlueNight T1071 T1059 "
        "https://evil.example/path 8.8.8.8 bad.example "
        "user@test.org d41d8cd98f00b204e9800998ecf8427e "
        "HKLM\\Software\\BadKey mutex:badmutex service:svc-upd"
    )
    package = build_intelligence_package(text, "Arbitrary Intelligence Text")

    assert "8.8.8.8" in package.iocs.ips
    assert "bad.example" in package.iocs.domains
    assert "https://evil.example/path" in package.iocs.urls
    assert "d41d8cd98f00b204e9800998ecf8427e" in package.iocs.hashes
    assert "user@test.org" in package.iocs.emails
    assert any(item.startswith("HKLM") for item in package.iocs.registry_keys)
    assert "badmutex" in package.iocs.mutexes
    assert "svc-upd" in package.iocs.services


def test_mitre_mapping_and_queries_present():
    package = build_intelligence_package("T1071 T1059 T1105", "Raw Threat Description")
    assert set(package.summary.mitre_techniques) >= {"T1071", "T1059", "T1105"}
    assert len(package.detection_queries) >= 8
    platforms = {q.platform for q in package.detection_queries}
    assert "SentinelOne S1QL" in platforms
    assert "Splunk SPL" in platforms
    assert "Microsoft Sentinel KQL" in platforms
    assert "Palo Alto Query" in platforms
    assert "Okta Detection Query" in platforms
    for query in package.detection_queries:
        assert query.platform
        assert query.query
        assert 0 <= query.confidence <= 1


def test_risk_scoring_in_expected_range():
    package = build_intelligence_package("8.8.8.8 1.1.1.1 bad.example T1071 exfil", "Domain")
    assert 0 <= package.risk_score <= 10


def test_stix_export_formatting_contains_bundle_and_indicators():
    package = build_intelligence_package(
        "8.8.8.8 bad.example ffffffffffffffffffffffffffffffff",
        "Raw Threat Description",
    )
    bundle = package_to_stix_like(package)
    assert bundle["type"] == "bundle"
    assert bundle["spec_version"] == "2.1"
    assert isinstance(bundle["objects"], list)
    assert any(obj["type"] == "indicator" for obj in bundle["objects"])
