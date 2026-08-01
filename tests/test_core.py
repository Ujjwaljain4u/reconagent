from reconagent.collectors import REGISTRY, collectors_for
from reconagent.correlator import correlate
from reconagent.models import CollectorResult, Confidence, Finding
from reconagent.opsec import build_opsec_findings


def test_registry_has_all_target_types():
    for t in ("domain", "username", "email", "phone", "image", "pdf"):
        assert t in REGISTRY
        assert len(collectors_for(t)) >= 1


def test_correlate_finds_matching_location_signals():
    results = [
        CollectorResult(collector="a", target="x", ok=True, findings=[
            Finding(source="a", category="registrant_country", value="India", confidence=Confidence.HIGH)
        ]),
        CollectorResult(collector="b", target="x", ok=True, findings=[
            Finding(source="b", category="ip_country", value="India", confidence=Confidence.HIGH)
        ]),
    ]
    report = correlate(results)
    assert len(report.edges) == 1
    assert len(report.location_candidates) == 1
    assert report.location_candidates[0]["confidence"] == "medium"


def test_opsec_flags_gps_finding():
    results = [
        CollectorResult(collector="exif_metadata", target="img.jpg", ok=True, findings=[
            Finding(source="exif_metadata", category="gps_coordinate",
                    value={"lat": 1.0, "lon": 2.0}, confidence=Confidence.HIGH)
        ])
    ]
    findings = build_opsec_findings(results)
    assert len(findings) == 1
    assert findings[0].severity.value == "high"


def test_collector_failure_does_not_crash_pipeline():
    results = [CollectorResult(collector="broken", target="x", ok=False, error="boom")]
    report = correlate(results)
    findings = build_opsec_findings(results)
    assert report.edges == []
    assert findings == []
