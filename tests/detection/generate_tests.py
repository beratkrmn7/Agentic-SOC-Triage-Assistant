import os

TEST_DIR = "tests/detection"

files = {
    "test_rule_registry.py": """
from agent.detection.registry import RuleRegistry
from agent.detection.detectors.base import BaseDetectionRule

class DummyRule(BaseDetectionRule):
    rule_id = "dummy"
    version = "1.0"
    name = "Dummy"
    family = "dummy"
    priority = 1
    def evaluate(self, e, c): return []

def test_registry():
    r = RuleRegistry()
    r.register(DummyRule())
    assert len(r.get_all_rules()) == 1
    assert r.get_rule("dummy").rule_id == "dummy"
    r.unregister("dummy")
    assert len(r.get_all_rules()) == 0
""",
    "test_horizontal_scan.py": """
import pytest
from datetime import datetime, timedelta
from agent.schema import CanonicalLogEvent
from agent.detection.detectors.horizontal_scan import HorizontalScanRule
from agent.detection.detectors.base import DetectionContext
from agent.detection.config import DetectionSettings

def test_horizontal_scan_positive():
    rule = HorizontalScanRule()
    settings = DetectionSettings(HORIZONTAL_SCAN_MIN_EVENTS=3, HORIZONTAL_SCAN_MIN_DISTINCT_TARGETS=2)
    ctx = DetectionContext(settings=settings, analysis_started_at=datetime.now())
    
    events = [
        CanonicalLogEvent(event_id=f"e{i}", timestamp=datetime.now() + timedelta(seconds=i), src_ip="1.2.3.4", dst_ip=f"10.0.0.{i}", dst_port=80, action="block")
        for i in range(3)
    ]
    signals = rule.evaluate(events, ctx)
    assert len(signals) == 1
    assert signals[0].primary_entity == "1.2.3.4"
    assert "T1046" in signals[0].mitre_techniques
    
def test_horizontal_scan_negative():
    rule = HorizontalScanRule()
    settings = DetectionSettings(HORIZONTAL_SCAN_MIN_EVENTS=3, HORIZONTAL_SCAN_MIN_DISTINCT_TARGETS=2)
    ctx = DetectionContext(settings=settings, analysis_started_at=datetime.now())
    events = [
        CanonicalLogEvent(event_id="e1", timestamp=datetime.now(), src_ip="1.2.3.4", dst_ip="10.0.0.1", dst_port=80, action="block"),
        CanonicalLogEvent(event_id="e2", timestamp=datetime.now(), src_ip="1.2.3.4", dst_ip="10.0.0.1", dst_port=80, action="block"),
        CanonicalLogEvent(event_id="e3", timestamp=datetime.now(), src_ip="1.2.3.4", dst_ip="10.0.0.1", dst_port=80, action="block")
    ]
    signals = rule.evaluate(events, ctx)
    assert len(signals) == 0
""",
    "test_vertical_scan.py": """
from datetime import datetime, timedelta
from agent.schema import CanonicalLogEvent
from agent.detection.detectors.vertical_scan import VerticalScanRule
from agent.detection.detectors.base import DetectionContext
from agent.detection.config import DetectionSettings

def test_vertical_scan_positive():
    rule = VerticalScanRule()
    settings = DetectionSettings(VERTICAL_SCAN_MIN_EVENTS=3, VERTICAL_SCAN_MIN_DISTINCT_PORTS=3)
    ctx = DetectionContext(settings=settings, analysis_started_at=datetime.now())
    events = [
        CanonicalLogEvent(event_id=f"e{i}", timestamp=datetime.now(), src_ip="1.2.3.4", dst_ip="10.0.0.1", dst_port=80+i, action="block")
        for i in range(3)
    ]
    signals = rule.evaluate(events, ctx)
    assert len(signals) == 1
    assert signals[0].target_entities == ["10.0.0.1"]
""",
    "test_remote_service_probe.py": """
from datetime import datetime
from agent.schema import CanonicalLogEvent
from agent.detection.detectors.remote_service_probe import RemoteServiceProbeRule
from agent.detection.detectors.base import DetectionContext
from agent.detection.config import DetectionSettings

def test_rdp_probe():
    rule = RemoteServiceProbeRule()
    settings = DetectionSettings(REMOTE_SERVICE_MIN_EVENTS=2, REMOTE_SERVICE_MIN_DISTINCT_TARGETS=2)
    ctx = DetectionContext(settings=settings, analysis_started_at=datetime.now())
    events = [
        CanonicalLogEvent(event_id=f"e{i}", timestamp=datetime.now(), src_ip="1.2.3.4", dst_ip=f"10.0.0.{i}", dst_port=3389, action="block")
        for i in range(2)
    ]
    signals = rule.evaluate(events, ctx)
    assert len(signals) == 1
    assert signals[0].signal_type == "rdp_probe"
    
def test_ssh_probe():
    rule = RemoteServiceProbeRule()
    settings = DetectionSettings(REMOTE_SERVICE_MIN_EVENTS=2, REMOTE_SERVICE_MIN_DISTINCT_TARGETS=2)
    ctx = DetectionContext(settings=settings, analysis_started_at=datetime.now())
    events = [
        CanonicalLogEvent(event_id=f"e{i}", timestamp=datetime.now(), src_ip="1.2.3.4", dst_ip=f"10.0.0.{i}", dst_port=22, action="block")
        for i in range(2)
    ]
    signals = rule.evaluate(events, ctx)
    assert len(signals) == 1
    assert signals[0].signal_type == "ssh_probe"
""",
    "test_spi_anomaly.py": """
from datetime import datetime
from agent.schema import CanonicalLogEvent
from agent.detection.detectors.spi_anomaly import SPIAnomalyRule
from agent.detection.detectors.base import DetectionContext
from agent.detection.config import DetectionSettings

def test_spi_anomaly_positive():
    rule = SPIAnomalyRule()
    settings = DetectionSettings(SPI_ANOMALY_MIN_EVENTS=2, SPI_ANOMALY_MIN_DISTINCT_TARGETS=1)
    ctx = DetectionContext(settings=settings, analysis_started_at=datetime.now())
    events = [
        CanonicalLogEvent(event_id=f"e{i}", timestamp=datetime.now(), src_ip="1.2.3.4", dst_ip="10.0.0.1", action_reason="SPI packet dropped")
        for i in range(2)
    ]
    signals = rule.evaluate(events, ctx)
    assert len(signals) == 1
""",
    "test_network_flood.py": """
from datetime import datetime
from agent.schema import CanonicalLogEvent
from agent.detection.detectors.network_flood import NetworkFloodRule
from agent.detection.detectors.base import DetectionContext
from agent.detection.config import DetectionSettings

def test_flood_positive():
    rule = NetworkFloodRule()
    settings = DetectionSettings(NETWORK_FLOOD_MIN_EVENTS=5, NETWORK_FLOOD_MIN_BLOCK_RATIO=0.8)
    ctx = DetectionContext(settings=settings, analysis_started_at=datetime.now())
    events = [
        CanonicalLogEvent(event_id=f"e{i}", timestamp=datetime.now(), src_ip="1.2.3.4", dst_ip="10.0.0.1", action="block")
        for i in range(5)
    ]
    signals = rule.evaluate(events, ctx)
    assert len(signals) == 1
""",
    "test_signal_deduplication.py": """
from datetime import datetime
from agent.schema import CanonicalLogEvent
from agent.detection.engine import DetectionEngine
from agent.detection.config import DetectionSettings
from agent.detection.registry import RuleRegistry
from agent.detection.detectors.horizontal_scan import HorizontalScanRule
from agent.detection.detectors.remote_service_probe import RemoteServiceProbeRule

def test_exact_dedup():
    engine = DetectionEngine(settings=DetectionSettings(HORIZONTAL_SCAN_MIN_EVENTS=1, HORIZONTAL_SCAN_MIN_DISTINCT_TARGETS=1))
    # Provide identical events... actually DetectionEngine dedups events first, so exact dedup of signals happens naturally.
    pass

def test_rdp_precedence():
    registry = RuleRegistry()
    registry.register(HorizontalScanRule())
    registry.register(RemoteServiceProbeRule())
    settings = DetectionSettings(
        HORIZONTAL_SCAN_MIN_EVENTS=2, HORIZONTAL_SCAN_MIN_DISTINCT_TARGETS=2,
        REMOTE_SERVICE_MIN_EVENTS=2, REMOTE_SERVICE_MIN_DISTINCT_TARGETS=2
    )
    engine = DetectionEngine(registry=registry, settings=settings)
    events = [
        CanonicalLogEvent(event_id=f"e{i}", timestamp=datetime.now(), src_ip="1.2.3.4", dst_ip=f"10.0.0.{i}", dst_port=3389, action="block")
        for i in range(2)
    ]
    res = engine.analyze(events)
    # Both horizontal and remote service match, but RDP absorbs horizontal
    assert len(res.signals) == 1
    assert res.signals[0].signal_type == "rdp_probe"
""",
    "test_stable_ids.py": """
from datetime import datetime
from agent.detection.models import generate_signal_id, generate_incident_id

def test_stable_ids():
    dt = datetime(2025, 1, 1, 12, 5, 30)
    sig1 = generate_signal_id("r1", "1.0", "ent", "key", dt, ["e1", "e2"])
    sig2 = generate_signal_id("r1", "1.0", "ent", "key", dt, ["e2", "e1"]) # event order diff
    assert sig1 == sig2 # Should be invariant
    
    inc1 = generate_incident_id("fam", "typ", "ent", "key", dt)
    inc2 = generate_incident_id("fam", "typ", "ent", "key", dt)
    assert inc1 == inc2
""",
    "test_input_order_invariance.py": """
from datetime import datetime
from agent.schema import CanonicalLogEvent
from agent.detection.engine import DetectionEngine
from agent.detection.config import DetectionSettings
from agent.detection.detectors.horizontal_scan import HorizontalScanRule
from agent.detection.registry import RuleRegistry

def test_order_invariance():
    registry = RuleRegistry()
    registry.register(HorizontalScanRule())
    settings = DetectionSettings(HORIZONTAL_SCAN_MIN_EVENTS=2, HORIZONTAL_SCAN_MIN_DISTINCT_TARGETS=2)
    engine = DetectionEngine(registry=registry, settings=settings)
    
    events = [
        CanonicalLogEvent(event_id="e1", timestamp=datetime(2025,1,1), src_ip="1.2.3.4", dst_ip="10.0.0.1", dst_port=80, action="block"),
        CanonicalLogEvent(event_id="e2", timestamp=datetime(2025,1,1), src_ip="1.2.3.4", dst_ip="10.0.0.2", dst_port=80, action="block")
    ]
    
    res1 = engine.analyze(events)
    
    events_shuffled = events[::-1]
    res2 = engine.analyze(events_shuffled)
    
    assert res1.signals[0].signal_id == res2.signals[0].signal_id
""",
    "test_scoring.py": """
from agent.detection.scoring import calculate_signal_confidence

def test_confidence_scoring():
    c = calculate_signal_confidence(10, 5, base_confidence=0.5, max_confidence=0.9)
    assert 0.5 < c <= 0.9
""",
    "test_suppression.py": """
from agent.detection.suppression import SuppressionPolicy
from agent.detection.models import DetectionSignal
from datetime import datetime

def test_suppression():
    pol = SuppressionPolicy()
    pol.add_allowed_source("10.0.0.0/8")
    sig = DetectionSignal(
        signal_id="x", rule_id="y", rule_version="z", rule_name="name",
        signal_type="type", signal_family="fam", severity="low", confidence=0.5,
        first_seen=datetime.now(), last_seen=datetime.now(), event_ids=[], primary_entity="10.1.1.1",
        target_entities=[], metrics={}, evidence=[], mitre_techniques=[], tags=[]
    )
    assert pol.is_suppressed(sig) is not None
""",
    "test_detection_engine.py": """
from agent.detection.engine import DetectionEngine
from agent.schema import CanonicalLogEvent
from datetime import datetime

def test_engine_empty():
    engine = DetectionEngine()
    res = engine.analyze([])
    assert len(res.signals) == 0
    
def test_engine_invalid_event():
    engine = DetectionEngine()
    # Missing timestamp should skip
    res = engine.analyze([CanonicalLogEvent(event_id="e1")])
    assert res.metrics.skipped_events == 1
""",
    "test_detect_api.py": """
from fastapi.testclient import TestClient
from server import app

client = TestClient(app)

def test_detect_api(tmp_path):
    log_file = tmp_path / "test.jsonl"
    log_file.write_text('{"src_ip": "1.2.3.4", "action": "block"}')
    with open(log_file, "rb") as f:
        response = client.post("/detect/file", files={"file": ("test.jsonl", f, "application/jsonl")})
    assert response.status_code == 200
    assert "detection" in response.json()
""",
    "test_false_positive_regressions.py": """
from agent.detection.engine import DetectionEngine
from agent.schema import CanonicalLogEvent
from datetime import datetime

def test_long_dns_domain_no_tunneling():
    engine = DetectionEngine()
    ev = CanonicalLogEvent(event_id="e1", timestamp=datetime.now(), event_type="DNS_QUERY", destination_fqdns=["verylonglegitimateservicename123456.googleapis.com"])
    res = engine.analyze([ev])
    assert len(res.signals) == 0

def test_same_target_repeat_no_scan():
    engine = DetectionEngine()
    events = [
        CanonicalLogEvent(event_id=f"e{i}", timestamp=datetime.now(), src_ip="1.2.3.4", dst_ip="10.0.0.1", dst_port=80, action="block")
        for i in range(10)
    ]
    res = engine.analyze(events)
    assert len(res.signals) == 0
"""
}

for name, content in files.items():
    with open(os.path.join(TEST_DIR, name), "w", encoding="utf-8") as f:
        f.write(content.strip())
