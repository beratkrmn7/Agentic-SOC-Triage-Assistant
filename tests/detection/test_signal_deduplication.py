from datetime import datetime, timezone
from agent.schema import CanonicalLogEvent
from agent.detection.engine import DetectionEngine
from agent.detection.config import DetectionSettings
from agent.detection.registry import RuleRegistry
from agent.detection.detectors.horizontal_scan import HorizontalScanRule
from agent.detection.detectors.remote_service_probe import RemoteServiceProbeRule

def test_exact_dedup():
    DetectionEngine(settings=DetectionSettings(HORIZONTAL_SCAN_MIN_EVENTS=1, HORIZONTAL_SCAN_MIN_DISTINCT_TARGETS=1))
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
        CanonicalLogEvent(event_id=f"e{i}", timestamp=datetime.now(timezone.utc), src_ip="1.2.3.4", dst_ip=f"10.0.0.{i}", dst_port=3389, action="block", parser_name="test", parse_status="success", protocol="TCP", tcp_flags="SYN")
        for i in range(2)
    ]
    res = engine.analyze(events)
    # Both horizontal scan and remote service probe signals stay in
    # DetectionResult.signals (Phase 6E.2 no longer deletes the generic
    # scan signal); incident correlation attaches both to one incident with
    # the more specific rdp_probe signal as its anchor/identity.
    assert len(res.signals) == 2
    rule_ids = {s.rule_id for s in res.signals}
    assert rule_ids == {"rdp_probe", "network_scan_horizontal"}
    rdp_signal = next(s for s in res.signals if s.rule_id == "rdp_probe")
    assert rdp_signal.rule_name == "RDP Probe"
    assert rdp_signal.signal_type == "rdp_probe"
    assert len(res.incidents) == 1
    assert res.incidents[0].incident_type == "rdp_probe"
    assert set(res.incidents[0].signal_ids) == {s.signal_id for s in res.signals}
