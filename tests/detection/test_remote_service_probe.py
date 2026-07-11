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
        CanonicalLogEvent(event_id=f"e{i}", timestamp=datetime.now(), src_ip="1.2.3.4", dst_ip=f"10.0.0.{i}", dst_port=3389, action="block", parser_name="test", parse_status="success")
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
        CanonicalLogEvent(event_id=f"e{i}", timestamp=datetime.now(), src_ip="1.2.3.4", dst_ip=f"10.0.0.{i}", dst_port=22, action="block", parser_name="test", parse_status="success")
        for i in range(2)
    ]
    signals = rule.evaluate(events, ctx)
    assert len(signals) == 1
    assert signals[0].signal_type == "ssh_probe"