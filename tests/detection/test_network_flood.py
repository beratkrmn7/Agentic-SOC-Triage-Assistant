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
        CanonicalLogEvent(event_id=f"e{i}", timestamp=datetime.now(), src_ip="1.2.3.4", dst_ip="10.0.0.1", action="block", parser_name="test", parse_status="success")
        for i in range(5)
    ]
    signals = rule.evaluate(events, ctx)
    assert len(signals) == 1