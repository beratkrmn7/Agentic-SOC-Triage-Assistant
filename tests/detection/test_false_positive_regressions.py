from agent.detection.engine import DetectionEngine
from agent.schema import CanonicalLogEvent
from datetime import datetime

def test_long_dns_domain_no_tunneling():
    engine = DetectionEngine()
    ev = CanonicalLogEvent(event_id="e1", timestamp=datetime.now(), event_type="DNS_QUERY", destination_fqdns=["verylonglegitimateservicename123456.googleapis.com"], parser_name="test", parse_status="success")
    res = engine.analyze([ev])
    assert len(res.signals) == 0

def test_same_target_repeat_no_scan():
    engine = DetectionEngine()
    events = [
        CanonicalLogEvent(event_id=f"e{i}", timestamp=datetime.now(), src_ip="1.2.3.4", dst_ip="10.0.0.1", dst_port=80, action="block", parser_name="test", parse_status="success")
        for i in range(10)
    ]
    res = engine.analyze(events)
    assert len(res.signals) == 0