
from agent.correlation import CorrelationEngine
from agent.schema import CanonicalLogEvent
from datetime import datetime
def test_vertical():
    c = CorrelationEngine()
    evs = []
    base_time = datetime.now()
    for i in range(5):
        evs.append(CanonicalLogEvent(event_id=str(i), src_ip="1.1.1.1", dst_ip="2.2.2.2", dst_port=1000+i, timestamp=base_time, parser_name="t", parse_status="s"))
    bundles = c.detect_vertical_port_scan(evs, [])
    assert len(bundles) == 1
    assert bundles[0].incident_type_hint == "vertical_port_scan"
