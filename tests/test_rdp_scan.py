
from agent.correlation import CorrelationEngine
from agent.schema import CanonicalLogEvent
def test_rdp():
    c = CorrelationEngine()
    evs = [CanonicalLogEvent(event_id=str(i), src_ip="1.1.1.1", dst_port=3389, action="block", parser_name="t", parse_status="s") for i in range(3)]
    bundles = c.detect_rdp_scan(evs, [])
    assert len(bundles) == 1
