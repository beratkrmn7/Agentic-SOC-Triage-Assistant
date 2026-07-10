
from agent.correlation import CorrelationEngine
from agent.schema import CanonicalLogEvent
from datetime import datetime
def test_build():
    c = CorrelationEngine()
    evs = [CanonicalLogEvent(event_id=str(i), src_ip="1.1.1.1", raw_message="blocked by spi", timestamp=datetime.now(), parser_name="t", parse_status="s") for i in range(3)]
    bundles = c.build_incidents(evs, [])
    assert len(bundles) >= 1
