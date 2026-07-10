
from agent.correlation import CorrelationEngine
from agent.schema import CanonicalLogEvent
def test_spi():
    c = CorrelationEngine()
    evs = [CanonicalLogEvent(event_id=str(i), src_ip="1.1.1.1", raw_message="blocked by spi", parser_name="t", parse_status="s") for i in range(3)]
    bundles = c.detect_spi_anomaly_cluster(evs, [])
    assert len(bundles) == 1
