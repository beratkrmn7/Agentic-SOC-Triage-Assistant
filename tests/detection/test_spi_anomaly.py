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
        CanonicalLogEvent(event_id=f"e{i}", timestamp=datetime.now(), src_ip="1.2.3.4", dst_ip="10.0.0.1", action_reason="SPI packet dropped", parser_name="test", parse_status="success")
        for i in range(2)
    ]
    signals = rule.evaluate(events, ctx)
    assert len(signals) == 1