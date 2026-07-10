
from agent.schema import CanonicalLogEvent
def test_schema():
    ev = CanonicalLogEvent(event_id="test-1", parser_name="Mock", parse_status="success")
    assert ev.event_id == "test-1"
