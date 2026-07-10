
from agent.filtering import EventFilter
from agent.schema import CanonicalLogEvent
def test_filtering():
    f = EventFilter()
    noise_ev = CanonicalLogEvent(event_id="1", action="pass", dst_port=80, bytes=1000, parser_name="test", parse_status="success")
    cand_ev = CanonicalLogEvent(event_id="2", action="block", dst_port=3389, parser_name="test", parse_status="success")
    res = f.filter_events([noise_ev, cand_ev])
    assert len(res.noise) == 1
    assert len(res.candidates) == 1
