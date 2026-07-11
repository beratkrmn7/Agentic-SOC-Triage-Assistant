from datetime import datetime
from agent.detection.models import generate_signal_id, generate_incident_id

def test_stable_ids():
    dt = datetime(2025, 1, 1, 12, 5, 30)
    sig1 = generate_signal_id("r1", "1.0", "ent", "key", dt, ["e1", "e2"])
    sig2 = generate_signal_id("r1", "1.0", "ent", "key", dt, ["e2", "e1"]) # event order diff
    assert sig1 == sig2 # Should be invariant
    
    inc1 = generate_incident_id("fam", "typ", "ent", "key", dt)
    inc2 = generate_incident_id("fam", "typ", "ent", "key", dt)
    assert inc1 == inc2