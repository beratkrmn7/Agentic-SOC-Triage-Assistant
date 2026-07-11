from agent.detection.suppression import SuppressionPolicy
from agent.detection.models import DetectionSignal
from datetime import datetime

def test_suppression():
    pol = SuppressionPolicy()
    pol.add_allowed_source("10.0.0.0/8")
    sig = DetectionSignal(
        signal_id="x", rule_id="y", rule_version="z", rule_name="name",
        signal_type="type", signal_family="fam", severity="low", confidence=0.5,
        first_seen=datetime.now(), last_seen=datetime.now(), event_ids=[], primary_entity="10.1.1.1",
        target_entities=[], metrics={}, evidence=[], mitre_techniques=[], tags=[]
    )
    assert pol.is_suppressed(sig) is not None