from agent.detection.registry import RuleRegistry
from agent.detection.detectors.base import BaseDetectionRule

class DummyRule(BaseDetectionRule):
    rule_id = "dummy"
    version = "1.0"
    name = "Dummy"
    family = "dummy"
    priority = 1
    def evaluate(self, e, c): return []

def test_registry():
    r = RuleRegistry()
    r.register(DummyRule())
    assert len(r.get_all_rules()) == 1
    assert r.get_rule("dummy").rule_id == "dummy"
    r.unregister("dummy")
    assert len(r.get_all_rules()) == 0