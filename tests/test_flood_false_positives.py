
from agent.tools import detect_network_flood
def test_flood_fp():
    logs = [{"src_ip": "1.1.1.1", "dst_ip": "2.2.2.2", "timestamp": "2026-07-10T10:00:00Z", "action": "pass"}] * 30
    res = detect_network_flood(logs)
    assert res["status"] == "not_applicable"
