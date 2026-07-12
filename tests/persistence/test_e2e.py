import pytest
from fastapi.testclient import TestClient
from server import app
import tempfile
import json
from agent.persistence.database import SessionLocal
from agent.persistence.orm_models import Incident, TriageRun

@pytest.fixture
def test_client():
    return TestClient(app)

@pytest.fixture
def db_session():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def test_api_to_db_flow(test_client, db_session):
    import random
    src_ip = f"1.2.3.{random.randint(1, 250)}"
    # 1. Create a dummy log file that triggers an incident (Vertical Scan: >=10 events, >=8 ports, >60% blocks)
    logs = []
    for port in range(1, 15):
        logs.append(json.dumps({
            "timestamp": f"2023-01-01T12:00:{port:02d}Z",
            "src_ip": src_ip, 
            "dst_ip": "10.0.0.1",
            "dst_port": port,
            "protocol": "tcp",
            "tcp_flags": "SYN",
            "action": "block"
        }))
    log_content = "\n".join(logs) + "\n"
    
    with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".jsonl") as tf:
        tf.write(log_content)
        tf_name = tf.name
        
    # 2. Call the analyze API endpoint
    with open(tf_name, "rb") as f:
        res = test_client.post("/analyze/file", files={"file": f})
        
    assert res.status_code == 200, res.text
    data = res.json()
    assert data["incidents_generated"] > 0
    incident_id = data["incidents"][0]["incident_id"]
    
    # 3. Verify that the incident was saved to the database
    orm_inc = db_session.query(Incident).filter(Incident.incident_id == incident_id).first()
    assert orm_inc is not None
    assert orm_inc.status == "triaged"
    
    # 4. Verify triage runs were created
    runs = db_session.query(TriageRun).filter(TriageRun.incident_id == incident_id).all()
    assert len(runs) > 0
    
    # 5. Call the v1 incidents API
    res = test_client.get(f"/api/v1/incidents/{incident_id}")
    assert res.status_code == 200
    inc_data = res.json()
    assert inc_data["status"] == "triaged"
    
    # 6. Change status
    res = test_client.patch(f"/api/v1/incidents/{incident_id}/status", json={"status": "investigating"})
    assert res.status_code == 200
    
    # 7. Check timeline
    res = test_client.get(f"/api/v1/incidents/{incident_id}/timeline")
    assert res.status_code == 200
    timeline = res.json()
    assert len(timeline) > 0
    assert timeline[0]["action"] == "status_change"
    assert timeline[0]["new_status"] == "investigating"
