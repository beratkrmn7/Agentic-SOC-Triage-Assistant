from agent.nodes import reporter_node

def test_reporter_sqli_format():
    state = {
        "incident_id": "TEST-01",
        "triage_verdict": "suspicious",
        "incident_type": "sql_injection",
        "severity": "high",
        "confidence_score": 0.9,
        "mitre_techniques": ["T1190 - Exploit Public-Facing Application"],
        "validated_evidence": [
            {"event_id": "E1", "quote": "POST /login OR '1'='1"},
            {"event_id": "E2", "quote": "POST /login UNION SELECT"},
            {"event_id": "E3", "quote": "POST /login DROP TABLE"},
            {"event_id": "E4", "quote": "POST /login sleep(10)"}
        ],
        "recommended_actions": [
            "Action 1", "Action 2", "Action 3", "Action 4"
        ]
    }
    
    res = reporter_node(state)
    report = res["final_report"]
    
    assert "## Triage Summary" in report
    assert "## Why It Matters" in report
    assert "## Key Evidence" in report
    assert "## Recommended Actions" in report
    assert "## MITRE ATT&CK" in report
    
    # Check truncation (max 3)
    assert "- E1:" in report
    assert "- E3:" in report
    assert "- E4:" not in report
    
    assert "- Action 3" in report
    assert "- Action 4" not in report
    
    # Check no hallucination
    assert "database compromised" not in report.lower()
    
    # Check length
    word_count = len(report.split())
    assert word_count <= 220

def test_reporter_false_positive():
    state = {
        "incident_id": "TEST-02",
        "triage_verdict": "false_positive",
        "incident_type": "benign_web_traffic",
        "severity": "none",
        "confidence_score": 0.9,
        "mitre_techniques": [],
        "validated_evidence": [{"event_id": "E1", "quote": "GET /"}],
        "recommended_actions": ["No action required."]
    }
    
    res = reporter_node(state)
    report = res["final_report"]
    
    assert "The logs only show successful 200 OK web requests" in report
    assert "## MITRE ATT&CK" not in report
    word_count = len(report.split())
    assert word_count <= 220

def test_reporter_needs_review():
    state = {
        "incident_id": "TEST-03",
        "triage_verdict": "needs_review",
        "incident_type": "other",
        "severity": "none",
        "confidence_score": 0.0,
        "mitre_techniques": [],
        "validated_evidence": [],
        "recommended_actions": ["Manual review necessary"]
    }
    
    res = reporter_node(state)
    report = res["final_report"]
    
    assert "Automated triage could not validate enough evidence" in report
    assert "reviewed by a SOC analyst" in report
    assert "No validated evidence available" in report
    word_count = len(report.split())
    assert word_count <= 220
