from agent.triage.validation import validate_evidence
from agent.triage.claims import validate_claims
from agent.triage.models import TriageSubmission, TriageInput, SafeEventView, EvidenceCandidate, TriageClaim
from agent.triage.enums import TriageVerdict, TriageSeverity, RejectionReason, ClaimType

def test_validate_evidence_success():
    submission = TriageSubmission(
        triage_verdict=TriageVerdict.CONFIRMED_INCIDENT,
        incident_type="test",
        severity=TriageSeverity.HIGH,
        confidence_score=0.9,
        summary="Test",
        selected_evidence_ids=["ev_1"],
        claims=[]
    )
    
    triage_input = TriageInput(
        incident_id="INC-1",
        incident_type="test",
        incident_family="test",
        title="test",
        deterministic_severity="high",
        deterministic_confidence=1.0,
        first_seen="2024",
        last_seen="2024",
        primary_entity="ip",
        candidate_evidence=[
            EvidenceCandidate(
                evidence_id="ev_1",
                event_id="EVT-1",
                quote="error occurred",
                reason="test",
                source="test_parser",
                original_fields={"src_ip": "1.2.3.4"}
            )
        ],
        limited_context_events=[
            SafeEventView(
                event_id="EVT-1",
                timestamp="2024",
                parser_name="test_parser",
                source_name="test_source",
                sanitized_message_excerpt="An error occurred here",
                src_ip="1.2.3.4"
            )
        ]
    )
    
    from agent.schema import CanonicalLogEvent
    from datetime import datetime, timezone
    trusted_events = [CanonicalLogEvent(event_id="EVT-1", timestamp=None, observed_at=datetime.now(timezone.utc), parse_status="success", parser_name="test_parser", source_name="test_source", raw_message="An error occurred here", original_log={"src_ip": "1.2.3.4"})]
    results = validate_evidence(submission, triage_input, trusted_events)
    assert len(results) == 1
    assert results[0].status == "validated"

def test_validate_evidence_quote_mismatch():
    submission = TriageSubmission(
        triage_verdict=TriageVerdict.CONFIRMED_INCIDENT,
        incident_type="test",
        severity=TriageSeverity.HIGH,
        confidence_score=0.9,
        summary="Test",
        selected_evidence_ids=["ev_1"],
        claims=[]
    )
    
    triage_input = TriageInput(
        incident_id="INC-1",
        incident_type="test",
        incident_family="test",
        title="test",
        deterministic_severity="high",
        deterministic_confidence=1.0,
        first_seen="2024",
        last_seen="2024",
        primary_entity="ip",
        candidate_evidence=[
            EvidenceCandidate(
                evidence_id="ev_1",
                event_id="EVT-1",
                quote="hallucinated quote",
                reason="test",
                source="test_parser",
                original_fields={"src_ip": "1.2.3.4"}
            )
        ],
        limited_context_events=[
            SafeEventView(
                event_id="EVT-1",
                timestamp="2024",
                parser_name="test_parser",
                source_name="test_source",
                sanitized_message_excerpt="An error occurred here",
                src_ip="1.2.3.4"
            )
        ]
    )
    
    from agent.schema import CanonicalLogEvent
    from datetime import datetime, timezone
    trusted_events = [CanonicalLogEvent(event_id="EVT-1", timestamp=None, observed_at=datetime.now(timezone.utc), parse_status="success", parser_name="test_parser", source_name="test_source", raw_message="An error occurred here", original_log={"src_ip": "1.2.3.4"})]
    results = validate_evidence(submission, triage_input, trusted_events)
    assert len(results) == 1
    assert results[0].status == "rejected"
    assert results[0].rejection_reason == RejectionReason.EVIDENCE_REJECTED

def test_validate_evidence_fields_mismatch():
    submission = TriageSubmission(
        triage_verdict=TriageVerdict.CONFIRMED_INCIDENT,
        incident_type="test",
        severity=TriageSeverity.HIGH,
        confidence_score=0.9,
        summary="Test",
        selected_evidence_ids=["ev_1"],
        claims=[]
    )
    
    triage_input = TriageInput(
        incident_id="INC-1",
        incident_type="test",
        incident_family="test",
        title="test",
        deterministic_severity="high",
        deterministic_confidence=1.0,
        first_seen="2024",
        last_seen="2024",
        primary_entity="ip",
        candidate_evidence=[
            EvidenceCandidate(
                evidence_id="ev_1",
                event_id="EVT-1",
                quote="error",
                reason="test",
                source="test_parser",
                original_fields={"src_ip": "9.9.9.9"} # Mismatch
            )
        ],
        limited_context_events=[
            SafeEventView(
                event_id="EVT-1",
                timestamp="2024",
                parser_name="test_parser",
                source_name="test_source",
                sanitized_message_excerpt="An error occurred here",
                src_ip="1.2.3.4"
            )
        ]
    )
    
    from agent.schema import CanonicalLogEvent
    from datetime import datetime, timezone
    trusted_events = [CanonicalLogEvent(event_id="EVT-1", timestamp=None, observed_at=datetime.now(timezone.utc), parse_status="success", parser_name="test_parser", source_name="test_source", raw_message="An error occurred here", original_log={"src_ip": "1.2.3.4"})]
    results = validate_evidence(submission, triage_input, trusted_events)
    assert len(results) == 1
    assert results[0].status == "rejected"
    assert results[0].rejection_reason == RejectionReason.EVIDENCE_REJECTED

def test_validate_claims():
    from agent.triage.models import EvidenceValidationResult
    claims = [
        TriageClaim(
            claim_id="cl_1",
            claim_type=ClaimType.OTHER,
            statement="Test",
            supporting_evidence_ids=["ev_1"],
            supporting_event_ids=["EVT-1"]
        ),
        TriageClaim(
            claim_id="cl_2",
            claim_type=ClaimType.OTHER,
            statement="Test",
            supporting_evidence_ids=["ev_2"], # Hallucinated or rejected
            supporting_event_ids=["EVT-1"]
        )
    ]
    
    validated_evidence = [
        EvidenceValidationResult(evidence_id="ev_1", event_id="EVT-1", status="validated"),
        EvidenceValidationResult(evidence_id="ev_2", event_id="EVT-1", status="rejected", rejection_reason=RejectionReason.EVIDENCE_REJECTED)
    ]
    
    accepted, rejected = validate_claims(claims, validated_evidence)
    assert len(accepted) == 1
    assert accepted[0].claim_id == "cl_1"
    assert len(rejected) == 1
    assert rejected[0]["claim_id"] == "cl_2"
    assert rejected[0]["reason"] == RejectionReason.EVIDENCE_REJECTED.value
