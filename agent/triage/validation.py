from typing import List
from agent.triage.models import TriageInput, TriageSubmission, EvidenceValidationResult
from agent.triage.enums import RejectionReason

def validate_evidence(submission: TriageSubmission, triage_input: TriageInput) -> List[EvidenceValidationResult]:
    results = []
    
    # Pre-compute valid IDs
    valid_candidate_ids = {c.evidence_id: c for c in triage_input.candidate_evidence}
    valid_event_ids = {e.event_id for e in triage_input.limited_context_events}
    
    seen_ids = set()
    
    for ev_id in submission.selected_evidence_ids:
        # Check duplicate
        if ev_id in seen_ids:
            results.append(EvidenceValidationResult(
                evidence_id=ev_id,
                event_id="unknown",
                status="rejected",
                rejection_reason=RejectionReason.EVIDENCE_REJECTED
            ))
            continue
            
        seen_ids.add(ev_id)
        
        # Check existence
        if ev_id not in valid_candidate_ids:
            results.append(EvidenceValidationResult(
                evidence_id=ev_id,
                event_id="unknown",
                status="rejected",
                rejection_reason=RejectionReason.MISSING_SUPPORTING_EVIDENCE
            ))
            continue
            
        candidate = valid_candidate_ids[ev_id]
        
        # Check scope
        if candidate.event_id not in valid_event_ids:
            results.append(EvidenceValidationResult(
                evidence_id=ev_id,
                event_id=candidate.event_id,
                status="rejected",
                rejection_reason=RejectionReason.EVENT_OUTSIDE_INCIDENT_SCOPE
            ))
            continue
            
        # Accept
        results.append(EvidenceValidationResult(
            evidence_id=ev_id,
            event_id=candidate.event_id,
            status="validated"
        ))
        
    return results
