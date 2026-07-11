from typing import List
from agent.triage.models import TriageInput, TriageSubmission, EvidenceValidationResult
from agent.triage.enums import RejectionReason

def normalize_text(text: str) -> str:
    # Defined normalization policy: lowercase, strip, remove extra whitespaces
    if not text:
        return ""
    import re
    return re.sub(r'\s+', ' ', text.strip().lower())

def validate_evidence(submission: TriageSubmission, triage_input: TriageInput) -> List[EvidenceValidationResult]:
    results = []
    
    # Pre-compute valid IDs
    valid_candidate_ids = {c.evidence_id: c for c in triage_input.candidate_evidence}
    valid_event_map = {e.event_id: e for e in triage_input.limited_context_events}
    
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
        
        # Check scope and canonical store existence
        if candidate.event_id not in valid_event_map:
            results.append(EvidenceValidationResult(
                evidence_id=ev_id,
                event_id=candidate.event_id,
                status="rejected",
                rejection_reason=RejectionReason.EVENT_OUTSIDE_INCIDENT_SCOPE
            ))
            continue
            
        canonical_event = valid_event_map[candidate.event_id]
        
        # Validate quote against canonical raw_message (sanitized_message_excerpt in safe view)
        if candidate.quote:
            norm_quote = normalize_text(candidate.quote)
            norm_raw = normalize_text(canonical_event.sanitized_message_excerpt or "")
            if norm_quote not in norm_raw:
                results.append(EvidenceValidationResult(
                    evidence_id=ev_id,
                    event_id=candidate.event_id,
                    status="rejected",
                    rejection_reason=RejectionReason.EVIDENCE_REJECTED # Mismatch quote
                ))
                continue
                
        # Validate original_fields parity
        if candidate.original_fields:
            # We must ensure all fields in candidate exist in the canonical event and match.
            # However, SafeEventView doesn't have raw original_fields, it has parsed fields.
            # We match against the properties of SafeEventView
            mismatch = False
            for k, v in candidate.original_fields.items():
                if hasattr(canonical_event, k):
                    if getattr(canonical_event, k) != v:
                        mismatch = True
                        break
            if mismatch:
                results.append(EvidenceValidationResult(
                    evidence_id=ev_id,
                    event_id=candidate.event_id,
                    status="rejected",
                    rejection_reason=RejectionReason.EVIDENCE_REJECTED # Mismatch fields
                ))
                continue
                
        # Validate source/provenance
        if candidate.source:
            if candidate.source != canonical_event.source_name and candidate.source != canonical_event.parser_name:
                results.append(EvidenceValidationResult(
                    evidence_id=ev_id,
                    event_id=candidate.event_id,
                    status="rejected",
                    rejection_reason=RejectionReason.EVIDENCE_REJECTED # Mismatch source
                ))
                continue
                
        # Validate correlation context (ensure it relates to the incident)
        if candidate.correlation_context:
            target_entities = triage_input.target_entities
            mismatch = False
            for k, v in candidate.correlation_context.items():
                if v not in target_entities and v != triage_input.primary_entity:
                    # If correlation context refers to an entity not in this incident
                    mismatch = True
                    break
            if mismatch:
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
