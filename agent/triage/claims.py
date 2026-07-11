from typing import List, Tuple
from agent.triage.models import TriageClaim, EvidenceValidationResult
from agent.triage.enums import ClaimType, RejectionReason

HIGH_IMPACT_CLAIMS = {
    ClaimType.ACCOUNT_COMPROMISE,
    ClaimType.CREDENTIAL_THEFT,
    ClaimType.SUCCESSFUL_EXPLOITATION,
    ClaimType.DATA_EXFILTRATION,
    ClaimType.DATABASE_COMPROMISE,
    ClaimType.MALWARE_EXECUTION,
    ClaimType.PERSISTENCE,
    ClaimType.LATERAL_MOVEMENT,
    ClaimType.BRUTE_FORCE_SUCCESS,
    ClaimType.SUCCESSFUL_AUTHENTICATION,
    ClaimType.COMMAND_EXECUTION
}

def validate_claims(claims: List[TriageClaim], validated_evidence: List[EvidenceValidationResult]) -> Tuple[List[TriageClaim], List[dict]]:
    valid_ev_ids = {r.evidence_id for r in validated_evidence if r.status == "validated"}
    
    accepted_claims = []
    rejected_claims = []
    
    for claim in claims:
        # Check if the claim type is recognized
        if not isinstance(claim.claim_type, ClaimType):
            rejected_claims.append({
                "claim_id": claim.claim_id,
                "reason": RejectionReason.UNSUPPORTED_CLAIM_TYPE.value
            })
            continue
            
        # Check for supporting evidence
        has_valid_support = False
        for ev_id in claim.supporting_evidence_ids:
            if ev_id in valid_ev_ids:
                has_valid_support = True
                break
                
        if not has_valid_support:
            rejected_claims.append({
                "claim_id": claim.claim_id,
                "reason": RejectionReason.MISSING_SUPPORTING_EVIDENCE.value
            })
            continue
            
        # Specific claim type validation could be added here
        # For now, if a high impact claim has validated evidence, we accept it.
        # But we ensure it has at least ONE piece of valid evidence.
        
        accepted_claims.append(claim)
        
    return accepted_claims, rejected_claims
