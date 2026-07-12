from typing import List, Dict, Any, cast
from agent.models import IncidentBundle
from agent.triage.models import TriageInput, SafeEventView, EvidenceCandidate
from agent.config import get_settings
from agent.schema import CanonicalLogEvent
import hashlib

def generate_evidence_id(incident_id: str, event_id: str, source: str, quote: str, reason: str) -> str:
    hash_input = f"{incident_id}|{event_id}|{source}|{quote}|{reason}"
    return hashlib.sha256(hash_input.encode('utf-8')).hexdigest()[:12]

def truncate_str(s: str, max_len: int = 500) -> str:
    if not s:
        return ""
    if len(s) > max_len:
        return s[:max_len] + "... [TRUNCATED]"
    return s

def _build_safe_event(event: CanonicalLogEvent, max_preview_chars: int = 1000) -> SafeEventView:
    return SafeEventView(
        event_id=event.event_id,
        timestamp=event.timestamp.isoformat() if event.timestamp else "",
        src_ip=event.src_ip,
        dst_ip=event.dst_ip,
        src_port=event.src_port,
        dst_port=event.dst_port,
        protocol=event.protocol,
        action=event.action,
        action_reason=event.action_reason,
        event_type=event.event_type,
        event_category=event.event_category,
        event_outcome=event.event_outcome,
        tcp_flags=event.tcp_flags,
        parser_name=event.parser_name or "unknown",
        source_name=event.source_name or "unknown",
        sanitized_message_excerpt=truncate_str(event.raw_message, max_preview_chars) if event.raw_message else None
    )

def build_triage_input(
    bundle: IncidentBundle,
    detected_signals: List[Dict[str, Any]],
    candidate_evidence: List[Dict[str, Any]]
) -> TriageInput:
    
    settings = get_settings()
    max_preview_chars = settings.max_event_preview_chars
    max_context_events = settings.max_context_events
    max_candidate_evidence = settings.max_candidate_evidence
    
    # Sort events deterministically by timestamp then event_id
    sorted_events = sorted(bundle.events, key=lambda e: (e.timestamp or "", e.event_id))
    safe_events = [_build_safe_event(e, max_preview_chars) for e in sorted_events]
    
    sorted_context = sorted(bundle.context_events, key=lambda e: (e.timestamp or "", e.event_id))
    safe_context = [_build_safe_event(e, max_preview_chars) for e in sorted_context]
    
    signal_summaries = []
    for sig in detected_signals:
        signal_summaries.append(f"[{sig.get('detector_name', 'unknown')}] {sig.get('description', '')} - Severity: {sig.get('severity', 'none')} Confidence: {sig.get('confidence_score', 0.0)}")
    signal_summaries.sort()
    
    ev_candidates = []
    for ev in candidate_evidence:
        quote = ev.get('quote', '')
        reason = ev.get('reason', '')
        source = ev.get('source', '')
        event_id = ev.get('event_id', '')
        ev_id = generate_evidence_id(bundle.incident_id, event_id, source, quote, reason)
        
        ev_candidates.append(EvidenceCandidate(
            evidence_id=ev_id,
            event_id=event_id,
            quote=quote,
            reason=reason,
            source=source,
            original_fields=ev.get('original_fields', {}),
            correlation_context=ev.get('correlation_context', {})
        ))
        
    ev_candidates.sort(key=lambda c: c.evidence_id)
    ev_candidates = ev_candidates[:max_candidate_evidence]
    
    limited_events = (safe_events + safe_context)[:max_context_events]
    
    mitre_set = set()
    for sig in detected_signals:
        if sig.get('mitre_techniques'):
            mitre_set.add(sig.get('mitre_techniques')[0])
    
    p_warns = set()
    dq_warns = set()
    for e in bundle.events + bundle.context_events:
        for w in getattr(e, 'parse_warnings', []):
            p_warns.add(w)
        for w in getattr(e, 'data_quality_warnings', []):
            dq_warns.add(w)
            
    return TriageInput(
        incident_id=bundle.incident_id,
        incident_type=bundle.incident_type_hint,
        incident_family=bundle.incident_type_hint, # Usually similar or derived
        title=f"Suspicious Activity detected: {bundle.incident_type_hint}",
        deterministic_severity=bundle.severity_hint or "low",
        deterministic_confidence=bundle.confidence_hint or 0.0,
        first_seen=bundle.first_seen.isoformat() if bundle.first_seen else "",
        last_seen=bundle.last_seen.isoformat() if bundle.last_seen else "",
        primary_entity=cast(list, bundle.source_ips)[0] if bundle.source_ips else "unknown",
        target_entities=bundle.destination_ips,
        signal_summaries=signal_summaries,
        candidate_evidence=ev_candidates,
        limited_context_events=limited_events,
        allowed_mitre_candidates=sorted(list(mitre_set)),
        parser_warnings=sorted(list(p_warns)),
        data_quality_warnings=sorted(list(dq_warns))
    )
