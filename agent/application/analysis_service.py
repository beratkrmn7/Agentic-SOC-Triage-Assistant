from typing import Optional, List, Dict, Any
from agent.application.models import AnalysisResult
from agent.ingestion.pipeline import IngestionPipeline
from agent.ingestion.models import CanonicalLogEvent
from agent.filtering import EventFilter
from agent.detection.engine import DetectionEngine
from agent.models import IncidentState
from agent.graph import app
import traceback

class AnalysisService:
    def __init__(self, uow: Optional[Any] = None):
        self.uow = uow
        self.ingest = IngestionPipeline()
        self.filter_engine = EventFilter()
        self.detection_engine = DetectionEngine()

    def analyze_file(self, file_path: str, *, run_triage: bool = True, source_name: Optional[str] = None) -> AnalysisResult:
        # 1. Ingestion
        ingest_result = self.ingest.ingest_file(file_path)
        return self._process_events(
            events=ingest_result.events,
            run_triage=run_triage,
            ingestion_result=ingest_result,
            source_name=source_name or ingest_result.source_name
        )

    def analyze_events(self, events: List[CanonicalLogEvent], *, run_triage: bool = True) -> AnalysisResult:
        return self._process_events(
            events=events,
            run_triage=run_triage,
            ingestion_result=None,
            source_name="api"
        )

    def _process_events(self, events: List[CanonicalLogEvent], run_triage: bool, ingestion_result: Any, source_name: str) -> AnalysisResult:
        # 2. Filtering
        filter_result = self.filter_engine.filter_events(events)
        
        # 3. Detection
        det_result = self.detection_engine.analyze(filter_result.candidates, filter_result.context)
        
        event_map = {e.event_id: e for e in events if e.event_id}
        signal_map = {s.signal_id: s for s in det_result.signals}
        
        result = AnalysisResult(
            source_name=source_name,
            ingestion_result=ingestion_result,
            detection_result=det_result,
            event_map=event_map,
            signal_map=signal_map,
            incidents=[]
        )
        
        # 4. Persistence setup (Optional Phase 5 integration point)
        # If we have a Unit Of Work, we can persist the canonical events, signals, and incidents here.
        if self.uow:
            pass # TODO: Implement persistence hook
        
        # 5. Graph Invocation (Triage)
        for inc in det_result.incidents:
            initial_state = self._build_initial_state(inc, event_map, signal_map)
            
            if run_triage:
                try:
                    final_state = app.invoke(initial_state)
                    result.incidents.append(final_state)
                    
                    if self.uow:
                        pass # TODO: Persist final state (Triage run, Evidence, Report)
                        
                except Exception as e:
                    print(f"Error during triage: {e}")
                    traceback.print_exc()
                    result.incidents.append(initial_state)
            else:
                result.incidents.append(initial_state)
                
        return result

    def _build_initial_state(self, incident: Any, event_map: Dict[str, CanonicalLogEvent], signal_map: Dict[str, Any]) -> IncidentState:
        # Reconstruct the logic that was duplicated in main.py and server.py
        if isinstance(incident, dict):
            incident_id = incident.get("incident_id")
            event_ids = incident.get("event_ids", [])
            signal_ids = incident.get("signal_ids", [])
            evidence_list = incident.get("evidence", [])
        else:
            incident_id = getattr(incident, 'incident_id', None)
            event_ids = getattr(incident, 'event_ids', [])
            signal_ids = getattr(incident, 'signal_ids', [])
            evidence_list = getattr(incident, 'evidence', [])
        
        canonical_events = []
        for eid in event_ids:
            if eid in event_map:
                canonical_events.append(event_map[eid].model_dump(mode="json"))
                
        detected_signals = []
        for sid in signal_ids:
            if sid in signal_map:
                sig = signal_map[sid]
                detected_signals.append({
                    "detector_name": getattr(sig, 'rule_name', 'Unknown'),
                    "status": "alert",
                    "message": f"{getattr(sig, 'rule_name', 'Unknown')} detected. Severity: {getattr(sig, 'severity', 'low')}",
                    "matched_event_ids": getattr(sig, 'event_ids', [])
                })
                
        candidate_evidence = []
        for ev in evidence_list:
            candidate_evidence.append({
                "event_id": getattr(ev, 'event_id', ev.get('event_id') if isinstance(ev, dict) else None),
                "quote": getattr(ev, 'quote', ev.get('quote') if isinstance(ev, dict) else ""),
                "reason": getattr(ev, 'reason', ev.get('reason') if isinstance(ev, dict) else ""),
                "source": getattr(ev, 'source', ev.get('source') if isinstance(ev, dict) else ""),
                "original_fields": getattr(ev, 'original_fields', ev.get('original_fields') if isinstance(ev, dict) else {}),
                "correlation_context": getattr(ev, 'correlation_context', ev.get('correlation_context') if isinstance(ev, dict) else {})
            })
            
        # Extract Phase 3 IncidentBundle fields to ensure lossless transport
        incident_bundle = None
        if hasattr(incident, 'model_dump'):
            incident_bundle = incident.model_dump(mode="json")
            
        return {
            "incident": incident_bundle, # Pass true incident bundle!
            "incident_id": incident_id,
            "canonical_events": canonical_events,
            "messages": [],
            "iteration_count": 0,
            "mitre_techniques": [],
            "candidate_evidence": candidate_evidence,
            "detected_signals": detected_signals,
            "search_history": [],
            "tool_results": [],
            "errors": [],
            "detection_engine_executed": True
        }
