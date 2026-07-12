from typing import List, Dict, Optional
from pydantic import BaseModel, ConfigDict
from agent.models import IncidentState
from agent.ingestion.models import CanonicalLogEvent, IngestionResult
from agent.detection.models import DetectionResult, DetectionSignal

class AnalysisResult(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)
    
    source_name: Optional[str] = None
    ingestion_result: Optional[IngestionResult] = None
    detection_result: Optional[DetectionResult] = None
    incidents: List[IncidentState] = []
    
    # Maps of domain entities
    event_map: Dict[str, CanonicalLogEvent] = {}
    signal_map: Dict[str, DetectionSignal] = {}
