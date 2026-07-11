from typing import List, Sequence
from abc import ABC, abstractmethod
from datetime import datetime
from pydantic import BaseModel

from agent.schema import CanonicalLogEvent
from agent.detection.models import DetectionSignal
from agent.detection.config import DetectionSettings

class DetectionContext(BaseModel):
    settings: DetectionSettings
    analysis_started_at: datetime
    source_name: str = "default"

class BaseDetectionRule(ABC):
    rule_id: str
    version: str
    name: str
    family: str
    priority: int

    @abstractmethod
    def evaluate(
        self,
        events: Sequence[CanonicalLogEvent],
        context: DetectionContext,
    ) -> List[DetectionSignal]:
        pass
