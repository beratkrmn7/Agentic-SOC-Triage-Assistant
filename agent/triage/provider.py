from typing import Protocol, Any, Dict, Optional
from agent.triage.models import TriageSubmission, TriageInput

class TriageProviderRequest:
    def __init__(
        self, 
        incident_id: str, 
        triage_input: TriageInput, 
        system_prompt: str, 
        context: Optional[Dict[str, Any]] = None,
        deadline: Optional[float] = None
    ):
        self.incident_id = incident_id
        self.triage_input = triage_input
        self.system_prompt = system_prompt
        self.context = context or {}
        self.deadline = deadline

class TriageProviderResponse:
    def __init__(
        self,
        submission: Optional[TriageSubmission] = None,
        search_call: Optional[str] = None,
        raw_output: Optional[str] = None,
        prompt_tokens: int = 0,
        completion_tokens: int = 0,
        iteration_count: int = 1,
        search_call_count: int = 0,
        tool_call_count: int = 0,
        retry_count: int = 0
    ):
        self.submission = submission
        self.search_call = search_call
        self.raw_output = raw_output
        self.prompt_tokens = prompt_tokens
        self.completion_tokens = completion_tokens
        self.iteration_count = iteration_count
        self.search_call_count = search_call_count
        self.tool_call_count = tool_call_count
        self.retry_count = retry_count

class TriageProvider(Protocol):
    def invoke(self, request: TriageProviderRequest) -> TriageProviderResponse:
        ...
