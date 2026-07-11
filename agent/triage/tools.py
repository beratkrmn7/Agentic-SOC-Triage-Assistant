from typing import List
from agent.triage.models import SafeEventView, SearchLogsResult
from agent.triage.exceptions import ProviderMaxSearchCallsError

class SearchLogsTool:
    def __init__(self, incident_events: List[SafeEventView], max_calls: int = 3, max_query_chars: int = 100, max_results: int = 10):
        self.incident_events = incident_events
        self.max_calls = max_calls
        self.max_query_chars = max_query_chars
        self.max_results = max_results
        self.calls = 0
        
    def __call__(self, query: str) -> SearchLogsResult:
        if not query or not str(query).strip():
            return SearchLogsResult(query="", matched_event_ids=[], results=[], truncated=False)
            
        self.calls += 1
        if self.calls > self.max_calls:
            raise ProviderMaxSearchCallsError(f"Maximum search calls ({self.max_calls}) reached")
            
        if len(query) > self.max_query_chars:
            query = query[:self.max_query_chars]
            
        q_lower = query.lower()
        matched = []
        
        # Only search within the scope of limited context events
        for event in self.incident_events:
            # We enforce structured field allowlist implicitly by dumping SafeEventView,
            # which only contains the Safe fields, NOT the full raw log.
            event_repr = event.model_dump_json().lower()
            if q_lower in event_repr:
                matched.append(event)
                
        truncated = False
        if len(matched) > self.max_results:
            matched = matched[:self.max_results]
            truncated = True
            
        return SearchLogsResult(
            query=query,
            matched_event_ids=[e.event_id for e in matched],
            results=matched,
            truncated=truncated
        )
