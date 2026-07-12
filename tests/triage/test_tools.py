import pytest
from agent.triage.tools import SearchLogsTool
from agent.triage.models import SafeEventView
from agent.triage.exceptions import TriageProviderError
from agent.triage.exceptions import ProviderMaxSearchCallsError

def test_search_logs_tool_truncation():
    events = [SafeEventView(event_id="EVT-1", timestamp="1", parser_name="p", source_name="s", sanitized_message_excerpt="long long long message")]
    tool = SearchLogsTool(incident_events=events, max_calls=3, max_query_chars=10, max_results=10)
    # It used to truncate, but now it raises TriageProviderError
    tool = SearchLogsTool(incident_events=[], max_calls=3, max_query_chars=10, max_results=10)
    
    with pytest.raises(TriageProviderError) as exc_info:
        tool("This is a very long query that should fail")
    assert "Search query exceeds maximum allowed characters" in str(exc_info.value)

def test_search_logs_tool_empty_query():
    tool = SearchLogsTool(incident_events=[], max_calls=3)
    result = tool("   ")
    assert tool.calls == 0
    assert len(result.matched_event_ids) == 0
    
def test_search_logs_tool_max_calls():
    tool = SearchLogsTool(incident_events=[], max_calls=1)
    tool("query1")
    with pytest.raises(ProviderMaxSearchCallsError):
        tool("query2")

def test_search_logs_tool_max_results():
    events = [
        SafeEventView(event_id="EVT-1", timestamp="1", parser_name="p", source_name="s", sanitized_message_excerpt="test 1"),
        SafeEventView(event_id="EVT-2", timestamp="2", parser_name="p", source_name="s", sanitized_message_excerpt="test 2")
    ]
    tool = SearchLogsTool(incident_events=events, max_calls=3, max_query_chars=100, max_results=1)
    
    result = tool("test")
    assert len(result.matched_event_ids) == 1
    assert result.truncated is True
