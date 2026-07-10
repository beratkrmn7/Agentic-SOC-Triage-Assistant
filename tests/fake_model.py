from langchain_core.messages import AIMessage

class FakeTriageModel:
    """A fake LLM for testing without external services."""
    def __init__(self, predefined_response=None):
        self.predefined_response = predefined_response

    def invoke(self, messages):
        if self.predefined_response:
            return self.predefined_response
            
        tool_call = {
            "name": "submit_triage_result",
            "args": {
                "triage_verdict": "suspicious",
                "incident_type": "port_scan",
                "severity": "medium",
                "confidence_score": 0.9,
                "evidence": []
            },
            "id": "call_12345"
        }
        return AIMessage(content="", tool_calls=[tool_call])

    def bind_tools(self, tools):
        return self
