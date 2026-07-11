from agent.triage.runner import TriageRunner
from agent.triage.provider import TriageProvider, TriageProviderResponse, TriageProviderRequest
from agent.triage.exceptions import ProviderTimeoutError
from agent.triage.enums import ReviewReason, TriageVerdict, TriageSeverity
from agent.triage.models import TriageSubmission
from agent.models import IncidentBundle
import time

class SlowFakeProvider(TriageProvider):
    def invoke(self, request: TriageProviderRequest) -> TriageProviderResponse:
        time.sleep(0.2)
        return TriageProviderResponse(
            submission=TriageSubmission(
                triage_verdict=TriageVerdict.FALSE_POSITIVE,
                incident_type="test",
                severity=TriageSeverity.NONE,
                confidence_score=0.9,
                summary="Done"
            ),
            prompt_tokens=10,
            completion_tokens=10
        )

class ExceptionFakeProvider(TriageProvider):
    def invoke(self, request: TriageProviderRequest) -> TriageProviderResponse:
        raise ProviderTimeoutError("Timed out from groq")

def test_triage_runner_global_timeout():
    provider = SlowFakeProvider()
    runner = TriageRunner(provider=provider)
    runner.settings.triage_timeout_seconds = 0.1 # Very short timeout
    
    bundle = IncidentBundle(
        incident_id="INC-1",
        incident_type_hint="test",
        source_ips=[],
        destination_ips=[],
        destination_ports=[],
        event_ids=[],
        events=[],
        context_events=[]
    )
    
    state = {"incident_id": "INC-1", "detected_signals": [], "candidate_evidence": []}
    
    result = runner.run(state, bundle)
    assert result.submission is not None
    assert result.submission.triage_verdict == TriageVerdict.NEEDS_REVIEW
    assert result.review_reason == ReviewReason.PROVIDER_TIMEOUT
    assert result.metrics.fallback_used is True

def test_triage_runner_provider_timeout_exception():
    provider = ExceptionFakeProvider()
    runner = TriageRunner(provider=provider)
    
    bundle = IncidentBundle(
        incident_id="INC-1",
        incident_type_hint="test",
        source_ips=[],
        destination_ips=[],
        destination_ports=[],
        event_ids=[],
        events=[],
        context_events=[]
    )
    
    state = {"incident_id": "INC-1", "detected_signals": [], "candidate_evidence": []}
    
    result = runner.run(state, bundle)
    assert result.submission is not None
    assert result.submission.triage_verdict == TriageVerdict.NEEDS_REVIEW
    assert result.review_reason == ReviewReason.PROVIDER_TIMEOUT
    assert result.metrics.fallback_used is True
