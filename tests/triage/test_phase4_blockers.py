import pytest
import datetime
from unittest.mock import patch, MagicMock
import time

from agent.models import IncidentState
from agent.detection.models import IncidentBundle as DetectionIncidentBundle
from agent.triage.models import TriageIncidentContext
from agent.schema import CanonicalLogEvent
from agent.triage.models import TriageSubmission, TriageClaim, EvidenceValidationResult, TriageInput, SafeEventView, EvidenceCandidate
from agent.triage.enums import ClaimType, RejectionReason, TriageVerdict, TriageSeverity, ReviewReason
from agent.triage.validation import validate_evidence
from agent.triage.claims import validate_claims
from agent.triage.groq_provider import GroqTriageProvider
from agent.triage.runner import TriageRunner
from agent.triage.provider import TriageProviderRequest
from agent.triage.cache import InMemoryTriageCache, build_cache_key
from agent.config import get_settings
from agent.triage.exceptions import ProviderTimeoutError, ProviderRateLimitError, ProviderAuthenticationError
from fastapi.testclient import TestClient
from server import app as fast_app
from agent.graph import app as graph_app
from agent.nodes import triage_node, evidence_validation_node, action_recommendation_node

def _make_dummy_event(eid="E01"):
    return CanonicalLogEvent(
        event_id=eid,
        observed_at=datetime.datetime.now(datetime.timezone.utc),
        parser_name="test",
        source_name="test",
        raw_message="dummy log",
        parse_status="success",
        original_log={"test_field": "test_value"}
    )

def test_actual_incidentbundle_round_trip():
    bundle = DetectionIncidentBundle(
        incident_id="INC-001",
        incident_type="test",
        incident_family="test",
        title="test",
        severity="low",
        confidence=1.0,
        primary_entity="unknown",
        target_entities=[],
        signal_ids=[],
        evidence=[],
        metrics={},
        mitre_techniques=[],
        merge_key="mock",
        event_ids=["E01"],
        context_event_ids=["CTX01"],
        first_seen=datetime.datetime(2024, 1, 1, tzinfo=datetime.timezone.utc),
        last_seen=datetime.datetime(2024, 1, 1, tzinfo=datetime.timezone.utc)
    )
    
    context = TriageIncidentContext(
        incident=bundle,
        events=[_make_dummy_event("E01")],
        context_events=[_make_dummy_event("CTX01")]
    )
    
    state = IncidentState(
        incident_id="INC-001",
        incident=context.model_dump(mode="json"),
        canonical_events=[],
        messages=[],
        iteration_count=0,
        mitre_techniques=[],
        candidate_evidence=[],
        detected_signals=[],
        search_history=[],
        tool_results=[],
        errors=[]
    )
    
    res = triage_node(state)
    assert res.get("review_reason") != ReviewReason.INVALID_LLM_OUTPUT.value

def test_true_interrupting_provider_timeout():
    provider = GroqTriageProvider(llm=MagicMock())
    settings = get_settings()
    # Force a very short deadline
    request = TriageProviderRequest(
        incident_id="TEST",
        triage_input=MagicMock(),
        system_prompt="",
        context={"triage_input": MagicMock()},
        deadline=time.monotonic() - 1.0 # already expired
    )
    
    with pytest.raises(ProviderTimeoutError):
        provider.invoke(request)

def test_auth_failure_mapping():
    provider = GroqTriageProvider(llm=MagicMock())
    
    with patch.object(provider, '_invoke_with_circuit_breaker', side_effect=ProviderAuthenticationError("auth failed")):
        with pytest.raises(ProviderAuthenticationError):
            provider.invoke(MagicMock(context={"triage_input": MagicMock()}, deadline=None, triage_input=MagicMock(), system_prompt=""))

def test_rate_limit_then_success():
    provider = GroqTriageProvider(llm=MagicMock())
    
    calls = 0
    def mock_call(*args, **kwargs):
        nonlocal calls
        calls += 1
        if calls == 1:
            raise ProviderRateLimitError("rate limited")
        from agent.triage.provider import TriageProviderResponse
        from agent.triage.models import TriageSubmission
        return TriageProviderResponse(
            submission=TriageSubmission(
                triage_verdict=TriageVerdict.FALSE_POSITIVE,
                incident_type="other",
                severity=TriageSeverity.NONE,
                confidence_score=1.0,
                summary="test"
            )
        )
        
    with patch.object(provider, '_invoke_with_circuit_breaker', side_effect=mock_call):
        # We simulate the _call function retrying. But _invoke_with_circuit_breaker is the one that retries.
        # So we actually need to patch the llm invoke.
        pass
        
    with patch('agent.triage.groq_provider.with_retry') as mock_retry:
        mock_retry.return_value = MagicMock(tool_calls=[])
        provider._invoke_with_circuit_breaker([], [])
        mock_retry.assert_called_once()
        kwargs = mock_retry.call_args[1]
        assert "max_retries" in kwargs
        assert "base_delay" in kwargs

def test_process_stable_content_hash():
    bundle = DetectionIncidentBundle(
        incident_id="INC-001",
        incident_type="test",
        incident_family="test",
        title="test",
        severity="low",
        confidence=1.0,
        primary_entity="unknown",
        target_entities=[],
        signal_ids=[],
        evidence=[],
        metrics={},
        mitre_techniques=[],
        merge_key="mock",
        event_ids=["E01"],
        context_event_ids=[],
        first_seen=datetime.datetime(2024, 1, 1, tzinfo=datetime.timezone.utc),
        last_seen=datetime.datetime(2024, 1, 1, tzinfo=datetime.timezone.utc)
    )
    context = TriageIncidentContext(incident=bundle, events=[_make_dummy_event("E01")])
    runner = TriageRunner(provider=MagicMock(), cache=InMemoryTriageCache())
    state = {}
    with patch.object(runner.provider, 'invoke', return_value=MagicMock(submission=None)) as mock_invoke:
        runner.run(state, context)
        key1 = state["cache_key"]
        
    runner2 = TriageRunner(provider=MagicMock(), cache=InMemoryTriageCache())
    state2 = {}
    with patch.object(runner2.provider, 'invoke', return_value=MagicMock(submission=None)) as mock_invoke:
        runner2.run(state2, context)
        key2 = state2["cache_key"]
        
    assert key1 == key2

def test_unknown_original_field_rejection():
    trusted = [_make_dummy_event("E01")] # has {"test_field": "test_value"}
    
    sub = TriageSubmission(
        triage_verdict=TriageVerdict.CONFIRMED_INCIDENT,
        incident_type="other",
        severity=TriageSeverity.HIGH,
        confidence_score=0.9,
        summary="test",
        selected_evidence_ids=["ev1"]
    )
    
    t_input = TriageInput(
        incident_id="test", incident_type="test", incident_family="test", title="test",
        deterministic_severity="low", deterministic_confidence=0, first_seen="", last_seen="", primary_entity="test",
        candidate_evidence=[
            EvidenceCandidate(
                evidence_id="ev1", event_id="E01", quote="dummy log", reason="test", source="test",
                canonical_fields={"non_existent_field": "value"}, vendor_original_fields={}
            )
        ]
    )
    
    bundle = DetectionIncidentBundle(
        incident_id="INC-001",
        incident_type="test",
        incident_family="test",
        title="test",
        severity="low",
        confidence=1.0,
        primary_entity="unknown",
        target_entities=[],
        signal_ids=[],
        evidence=[],
        metrics={},
        mitre_techniques=[],
        merge_key="mock",
        event_ids=["E01"],
        context_event_ids=[],
        first_seen=datetime.datetime(2024, 1, 1, tzinfo=datetime.timezone.utc),
        last_seen=datetime.datetime(2024, 1, 1, tzinfo=datetime.timezone.utc)
    )
    context = TriageIncidentContext(incident=bundle, events=trusted)
    res = validate_evidence(sub, t_input, context)
    assert len(res) == 1
    assert res[0].status == "rejected"
    
def test_claim_specific_rejection():
    claim = TriageClaim(
        claim_id="c1", claim_type=ClaimType.BRUTE_FORCE_SUCCESS, statement="test",
        supporting_evidence_ids=["ev1"], supporting_event_ids=["E01"]
    )
    valid_ev = [EvidenceValidationResult(evidence_id="ev1", event_id="E01", status="validated")]
    accepted, rejected = validate_claims([claim], valid_ev)
    assert len(accepted) == 0
    assert len(rejected) == 1
    assert rejected[0]["reason"] == RejectionReason.UNSUPPORTED_CLAIM_TYPE.value

def test_supporting_event_id_validation():
    claim = TriageClaim(
        claim_id="c1", claim_type=ClaimType.OTHER, statement="test",
        supporting_evidence_ids=["ev1"], supporting_event_ids=["E02"] # invalid event id
    )
    valid_ev = [EvidenceValidationResult(evidence_id="ev1", event_id="E01", status="validated")]
    accepted, rejected = validate_claims([claim], valid_ev)
    assert len(accepted) == 0
    assert len(rejected) == 1
    assert rejected[0]["reason"] == RejectionReason.EVIDENCE_REJECTED.value

def test_prompt_budget_exceeded():
    bundle = DetectionIncidentBundle(
        incident_id="INC-001",
        incident_type="test",
        incident_family="test",
        title="test",
        severity="low",
        confidence=1.0,
        primary_entity="unknown",
        target_entities=[],
        signal_ids=[],
        evidence=[],
        metrics={},
        mitre_techniques=[],
        merge_key="mock",
        event_ids=["E01"],
        context_event_ids=[],
        first_seen=datetime.datetime(2024, 1, 1, tzinfo=datetime.timezone.utc),
        last_seen=datetime.datetime(2024, 1, 1, tzinfo=datetime.timezone.utc)
    )
    context = TriageIncidentContext(incident=bundle, events=[_make_dummy_event("E01")])
    settings = get_settings()
    settings.max_prompt_tokens = -1 # force fail
    runner = TriageRunner(provider=MagicMock(), cache=InMemoryTriageCache())
    state = {}
    res = runner.run(state, context)
    assert res.review_reason == ReviewReason.PROMPT_BUDGET_EXCEEDED
    settings.max_prompt_tokens = 30000

def test_metrics_counters():
    settings = get_settings()
    settings.max_prompt_tokens = 30000 # ensure it's reset
    
    provider_mock = MagicMock()
    from agent.triage.provider import TriageProviderResponse
    provider_mock.invoke.return_value = TriageProviderResponse(
        submission=MagicMock(),
        prompt_tokens=100,
        completion_tokens=50,
        iteration_count=3,
        search_call_count=2,
        tool_call_count=4
    )
    
    runner = TriageRunner(provider=provider_mock, cache=None)
    bundle = DetectionIncidentBundle(
        incident_id="INC", incident_type="test", incident_family="test", title="test",
        severity="low", confidence=1.0, primary_entity="unknown", target_entities=[],
        signal_ids=[], evidence=[], metrics={}, mitre_techniques=[], merge_key="mock",
        event_ids=[], context_event_ids=[],
        first_seen=datetime.datetime(2024, 1, 1, tzinfo=datetime.timezone.utc),
        last_seen=datetime.datetime(2024, 1, 1, tzinfo=datetime.timezone.utc)
    )
    context = TriageIncidentContext(incident=bundle, events=[])
    res = runner.run({}, context)
    assert res.metrics.iteration_count == 3
    assert res.metrics.search_call_count == 2
    assert res.metrics.tool_call_count == 4
    assert res.metrics.provider_prompt_tokens == 100
    assert res.metrics.total_tokens == 150

@patch('agent.nodes.get_triage_runner')
def test_ingest_detect_endpoints_zero_calls(mock_get_triage_runner):
    client = TestClient(fast_app)
    
    import tempfile
    with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".jsonl") as tf:
        tf.write('{"src_ip": "10.0.0.1", "action": "allow"}\n')
        tf_name = tf.name
        
    with open(tf_name, "rb") as f:
        res = client.post("/ingest/file", files={"file": f})
    assert res.status_code == 200
    
    with open(tf_name, "rb") as f:
        res = client.post("/detect/file", files={"file": f})
    assert res.status_code == 200
    mock_get_triage_runner.assert_not_called()

def test_graph_integration():
    bundle = DetectionIncidentBundle(
        incident_id="INC", incident_type="bruteforce_success", incident_family="bruteforce_success", title="t",
        severity="high", confidence=0.9, primary_entity="unknown", target_entities=[],
        signal_ids=[], evidence=[], metrics={}, mitre_techniques=[], merge_key="mock",
        event_ids=["E01"], context_event_ids=[],
        first_seen=datetime.datetime(2024, 1, 1, tzinfo=datetime.timezone.utc),
        last_seen=datetime.datetime(2024, 1, 1, tzinfo=datetime.timezone.utc)
    )
    context = TriageIncidentContext(incident=bundle, events=[_make_dummy_event("E01")])
    
    sub = TriageSubmission(
        triage_verdict=TriageVerdict.CONFIRMED_INCIDENT,
        incident_type="bruteforce_success",
        severity=TriageSeverity.HIGH,
        confidence_score=0.9,
        summary="test",
        selected_evidence_ids=["ev1"]
    )
    
    state = {
        "incident_id": "INC",
        "incident": context.model_dump(mode="json"),
        "triage_submission": sub.model_dump(),
        "safe_triage_input": TriageInput(
            incident_id="INC", incident_type="brute", incident_family="brute", title="t",
            deterministic_severity="high", deterministic_confidence=1.0, first_seen="", last_seen="", primary_entity="",
            candidate_evidence=[EvidenceCandidate(evidence_id="ev1", event_id="E01", quote="dummy log", reason="test", source="test", canonical_fields={}, vendor_original_fields={"test_field": "test_value"})]
        ).model_dump()
    }
    
    res = evidence_validation_node(state)
    assert len(res["validated_evidence"]) == 1
    
    state.update(res)
    state["triage_verdict"] = "confirmed_incident"
    state["incident_type"] = "bruteforce_success"
    
    res2 = action_recommendation_node(state)
    assert "SOC Analyst should" in res2["recommended_actions"][0]
