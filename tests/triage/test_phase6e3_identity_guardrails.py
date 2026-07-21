"""Phase 6E.3 focused tests: deterministic identity locking and firewall-only
verdict/severity caps across success, cache, and every fallback path."""

from __future__ import annotations

import datetime
from unittest.mock import patch

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from agent.application.analysis_service import AnalysisService
from agent.application.models import AnalysisResult
from agent.detection.models import (
    DetectionMetrics,
    DetectionResult,
    DetectionSignal,
    IncidentBundle,
)
from agent.nodes import evidence_validation_node, triage_node
from agent.persistence.database import Base
from agent.persistence.orm_models import IngestionJob
from agent.persistence.unit_of_work import UnitOfWork
from agent.schema import CanonicalLogEvent
from agent.triage.cache import InMemoryTriageCache
from agent.triage.exceptions import ProviderInvalidResponseError, ProviderUnavailableError
from agent.triage.input_builder import build_triage_input
from agent.triage.models import TriageIncidentContext, TriageSubmission
from agent.triage.provider import TriageProvider, TriageProviderRequest, TriageProviderResponse
from agent.triage.enums import TriageSeverity, TriageVerdict
from agent.triage.runner import TriageRunner


FIXED = datetime.datetime(2026, 7, 10, 6, 0, 0, tzinfo=datetime.timezone.utc)


def _rdp_incident() -> tuple[IncidentBundle, list[CanonicalLogEvent]]:
    events = [
        CanonicalLogEvent(
            event_id=f"rdp-{i}",
            timestamp=FIXED + datetime.timedelta(seconds=i),
            src_ip="203.0.113.9",
            dst_ip=f"198.51.100.{i + 1}",
            dst_port=3389,
            protocol="TCP",
            action="block",
            tcp_flags="SYN",
            parser_name="pf_firewall",
            parse_status="parsed",
            source_name="firewall.json",
            safe_message_excerpt=f"BLOCK TCP 203.0.113.9 -> 198.51.100.{i + 1}:3389 flags=S",
        )
        for i in range(2)
    ]
    incident = IncidentBundle(
        incident_id="INC-RDP",
        incident_type="rdp_probe",
        incident_family="service_probing",
        title="Detected RDP probe",
        severity="high",
        confidence=0.8,
        first_seen=events[0].timestamp,
        last_seen=events[-1].timestamp,
        primary_entity="203.0.113.9",
        target_entities=[e.dst_ip for e in events if e.dst_ip],
        signal_ids=["SIG-RDP"],
        event_ids=[e.event_id for e in events],
        context_event_ids=[],
        evidence=[],
        metrics={},
        mitre_techniques=["T1046"],
        merge_key="service_probing_1",
    )
    return incident, events


def _exposure_incident() -> tuple[IncidentBundle, list[CanonicalLogEvent]]:
    events = [
        CanonicalLogEvent(
            event_id="exposure-1",
            timestamp=FIXED,
            src_ip="8.8.8.8",
            dst_ip="203.0.113.50",
            translated_dst_ip="10.0.0.60",
            dst_port=6379,
            protocol="TCP",
            action="allow",
            tcp_flags="SYN,ACK",
            inbound_zone="wan",
            outbound_zone="lan",
            nat_type="dnat",
            packets=1,
            bytes=64,
            parser_name="pf_firewall",
            parse_status="parsed",
            source_name="firewall.json",
            safe_message_excerpt="ALLOW TCP 8.8.8.8 -> 10.0.0.60:6379 flags=SA",
        )
    ]
    incident = IncidentBundle(
        incident_id="INC-EXPOSURE",
        incident_type="dnat_sensitive_service_exposure",
        incident_family="firewall_exposure",
        title="Detected DNAT sensitive service exposure",
        severity="high",
        confidence=0.85,
        first_seen=events[0].timestamp,
        last_seen=events[0].timestamp,
        primary_entity="10.0.0.60",
        target_entities=["8.8.8.8"],
        signal_ids=["SIG-EXPOSURE"],
        event_ids=[events[0].event_id],
        context_event_ids=[],
        evidence=[],
        metrics={},
        mitre_techniques=[],
        merge_key="firewall_exposure_1",
    )
    return incident, events


def _validation_state(
    incident: IncidentBundle,
    events: list[CanonicalLogEvent],
    *,
    submitted_incident_type: str,
    verdict: str,
    severity: str = "high",
    confidence: float = 0.9,
    summary: str = "model summary",
) -> dict:
    context = TriageIncidentContext(incident=incident, events=events)
    evidence = {
        "event_id": events[0].event_id,
        "quote": events[0].safe_message_excerpt,
        "reason": "evidence",
        "source": "pf_firewall",
        "original_fields": {},
        "correlation_context": {},
    }
    triage_input = build_triage_input(context, [], [evidence])
    evidence_id = triage_input.candidate_evidence[0].evidence_id

    return {
        "incident_id": incident.incident_id,
        "incident": context.model_dump(mode="json"),
        "triage_submission": {
            "triage_verdict": verdict,
            "incident_type": submitted_incident_type,
            "severity": severity,
            "confidence_score": confidence,
            "summary": summary,
            "selected_evidence_ids": [evidence_id],
            "claims": [],
        },
        "triage_verdict": verdict,
        "incident_type": submitted_incident_type,
        "severity": severity,
        "confidence_score": confidence,
        "safe_triage_input": triage_input.model_dump(mode="json"),
        "review_reason": "none",
    }


def _triage_node_state(incident: IncidentBundle, events: list[CanonicalLogEvent]) -> dict:
    context = TriageIncidentContext(incident=incident, events=events)
    return {
        "incident_id": incident.incident_id,
        "incident": context.model_dump(mode="json"),
        "detected_signals": [],
        "candidate_evidence": [],
        "iteration_count": 0,
    }


# --- 7 & 8: identity lock at the evidence-validation stage ------------------


def test_provider_incident_type_cannot_rename_rdp_probe() -> None:
    incident, events = _rdp_incident()
    state = _validation_state(
        incident, events, submitted_incident_type="horizontal_scan", verdict="suspicious_activity"
    )

    result = evidence_validation_node(state)

    assert result["incident_type"] == "rdp_probe"
    assert result["triage_submission"]["incident_type"] == "rdp_probe"


def test_provider_incident_type_cannot_rename_firewall_exposure() -> None:
    incident, events = _exposure_incident()
    state = _validation_state(
        incident,
        events,
        submitted_incident_type="database_compromise",
        verdict="suspicious_activity",
    )

    result = evidence_validation_node(state)

    assert result["incident_type"] == "dnat_sensitive_service_exposure"
    assert result["triage_submission"]["incident_type"] == "dnat_sensitive_service_exposure"
    assert "deterministic_incident_type_locked" in result["policy_adjustments"]


# --- 11 & 12: firewall-only verdict/severity caps ---------------------------


def test_firewall_only_confirmed_incident_capped_to_suspicious_activity() -> None:
    incident, events = _exposure_incident()
    state = _validation_state(
        incident,
        events,
        submitted_incident_type="dnat_sensitive_service_exposure",
        verdict="confirmed_incident",
        severity="high",
    )

    result = evidence_validation_node(state)

    assert result["triage_verdict"] == "suspicious_activity"
    assert result["triage_submission"]["triage_verdict"] == "suspicious_activity"
    assert "firewall_only_confirmed_verdict_capped" in result["policy_adjustments"]
    assert "application_success_not_proven" in result["policy_adjustments"]
    assert "compromise_not_proven" in result["policy_adjustments"]


def test_firewall_only_severity_above_deterministic_is_capped() -> None:
    incident, events = _exposure_incident()  # deterministic severity == "high"
    state = _validation_state(
        incident,
        events,
        submitted_incident_type="dnat_sensitive_service_exposure",
        verdict="suspicious_activity",
        severity="critical",
    )

    result = evidence_validation_node(state)

    assert result["severity"] == "high"
    assert result["triage_submission"]["severity"] == "high"
    assert "exposure_severity_capped" in result["policy_adjustments"]


def test_firewall_exposure_severity_may_stay_high_when_not_escalated() -> None:
    incident, events = _exposure_incident()
    state = _validation_state(
        incident,
        events,
        submitted_incident_type="dnat_sensitive_service_exposure",
        verdict="suspicious_activity",
        severity="medium",
    )

    result = evidence_validation_node(state)

    # A same-or-lower severity is not an escalation; no cap applied.
    assert result.get("severity", "medium") == "medium" or "severity" not in result
    assert "exposure_severity_capped" not in result.get("policy_adjustments", [])


# --- 9: fallback identity preservation across every failure mode -----------


class _RenamingProvider(TriageProvider):
    def invoke(self, request: TriageProviderRequest) -> TriageProviderResponse:
        return TriageProviderResponse(
            submission=TriageSubmission(
                triage_verdict=TriageVerdict.SUSPICIOUS_ACTIVITY,
                incident_type="database_compromise",
                severity=TriageSeverity.HIGH,
                confidence_score=0.7,
                summary="The database was compromised.",
            ),
            prompt_tokens=5,
            completion_tokens=5,
        )


class _UnavailableProvider(TriageProvider):
    def invoke(self, request: TriageProviderRequest) -> TriageProviderResponse:
        raise ProviderUnavailableError("provider is down")


class _AlwaysInvalidProvider(TriageProvider):
    def invoke(self, request: TriageProviderRequest) -> TriageProviderResponse:
        raise ProviderInvalidResponseError("bad output")


def test_provider_unavailable_fallback_preserves_deterministic_identity() -> None:
    incident, events = _exposure_incident()
    state = _triage_node_state(incident, events)
    fake_runner = TriageRunner(provider=_UnavailableProvider())

    with patch("agent.nodes.get_triage_runner", return_value=fake_runner):
        result = triage_node(state)

    assert result["incident_type"] == "dnat_sensitive_service_exposure"
    assert result["incident_type"] != "other"
    assert result["triage_verdict"] == "needs_review"


def test_invalid_output_fallback_preserves_deterministic_identity() -> None:
    incident, events = _rdp_incident()
    state = _triage_node_state(incident, events)
    fake_runner = TriageRunner(provider=_AlwaysInvalidProvider())

    with patch.object(fake_runner.settings, "llm_invalid_response_retries", 0):
        with patch("agent.nodes.get_triage_runner", return_value=fake_runner):
            result = triage_node(state)

    assert result["incident_type"] == "rdp_probe"
    assert result["incident_type"] != "other"


def test_prompt_budget_fallback_preserves_deterministic_identity() -> None:
    incident, events = _exposure_incident()
    state = _triage_node_state(incident, events)
    fake_runner = TriageRunner(provider=_UnavailableProvider())

    with patch.object(fake_runner.settings, "max_prompt_tokens", 1):
        with patch("agent.nodes.get_triage_runner", return_value=fake_runner):
            result = triage_node(state)

    assert result["incident_type"] == "dnat_sensitive_service_exposure"
    assert result["incident_type"] != "other"


def test_provider_timeout_fallback_preserves_deterministic_identity() -> None:
    incident, events = _rdp_incident()
    state = _triage_node_state(incident, events)
    fake_runner = TriageRunner(provider=_UnavailableProvider())

    with patch.object(fake_runner.settings, "triage_timeout_seconds", 0.0):
        with patch("agent.nodes.get_triage_runner", return_value=fake_runner):
            result = triage_node(state)

    assert result["incident_type"] == "rdp_probe"
    assert result["incident_type"] != "other"


# --- 10: cached provider result gets the same identity normalization -------


def test_cached_provider_result_receives_same_identity_normalization() -> None:
    incident, events = _exposure_incident()
    fake_runner = TriageRunner(provider=_RenamingProvider(), cache=InMemoryTriageCache())

    with patch("agent.nodes.get_triage_runner", return_value=fake_runner):
        first = triage_node(_triage_node_state(incident, events))
        second = triage_node(_triage_node_state(incident, events))

    assert first["incident_type"] == "dnat_sensitive_service_exposure"
    assert second["incident_type"] == "dnat_sensitive_service_exposure"
    assert second["triage_metrics"]["cache_hit"] is True


# --- 27: fresh and idempotently hydrated exposure results agree ------------


@pytest.fixture
def session_factory():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    factory = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    yield factory
    engine.dispose()


def test_fresh_and_hydrated_exposure_result_preserve_identity_and_verdict(
    session_factory,
) -> None:
    incident, events = _exposure_incident()
    # Mirror what Phase 6E.1 routing stashes into Incident.metrics so
    # hydration RESTORES the route instead of recomputing it.
    incident = incident.model_copy(
        update={
            "metrics": {
                "triage_route": "individual_triage",
                "routing_reason": "high_value_rule:dnat_sensitive_service_exposure",
                "triage_origin": "llm",
                "llm_invoked": True,
            }
        }
    )
    signal = DetectionSignal(
        signal_id="SIG-EXPOSURE",
        rule_id="dnat_sensitive_service_exposure",
        rule_version="1.0.0",
        rule_name="DNAT Sensitive Service Exposure",
        signal_type="dnat_sensitive_service_exposure",
        signal_family="firewall_exposure",
        severity="high",
        confidence=0.85,
        first_seen=incident.first_seen,
        last_seen=incident.last_seen,
        event_ids=incident.event_ids,
        primary_entity=incident.primary_entity,
        target_entities=incident.target_entities,
        metrics={},
        evidence=[],
        mitre_techniques=[],
        tags=[],
    )
    event_map = {e.event_id: e for e in events}

    # The capped state that evidence_validation_node would have produced
    # after the provider tried to rename/escalate the incident.
    inc_state = {
        "incident_id": incident.incident_id,
        "triage_verdict": "suspicious_activity",
        "incident_type": "dnat_sensitive_service_exposure",
        "severity": "high",
        "confidence_score": 0.7,
        "iteration_count": 1,
        "triage_route": "individual_triage",
        "routing_reason": "high_value_rule:dnat_sensitive_service_exposure",
        "triage_origin": "llm",
        "llm_invoked": True,
        "detection_confidence": incident.confidence,
        "policy_adjustments": [
            "deterministic_incident_type_locked",
            "firewall_only_confirmed_verdict_capped",
        ],
        "final_report": "Deterministic exposure report text.",
        "safe_triage_input": {},
        "validated_evidence": [],
        "rejected_evidence": [],
    }

    fresh_result = AnalysisResult(
        source_name="test",
        detection_result=DetectionResult(
            signals=[signal],
            incidents=[incident],
            suppressed_signals=[],
            uncorrelated_event_ids=[],
            warnings=[],
            metrics=DetectionMetrics(signal_count=1, incident_count=1, duration_ms=1.0),
        ),
        event_map=event_map,
        signal_map={signal.signal_id: signal},
        incidents=[inc_state],
    )

    with session_factory() as session:
        session.add(
            IngestionJob(
                id="job-exposure-1",
                idempotency_key="idem-exposure-1",
                source_name="test",
                status="processing",
            )
        )
        session.commit()

    fresh_result.job_id = "job-exposure-1"
    persist_svc = AnalysisService(uow=UnitOfWork(session_factory=session_factory))
    persist_svc._persist_analysis(fresh_result, run_triage=True)

    hydrate_svc = AnalysisService(uow=UnitOfWork(session_factory=session_factory))
    hydrated_result = hydrate_svc.analyze_file(
        "nonexistent-file-not-touched.jsonl",
        run_triage=True,
        idempotency_key="idem-exposure-1",
    )

    assert hydrated_result.reused is True
    hydrated_state = hydrated_result.incidents[0]
    assert hydrated_state["incident_id"] == incident.incident_id
    assert hydrated_state["incident_type"] == "dnat_sensitive_service_exposure"
    assert hydrated_state["triage_verdict"] == "suspicious_activity"
    assert hydrated_state["severity"] == "high"
    assert hydrated_state["triage_route"] == "individual_triage"
    assert set(hydrated_state["policy_adjustments"]) == set(
        inc_state["policy_adjustments"]
    )
