"""Phase 6E.3 focused tests: SafeEventView enrichment, flow_direction,
signal_views, and deterministic exposure/scan fact derivation."""

from __future__ import annotations

import datetime

from agent.detection.detectors import register_default_rules
from agent.detection.detectors.extended_service_probe import SmbProbeRule
from agent.detection.registry import default_registry
from agent.schema import CanonicalLogEvent
from agent.triage.guardrails import (
    FirewallExposureFacts,
    ScanProbeFacts,
    classify_incident,
    derive_incident_facts,
)
from agent.triage.input_builder import _build_safe_event, build_triage_input
from agent.triage.models import TriageIncidentContext, TriageSignalView
from agent.triage.network_context import derive_flow_direction
from agent.detection.models import IncidentBundle


FIXED = datetime.datetime(2026, 7, 10, 6, 0, 0, tzinfo=datetime.timezone.utc)


def _event(event_id: str, **overrides) -> CanonicalLogEvent:
    values = dict(
        event_id=event_id,
        timestamp=FIXED,
        src_ip="8.8.8.8",
        dst_ip="203.0.113.50",
        dst_port=6379,
        protocol="TCP",
        action="allow",
        tcp_flags="SYN,ACK",
        parser_name="pf_firewall",
        parse_status="parsed",
        source_name="firewall.json",
        safe_message_excerpt="ALLOW TCP 8.8.8.8 -> 10.0.0.60:6379 flags=SA",
        parser_metadata={"raw": "should never leak", "secret_token": "abc123"},
    )
    values.update(overrides)
    return CanonicalLogEvent(**values)


def _exposure_incident(events: list[CanonicalLogEvent], **overrides) -> IncidentBundle:
    values = dict(
        incident_id="INC-EXPOSURE",
        incident_type="dnat_sensitive_service_exposure",
        incident_family="firewall_exposure",
        title="Detected DNAT sensitive service exposure",
        severity="high",
        confidence=0.85,
        first_seen=events[0].timestamp,
        last_seen=events[-1].timestamp,
        primary_entity="10.0.0.60",
        target_entities=["8.8.8.8"],
        signal_ids=["SIG-EXPOSURE"],
        event_ids=[e.event_id for e in events],
        context_event_ids=[],
        evidence=[],
        metrics={},
        mitre_techniques=[],
        merge_key="firewall_exposure_1",
    )
    values.update(overrides)
    return IncidentBundle(**values)


# --- 1 & 2: SafeEventView enrichment and safety ----------------------------


def test_safe_event_view_includes_packet_byte_duration_zone_and_nat_fields() -> None:
    event = _event(
        "evt-1",
        packets=6,
        bytes=4096,
        duration_ms=1500,
        inbound_zone="wan",
        outbound_zone="lan",
        inbound_interface="eth0",
        outbound_interface="eth1",
        nat_type="dnat",
        translated_dst_ip="10.0.0.60",
        translated_dst_port=6379,
    )
    safe_view = _build_safe_event(event)

    assert safe_view.packets == 6
    assert safe_view.bytes == 4096
    assert safe_view.duration_ms == 1500
    assert safe_view.inbound_zone == "wan"
    assert safe_view.outbound_zone == "lan"
    assert safe_view.inbound_interface == "eth0"
    assert safe_view.outbound_interface == "eth1"
    assert safe_view.nat_type == "dnat"
    assert safe_view.translated_dst_ip == "10.0.0.60"
    assert safe_view.translated_dst_port == 6379
    assert safe_view.flow_direction in {"inbound", "outbound", "lateral", "unknown"}


def test_safe_event_view_never_exposes_raw_records_or_parser_metadata() -> None:
    event = _event("evt-1")
    safe_view = _build_safe_event(event)
    dumped = safe_view.model_dump()

    assert "parser_metadata" not in dumped
    assert "raw_record_hash" not in dumped
    assert "source_line" not in dumped
    for value in dumped.values():
        assert "secret_token" not in str(value)
        assert "should never leak" not in str(value)


# --- 3 & 4: flow_direction ---------------------------------------------------


def test_flow_direction_inbound_for_explicit_wan_to_lan() -> None:
    event = _event("evt-1", inbound_zone="wan", outbound_zone="lan")
    assert derive_flow_direction(event) == "inbound"


def test_flow_direction_outbound_for_private_to_public_without_zone_conflict() -> None:
    event = _event(
        "evt-1",
        src_ip="10.0.0.5",
        dst_ip="8.8.8.8",
        inbound_zone=None,
        outbound_zone=None,
    )
    assert derive_flow_direction(event) == "outbound"


# --- 5 & 6: TriageInput signal_views -----------------------------------------


def test_triage_input_has_typed_metadata_for_every_attached_signal() -> None:
    events = [_event("evt-1")]
    incident = _exposure_incident(
        events, signal_ids=["SIG-ANCHOR", "SIG-ABSORBED"]
    )
    context = TriageIncidentContext(incident=incident, events=events)
    detected_signals = [
        {
            "signal_id": "SIG-ANCHOR",
            "rule_id": "dnat_sensitive_service_exposure",
            "rule_name": "DNAT Sensitive Service Exposure",
            "signal_type": "dnat_sensitive_service_exposure",
            "signal_family": "firewall_exposure",
            "severity": "high",
            "confidence_score": 0.85,
            "mitre_techniques": [],
            "matched_event_ids": ["evt-1"],
        },
        {
            "signal_id": "SIG-ABSORBED",
            "rule_id": "network_scan_horizontal",
            "rule_name": "Horizontal Port Scan",
            "signal_type": "horizontal_scan",
            "signal_family": "network_scanning",
            "severity": "medium",
            "confidence_score": 0.6,
            "mitre_techniques": ["T1046"],
            "matched_event_ids": ["evt-1", "not-in-incident"],
        },
    ]

    triage_input = build_triage_input(context, detected_signals, [])

    assert len(triage_input.signal_views) == 2
    by_id = {view.signal_id: view for view in triage_input.signal_views}
    assert by_id["SIG-ANCHOR"].signal_family == "firewall_exposure"
    assert by_id["SIG-ABSORBED"].signal_family == "network_scanning"
    # Matched event IDs are bounded to incident scope.
    assert by_id["SIG-ABSORBED"].matched_event_ids == ["evt-1"]


def test_signal_views_are_deterministic_bounded_and_duplicate_free() -> None:
    events = [_event("evt-1")]
    incident = _exposure_incident(events, signal_ids=["SIG-A", "SIG-A", "SIG-B"])
    context = TriageIncidentContext(incident=incident, events=events)
    detected_signals = [
        {
            "signal_id": "SIG-B",
            "rule_id": "rule-b",
            "rule_name": "Rule B",
            "signal_type": "type-b",
            "signal_family": "family-b",
            "severity": "low",
            "confidence_score": 0.4,
            "matched_event_ids": ["evt-1"],
        },
        {
            "signal_id": "SIG-A",
            "rule_id": "rule-a",
            "rule_name": "Rule A",
            "signal_type": "type-a",
            "signal_family": "family-a",
            "severity": "high",
            "confidence_score": 0.9,
            "matched_event_ids": ["evt-1"],
        },
        {
            "signal_id": "SIG-A",  # duplicate entry must not duplicate the view
            "rule_id": "rule-a",
            "rule_name": "Rule A",
            "signal_type": "type-a",
            "signal_family": "family-a",
            "severity": "high",
            "confidence_score": 0.9,
            "matched_event_ids": ["evt-1"],
        },
    ]

    triage_input = build_triage_input(context, detected_signals, [])

    ids = [view.signal_id for view in triage_input.signal_views]
    assert ids == ["SIG-A", "SIG-B"]  # sorted, duplicate-free
    assert len(ids) == len(set(ids))


# --- 13-16: exposure fact semantics ------------------------------------------


def test_single_packet_dnat_allow_is_policy_exposure_without_proof() -> None:
    events = [_event("evt-1", packets=1, bytes=64)]
    incident = _exposure_incident(events)
    context = TriageIncidentContext(incident=incident, events=events)

    facts = derive_incident_facts(context, [])

    assert isinstance(facts, FirewallExposureFacts)
    assert facts.policy_allow_observed is True
    assert facts.single_packet_allowed_event_count == 1
    assert facts.multi_packet_allowed_event_count == 0
    assert facts.transport_activity_observed is False
    assert facts.application_success_proven is False
    assert facts.compromise_proven is False


def test_multi_packet_allowed_flow_sets_transport_activity_without_proof() -> None:
    events = [_event("evt-1", packets=8, bytes=6000, duration_ms=2000)]
    incident = _exposure_incident(events)
    context = TriageIncidentContext(incident=incident, events=events)

    facts = derive_incident_facts(context, [])

    assert isinstance(facts, FirewallExposureFacts)
    assert facts.multi_packet_allowed_event_count == 1
    assert facts.transport_activity_observed is True
    assert facts.application_success_proven is False
    assert facts.compromise_proven is False


def test_strongly_related_reverse_context_sets_bidirectional_flow() -> None:
    incident_event = _event(
        "evt-1",
        src_ip="203.0.113.5",
        src_port=443,
        dst_ip="192.0.2.10",
        dst_port=51000,
        action="block",
        tcp_flags="ACK,RST",
    )
    related_context_event = _event(
        "ctx-1",
        src_ip="192.0.2.10",
        src_port=52222,
        dst_ip="203.0.113.5",
        dst_port=443,
        action="allow",
        tcp_flags="SYN",
    )
    incident = _exposure_incident(
        [incident_event],
        primary_entity="203.0.113.5",
        target_entities=["192.0.2.10"],
        incident_family="firewall_exposure",
    )
    context = TriageIncidentContext(
        incident=incident, events=[incident_event], context_events=[related_context_event]
    )

    facts = derive_incident_facts(context, [])

    assert isinstance(facts, FirewallExposureFacts)
    assert facts.bidirectional_related_flow_observed is True
    assert facts.transport_activity_observed is True


def test_unrelated_cross_protocol_context_event_does_not_set_bidirectional_flow() -> None:
    incident_event = _event(
        "evt-1",
        src_ip="203.0.113.5",
        src_port=443,
        dst_ip="192.0.2.10",
        dst_port=51000,
        action="block",
        tcp_flags="ACK,RST",
        protocol="TCP",
    )
    unrelated_context_event = _event(
        "ctx-1",
        src_ip="192.0.2.10",
        src_port=52222,
        dst_ip="203.0.113.5",
        dst_port=443,
        action="allow",
        protocol="UDP",
    )
    incident = _exposure_incident(
        [incident_event],
        primary_entity="203.0.113.5",
        target_entities=["192.0.2.10"],
    )
    context = TriageIncidentContext(
        incident=incident, events=[incident_event], context_events=[unrelated_context_event]
    )

    facts = derive_incident_facts(context, [])

    assert isinstance(facts, FirewallExposureFacts)
    assert facts.bidirectional_related_flow_observed is False


# --- 23: family-aware scan guardrails cover a probe outside the old list ----


def test_smb_probe_is_recognized_as_scan_probe_family() -> None:
    events = [
        _event(
            f"smb-{i}",
            dst_port=445,
            action="block",
            tcp_flags="SYN",
        )
        for i in range(3)
    ]
    incident = IncidentBundle(
        incident_id="INC-SMB",
        incident_type="smb_probe",
        incident_family="service_probing",
        title="Detected SMB probe",
        severity="high",
        confidence=0.8,
        first_seen=events[0].timestamp,
        last_seen=events[-1].timestamp,
        primary_entity="8.8.8.8",
        target_entities=["203.0.113.50"],
        signal_ids=["SIG-SMB"],
        event_ids=[e.event_id for e in events],
        context_event_ids=[],
        evidence=[],
        metrics={},
        mitre_techniques=["T1046"],
        merge_key="service_probing_smb",
    )
    context = TriageIncidentContext(incident=incident, events=events)
    signal_view = TriageSignalView(
        signal_id="SIG-SMB",
        rule_id="smb_probe",
        rule_name="SMB Probe",
        signal_type="smb_probe",
        signal_family="service_probing",
        severity="high",
        confidence=0.8,
        matched_event_ids=[e.event_id for e in events],
    )

    classification = classify_incident(context, [signal_view])
    facts = derive_incident_facts(context, [signal_view])

    assert classification.is_scan_probe is True
    assert isinstance(facts, ScanProbeFacts)
    assert facts.all_attempts_blocked is True


def test_default_registry_still_has_exactly_36_rules() -> None:
    register_default_rules()
    rules = default_registry.get_all_rules()
    assert len(rules) == 36
    assert len({rule.rule_id for rule in rules}) == 36
    assert any(isinstance(rule, SmbProbeRule) for rule in rules)
