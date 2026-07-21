"""Phase 6E.4A: persistent cross-job stateful correlation profile contract.

Everything here is pure and deterministic: no database access, no provider
calls, no wall-clock reads for key generation. Given the same incident and
events, `derive_stateful_profile` always returns the same profile (or the
same None), and `compute_correlation_key` always returns the same key for
semantically identical profiles regardless of input ordering.

This module only recognizes activity, it never decides whether two
*incidents* should merge - `is_state_eligible` below is the only eligibility
gate, and it operates on an already-matched correlation key plus timestamps.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta
from typing import Literal, Optional, Sequence

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from agent.detection.detectors.scan_helpers import classify_service
from agent.detection.models import IncidentBundle
from agent.schema import CanonicalLogEvent


CORRELATION_KEY_PREFIX = "scv"

StatefulStrategy = Literal[
    "source_service_campaign",
    "source_target_sequence",
    "protected_service_exposure",
]

# Strategy A: source-service campaign. "Broad" incident types describe an
# activity pattern that legitimately spans different targets across files
# (horizontal/service-wide scanning, or a per-service probe rule), so target
# identity is deliberately excluded from the profile. "Narrow" incident
# types are target-specific: the destination must be part of the profile so
# unrelated targets never merge.
_SOURCE_SERVICE_BROAD_TYPES = frozenset(
    {
        "horizontal_scan",
        "low_and_slow_horizontal_scan",
        "subnet_sweep",
        "distributed_scan",
        "multi_service_sweep",
        "repeated_blocked_scanner",
        "rdp_probe",
        "ssh_probe",
        "smb_probe",
        "vnc_probe",
        "winrm_probe",
        "mssql_probe",
        "oracle_probe",
        "mysql_probe",
        "postgresql_probe",
        "redis_probe",
        "elasticsearch_probe",
        "mongodb_probe",
        "docker_daemon_probe",
        "kubernetes_api_probe",
        "kubelet_probe",
        "telnet_probe",
        "ftp_probe",
        "web_admin_panel_probe",
    }
)
_SOURCE_SERVICE_NARROW_TYPES = frozenset(
    {
        "vertical_scan",
        "low_and_slow_vertical_scan",
        "internal_lateral_scan",
    }
)
_SOURCE_SERVICE_INCIDENT_TYPES = _SOURCE_SERVICE_BROAD_TYPES | _SOURCE_SERVICE_NARROW_TYPES
_SOURCE_SERVICE_FAMILIES = frozenset(
    {"network_scanning", "service_probing", "network_anomaly"}
)

# Strategy B: source-target sequence. Only correlates incidents that Phase
# 6E.2 has already emitted with one of these identities - never re-derives a
# sequence from raw historical events (that is out of scope for 6E.4A).
_SEQUENCE_INCIDENT_TYPES = frozenset(
    {
        "scan_followed_by_allowed_connection",
        "blocked_then_allowed_same_service",
        "spi_followed_by_allowed_connection",
    }
)

# Strategy C: protected-service exposure. External source IP is
# intentionally excluded from the profile - see module docstring on
# StatefulCorrelationProfile.actor_entity.
_EXPOSURE_FAMILIES = frozenset({"firewall_exposure", "firewall_policy"})


class StatefulCorrelationProfile(BaseModel):
    """Normalized, bounded, duplicate-free identity for one stateful
    correlation strategy. Safe to serialize: no raw messages, no parser
    metadata, no free-form provider text.
    """

    model_config = ConfigDict(frozen=True)

    correlation_version: str = Field(min_length=1, max_length=16)
    strategy: StatefulStrategy
    actor_entity: Optional[str] = Field(default=None, max_length=128)
    protected_entity: Optional[str] = Field(default=None, max_length=128)
    protocols: tuple[str, ...] = Field(default_factory=tuple, max_length=100)
    services: tuple[str, ...] = Field(default_factory=tuple, max_length=100)
    destination_ports: tuple[int, ...] = Field(default_factory=tuple, max_length=100)
    target_scopes: tuple[str, ...] = Field(default_factory=tuple, max_length=100)

    @field_validator("actor_entity", "protected_entity", mode="after")
    @classmethod
    def _normalize_entity(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        normalized = value.strip()
        return normalized or None

    @field_validator("protocols", "services", "target_scopes", mode="after")
    @classmethod
    def _normalize_str_tuple(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(sorted({item.strip().upper() for item in value if item and item.strip()}))

    @field_validator("destination_ports", mode="after")
    @classmethod
    def _normalize_ports(cls, value: tuple[int, ...]) -> tuple[int, ...]:
        return tuple(sorted({port for port in value if port is not None}))

    @model_validator(mode="after")
    def _validate_required_identity(self) -> "StatefulCorrelationProfile":
        if self.strategy == "protected_service_exposure":
            if self.actor_entity is not None:
                raise ValueError("protected_service_exposure_actor_forbidden")
            if not self.protected_entity:
                raise ValueError("protected_service_exposure_requires_protected_entity")
        else:
            if not self.actor_entity:
                raise ValueError("actor_entity_required")
        if self.strategy == "source_target_sequence" and not self.protected_entity:
            raise ValueError("source_target_sequence_requires_protected_entity")
        if not self.protocols:
            raise ValueError("protocols_required")
        if not self.services and not self.destination_ports:
            raise ValueError("service_or_port_required")
        return self


def compute_correlation_key(profile: StatefulCorrelationProfile) -> str:
    """Versioned SHA-256 correlation key over the profile's canonical JSON.

    Field-level validators already sort/dedup every collection, so identical
    semantic profiles serialize identically regardless of the order their
    source data arrived in. `sort_keys=True` is a second, independent
    safeguard against relying on Python's (stable, but incidental) field
    declaration order.
    """
    payload = profile.model_dump(mode="json")
    canonical_json = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    digest = hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()
    return f"{CORRELATION_KEY_PREFIX}{profile.correlation_version}:{digest}"


def _effective_destination_ip(event: CanonicalLogEvent) -> Optional[str]:
    return event.translated_dst_ip or event.dst_ip


def _effective_destination_port(event: CanonicalLogEvent) -> Optional[int]:
    if event.translated_dst_port is not None:
        return event.translated_dst_port
    return event.dst_port


def _normalized_protocol(event: CanonicalLogEvent) -> Optional[str]:
    if not event.protocol:
        return None
    return str(event.protocol).strip().upper() or None


def _incident_events(
    incident: IncidentBundle, events: Sequence[CanonicalLogEvent]
) -> list[CanonicalLogEvent]:
    incident_event_ids = set(incident.event_ids)
    return [event for event in events if event.event_id in incident_event_ids]


def _single_protocol(events: Sequence[CanonicalLogEvent]) -> tuple[str, ...]:
    """A single, unambiguous protocol identity, or empty when contradictory.

    More than one distinct known protocol across the incident's own events
    is treated as contradictory (fail closed) rather than guessed at -
    matching services/ports still constrain identity, but a mixed-protocol
    incident cannot safely claim a single-protocol campaign identity.
    """
    protocols = {p for p in (_normalized_protocol(e) for e in events) if p}
    if len(protocols) != 1:
        return ()
    return (next(iter(protocols)),)


def _services_and_ports(
    ports: Sequence[Optional[int]], *, max_items: int
) -> tuple[tuple[str, ...], tuple[int, ...]]:
    known_ports = sorted({p for p in ports if p is not None})[:max_items]
    services = sorted({s for s in (classify_service(p) for p in known_ports) if s})[:max_items]
    return tuple(services), tuple(known_ports)


def _derive_source_service_profile(
    incident: IncidentBundle,
    incident_events: Sequence[CanonicalLogEvent],
    *,
    correlation_version: str,
    max_items: int,
) -> Optional[StatefulCorrelationProfile]:
    if incident.incident_family not in _SOURCE_SERVICE_FAMILIES:
        return None
    if incident.incident_type not in _SOURCE_SERVICE_INCIDENT_TYPES:
        return None
    if not incident_events:
        return None

    actor_entity = (incident.primary_entity or "").strip()
    if not actor_entity:
        return None

    protocols = _single_protocol(incident_events)
    if not protocols:
        return None

    ports = [_effective_destination_port(event) for event in incident_events]
    services, destination_ports = _services_and_ports(ports, max_items=max_items)
    if not services and not destination_ports:
        return None

    target_scopes: tuple[str, ...] = ()
    if incident.incident_type in _SOURCE_SERVICE_NARROW_TYPES:
        destinations = [
            _effective_destination_ip(event) for event in incident_events
        ]
        target_scopes = tuple(
            sorted({d for d in destinations if d})[:max_items]
        )
        if not target_scopes:
            return None

    try:
        return StatefulCorrelationProfile(
            correlation_version=correlation_version,
            strategy="source_service_campaign",
            actor_entity=actor_entity,
            protected_entity=None,
            protocols=protocols,
            services=services,
            destination_ports=destination_ports,
            target_scopes=target_scopes,
        )
    except ValueError:
        return None


def _derive_source_target_sequence_profile(
    incident: IncidentBundle,
    incident_events: Sequence[CanonicalLogEvent],
    *,
    correlation_version: str,
    max_items: int,
) -> Optional[StatefulCorrelationProfile]:
    if incident.incident_type not in _SEQUENCE_INCIDENT_TYPES:
        return None
    if not incident_events:
        return None

    actor_entity = (incident.primary_entity or "").strip()
    if not actor_entity:
        return None

    destinations = {
        d for d in (_effective_destination_ip(event) for event in incident_events) if d
    }
    if len(destinations) != 1:
        return None
    protected_entity = next(iter(destinations))

    protocols = _single_protocol(incident_events)
    if not protocols:
        return None

    ports = [_effective_destination_port(event) for event in incident_events]
    services, destination_ports = _services_and_ports(ports, max_items=max_items)
    if not services and not destination_ports:
        return None

    try:
        return StatefulCorrelationProfile(
            correlation_version=correlation_version,
            strategy="source_target_sequence",
            actor_entity=actor_entity,
            protected_entity=protected_entity,
            protocols=protocols,
            services=services,
            destination_ports=destination_ports,
            target_scopes=(),
        )
    except ValueError:
        return None


def _derive_protected_service_exposure_profile(
    incident: IncidentBundle,
    incident_events: Sequence[CanonicalLogEvent],
    *,
    correlation_version: str,
    max_items: int,
) -> Optional[StatefulCorrelationProfile]:
    if incident.incident_family not in _EXPOSURE_FAMILIES:
        return None
    if not incident_events:
        return None

    destinations = {
        d for d in (_effective_destination_ip(event) for event in incident_events) if d
    }
    if len(destinations) != 1:
        return None
    protected_entity = next(iter(destinations))
    # Public sources reaching the same protected service across different
    # files must still correlate, so the source side is deliberately never
    # examined here - actor_entity stays None for this strategy.

    protocols = _single_protocol(incident_events)
    if not protocols:
        return None

    ports = [_effective_destination_port(event) for event in incident_events]
    services, destination_ports = _services_and_ports(ports, max_items=max_items)
    if not services and not destination_ports:
        return None

    try:
        return StatefulCorrelationProfile(
            correlation_version=correlation_version,
            strategy="protected_service_exposure",
            actor_entity=None,
            protected_entity=protected_entity,
            protocols=protocols,
            services=services,
            destination_ports=destination_ports,
            target_scopes=(),
        )
    except ValueError:
        return None


def derive_stateful_profile(
    incident: IncidentBundle,
    events: Sequence[CanonicalLogEvent],
    *,
    correlation_version: str,
    max_profile_items: int,
) -> Optional[StatefulCorrelationProfile]:
    """Derive a stateful correlation profile for `incident`, or None.

    Only uses `incident`'s own event_ids (never context_event_ids) and
    typed CanonicalLogEvent fields - never raw PF strings, source-line
    parsing, parser_metadata, LLM output, or report text. Fails closed
    (returns None) whenever the required identity for every supported
    strategy cannot be established; never falls back to primary_entity
    alone as a stand-in for a real profile.
    """
    incident_events = _incident_events(incident, events)

    profile = _derive_source_target_sequence_profile(
        incident,
        incident_events,
        correlation_version=correlation_version,
        max_items=max_profile_items,
    )
    if profile is not None:
        return profile

    profile = _derive_protected_service_exposure_profile(
        incident,
        incident_events,
        correlation_version=correlation_version,
        max_items=max_profile_items,
    )
    if profile is not None:
        return profile

    return _derive_source_service_profile(
        incident,
        incident_events,
        correlation_version=correlation_version,
        max_items=max_profile_items,
    )


class StatefulStateSnapshot(BaseModel):
    """Minimal read-only view of a persisted IncidentCorrelationState row,
    used by `is_state_eligible` so that function stays pure/DB-free."""

    model_config = ConfigDict(frozen=True)

    correlation_version: str
    generation: int
    incident_id: str
    first_seen: datetime
    last_seen: datetime
    expires_at: datetime


def is_state_eligible(
    state: StatefulStateSnapshot,
    *,
    correlation_version: str,
    incident_exists: bool,
    incoming_first_seen: datetime,
    incoming_last_seen: datetime,
    window_seconds: int,
    now: datetime,
) -> bool:
    """True when an incoming incident may merge into `state`'s campaign.

    Same TTL alone is never sufficient: `expires_at` only bounds state
    *cleanup*, while `window_seconds` bounds campaign *continuity* and is
    checked independently against the incoming incident's own event
    timestamps (never ingestion time). The window check is a genuine
    overlap test in both directions, so a late-arriving report of slightly
    older activity can still merge, while a very old, unrelated incident
    outside the window cannot reopen an active campaign.
    """
    if not incident_exists:
        return False
    if state.correlation_version != correlation_version:
        return False
    if state.expires_at <= now:
        return False
    if incoming_first_seen > incoming_last_seen:
        return False
    window = timedelta(seconds=window_seconds)
    if incoming_first_seen > state.last_seen + window:
        return False
    if incoming_last_seen < state.first_seen - window:
        return False
    return True
