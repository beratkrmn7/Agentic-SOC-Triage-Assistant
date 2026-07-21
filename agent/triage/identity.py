"""Deterministic incident identity locking (Phase 6E.3).

The deterministic IncidentBundle owns incident_type, incident_family,
primary entity, and detection severity/confidence. The provider may explain
and assess an incident, but it must never rename it. This module is the
single choke point every code path (success, cache hit, timeout,
provider-unavailable, invalid-output, and prompt-budget fallback) funnels
through so fresh and cached results cannot diverge.
"""

from __future__ import annotations

from agent.triage.models import TriageIncidentContext, TriageSubmission


def lock_deterministic_identity(
    submission: TriageSubmission,
    context: TriageIncidentContext,
) -> TriageSubmission:
    """Overwrite submission.incident_type with the deterministic incident type.

    Applies to every deterministic detection incident, not a narrow allow
    list - the deterministic detector, never the provider, owns identity.
    Mutates and returns `submission` for convenient chaining.
    """
    submission.incident_type = context.incident.incident_type
    return submission
