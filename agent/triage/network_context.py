"""Deterministic network-context derivation shared by the safe triage view.

Leaf module: imports only from the detection package's already-shared
IP/zone helpers, never from the rest of the triage package, so there is no
circular import between the triage and detector packages.
"""

from __future__ import annotations

from agent.detection.detectors.exposure_helpers import (
    effective_destination_ip,
    is_explicit_dmz_zone,
    is_explicit_lan_zone,
    is_explicit_wan_zone,
)
from agent.detection.detectors.scan_helpers import is_private_unicast, parse_ip_address
from agent.schema import CanonicalLogEvent


def derive_flow_direction(event: CanonicalLogEvent) -> str:
    """Deterministic flow direction: inbound, outbound, lateral, or unknown.

    Prefers explicit normalized inbound/outbound zones (for example WAN to
    LAN/DMZ). Falls back to private/public IP classification only when zone
    evidence is absent or does not resolve the direction. Never inspects
    raw PF-specific message strings.
    """
    inbound_is_wan = is_explicit_wan_zone(event.inbound_zone)
    outbound_is_wan = is_explicit_wan_zone(event.outbound_zone)
    inbound_is_internal = is_explicit_lan_zone(event.inbound_zone) or is_explicit_dmz_zone(
        event.inbound_zone
    )
    outbound_is_internal = is_explicit_lan_zone(event.outbound_zone) or is_explicit_dmz_zone(
        event.outbound_zone
    )

    if inbound_is_wan and outbound_is_internal:
        return "inbound"
    if outbound_is_wan and inbound_is_internal:
        return "outbound"
    if inbound_is_wan:
        return "inbound"
    if outbound_is_wan:
        return "outbound"

    source_address = parse_ip_address(event.src_ip)
    destination_address = parse_ip_address(effective_destination_ip(event))
    if source_address is None or destination_address is None:
        return "unknown"

    source_is_private = is_private_unicast(event.src_ip)
    destination_is_private = is_private_unicast(effective_destination_ip(event))

    if not source_is_private and destination_is_private:
        return "inbound"
    if source_is_private and not destination_is_private:
        return "outbound"
    if source_is_private and destination_is_private:
        return "lateral"
    return "unknown"
