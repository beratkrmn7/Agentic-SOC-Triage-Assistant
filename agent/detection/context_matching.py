"""Bidirectional, NAT-aware relatedness checks between canonical events.

Used to decide whether a context (non-incident) event should be attached to an
incident, and whether a related allowed flow exists for likely SPI
state-desynchronization classification. A single shared IP is never treated as
sufficient evidence of relatedness.
"""

from collections.abc import Iterable, Sequence

from agent.detection.detectors.scan_helpers import classify_service
from agent.schema import CanonicalLogEvent


def _endpoint_ip_sets(
    event: CanonicalLogEvent,
) -> tuple[frozenset[str], frozenset[str]]:
    src_ips = frozenset(
        ip for ip in (event.src_ip, event.translated_src_ip) if ip
    )
    dst_ips = frozenset(
        ip for ip in (event.dst_ip, event.translated_dst_ip) if ip
    )
    return src_ips, dst_ips


def _endpoint_port_sets(
    event: CanonicalLogEvent,
) -> tuple[frozenset[int], frozenset[int]]:
    src_ports = frozenset(
        port
        for port in (event.src_port, event.translated_src_port)
        if port is not None
    )
    dst_ports = frozenset(
        port
        for port in (event.dst_port, event.translated_dst_port)
        if port is not None
    )
    return src_ports, dst_ports


def events_are_bidirectionally_related(
    reference: CanonicalLogEvent,
    candidate: CanonicalLogEvent,
) -> bool:
    """True when `candidate` is strongly related to `reference`.

    Relatedness requires an exact endpoint relationship (forward or reverse
    source/destination, including NAT-translated IPs) combined with a port
    relationship. The port relationship may be: a full forward or reversed
    port match, a NAT/classified-service match, or - for a confirmed reverse
    IP relationship only - a one-sided service-port match (for example an
    incident event's destination 443 matching the candidate's reverse source
    443), so that differing client-side ephemeral ports on an otherwise
    reverse HTTPS/NAT flow do not block the match. Events with no ports at
    all (for example ICMP) may match on endpoints alone. Sharing exactly one
    IP with no other relationship is never sufficient.
    """
    ref_src_ips, ref_dst_ips = _endpoint_ip_sets(reference)
    cand_src_ips, cand_dst_ips = _endpoint_ip_sets(candidate)

    forward_ip = bool(ref_src_ips & cand_src_ips) and bool(ref_dst_ips & cand_dst_ips)
    reverse_ip = bool(ref_src_ips & cand_dst_ips) and bool(ref_dst_ips & cand_src_ips)
    if not (forward_ip or reverse_ip):
        return False

    ref_src_ports, ref_dst_ports = _endpoint_port_sets(reference)
    cand_src_ports, cand_dst_ports = _endpoint_port_sets(candidate)

    forward_ports = bool(ref_src_ports & cand_src_ports) and bool(
        ref_dst_ports & cand_dst_ports
    )
    reverse_ports = bool(ref_src_ports & cand_dst_ports) and bool(
        ref_dst_ports & cand_src_ports
    )
    # Reverse HTTPS/NAT flows keep the fixed service-side port but the
    # client-side ephemeral port legitimately differs between the request
    # and response/allowed log entries. Accept a one-sided service-port
    # match only when the IP relationship is genuinely reverse - never as a
    # substitute for the exact endpoint check above.
    reverse_service_port_match = reverse_ip and (
        bool(ref_dst_ports & cand_src_ports) or bool(ref_src_ports & cand_dst_ports)
    )

    all_ref_ports = ref_src_ports | ref_dst_ports
    all_cand_ports = cand_src_ports | cand_dst_ports
    if not all_ref_ports and not all_cand_ports:
        return True

    ref_services = {
        service
        for port in all_ref_ports
        if (service := classify_service(port)) is not None
    }
    cand_services = {
        service
        for port in all_cand_ports
        if (service := classify_service(port)) is not None
    }
    compatible_service = bool(ref_services & cand_services)

    return forward_ports or reverse_ports or compatible_service or reverse_service_port_match


def find_related_context_events(
    reference_events: Sequence[CanonicalLogEvent],
    context_events: Iterable[CanonicalLogEvent],
) -> list[CanonicalLogEvent]:
    """Return the subset of `context_events` related to any `reference_events`."""
    return [
        candidate
        for candidate in context_events
        if any(
            events_are_bidirectionally_related(reference, candidate)
            for reference in reference_events
        )
    ]
