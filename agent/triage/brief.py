"""Rich, provider-free rendering for the bounded SOC triage brief."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import datetime, timedelta, timezone
from typing import Literal

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from agent.detection.detectors.exposure_helpers import (
    effective_destination_ip,
    effective_destination_port,
    is_critical_management_port,
)
from agent.detection.presentation import BriefActionItem, BriefSelection
from agent.detection.rollup import ExposedAsset, RollupResult
from agent.schema import CanonicalLogEvent
from agent.triage.attack_context import derive_attack_context, render_attack_context
from agent.triage.disposition import (
    EVIDENCE_STRENGTH_RANK,
    EvidenceStrength,
    classify_evidence_strength,
)
from agent.triage.enrichment import BriefEnrichmentResult


MAX_BRIEF_EVIDENCE_IDS = 3
MAX_BRIEF_ASSETS = 10


def _format_timestamp(value: datetime) -> str:
    return value.isoformat(sep=" ", timespec="seconds")


def _format_duration(seconds: float) -> str:
    total = max(0, int(seconds))
    minutes, remainder = divmod(total, 60)
    hours, minutes = divmod(minutes, 60)
    if hours:
        return f"{hours}h {minutes:02d}m {remainder:02d}s"
    return f"{minutes}m {remainder:02d}s"


def _source_timezone(
    event_lookup: Mapping[str, CanonicalLogEvent],
) -> timezone | None:
    offsets = sorted(
        {
            value
            for event in event_lookup.values()
            if isinstance(event.parser_metadata, dict)
            if isinstance(
                value := event.parser_metadata.get("source_timezone_offset"), str
            )
        }
    )
    if len(offsets) != 1:
        return None
    value = offsets[0]
    if len(value) != 6 or value[0] not in {"+", "-"} or value[3] != ":":
        return None
    try:
        hours = int(value[1:3])
        minutes = int(value[4:6])
    except ValueError:
        return None
    if hours > 23 or minutes > 59:
        return None
    direction = 1 if value[0] == "+" else -1
    return timezone(direction * timedelta(hours=hours, minutes=minutes))


def _in_source_timezone(value: datetime, source_timezone: timezone) -> datetime:
    # SQLite may hydrate an originally aware UTC value as a naive datetime.
    # Canonical timestamps are normalized to UTC before persistence, so UTC is
    # the only safe interpretation for a naive hydrated value here.
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(source_timezone)


def _asset_evidence_strength(
    rollup: RollupResult,
    event_lookup: Mapping[str, CanonicalLogEvent],
) -> dict[str, EvidenceStrength]:
    """Deterministic evidence strength per exposed destination."""
    by_destination: dict[str, list[CanonicalLogEvent]] = {}
    for event in event_lookup.values():
        destination = effective_destination_ip(event)
        if destination:
            by_destination.setdefault(destination, []).append(event)
    return {
        asset.effective_destination_ip: classify_evidence_strength(
            [
                event
                for event in by_destination.get(asset.effective_destination_ip, [])
                if effective_destination_port(event) in set(asset.ports)
            ]
        )
        for asset in rollup.exposed_assets
    }


def _asset_priority(asset: ExposedAsset, strength: EvidenceStrength) -> str:
    critical_management = is_critical_management_port(
        asset.ports[0] if asset.ports else None
    )
    if critical_management:
        return "P1" if strength in _STRONG_STRENGTHS else "P2"
    return "P2" if strength not in _WEAK_STRENGTHS else "P3"


def _asset_risk_key(
    asset: ExposedAsset, strengths: Mapping[str, EvidenceStrength]
) -> tuple:
    strength = strengths.get(
        asset.effective_destination_ip, EvidenceStrength.SYN_ONLY
    )
    return (
        _asset_priority(asset, strength),
        -EVIDENCE_STRENGTH_RANK[strength],
        -asset.distinct_external_source_count,
        asset.effective_destination_ip,
    )


_STRONG_STRENGTHS = frozenset(
    {
        EvidenceStrength.BIDIRECTIONAL_TRANSPORT,
        EvidenceStrength.APPLICATION_EVIDENCE,
    }
)
_WEAK_STRENGTHS = frozenset(
    {EvidenceStrength.SYN_ONLY, EvidenceStrength.SINGLE_PACKET_NON_SYN}
)

Language = Literal["en", "tr"]

_LABELS = {
    "en": {
        "priority": "Priority",
        "what": "What happened / observed flow",
        "events": "Events",
        "why": "Why it matters / next steps",
        "empty": "No items in this section.",
        "evidence": "Evidence",
        "strength": "Evidence strength",
        "members": "Grouped canonical incidents",
        "destinations": "destination(s)",
        "shared": "Applies to every item above",
        "no_attack": "ATT&CK context: insufficient behavioral evidence",
        "review": "NEEDS REVIEW",
    },
    "tr": {
        "priority": "Öncelik",
        "what": "Ne oldu / gözlenen akış",
        "events": "Olaylar",
        "why": "Neden önemli / sonraki adımlar",
        "empty": "Bu bölümde öğe yok.",
        "evidence": "Kanıt",
        "strength": "Kanıt gücü",
        "members": "Gruplanan kanonik olaylar",
        "destinations": "hedef",
        "shared": "Yukarıdaki tüm öğeler için geçerli",
        "no_attack": "ATT&CK bağlamı: yeterli davranışsal kanıt yok",
        "review": "İNCELEME GEREKLİ",
    },
}


def _priority(severity: str) -> str:
    if severity == "critical":
        return "P1"
    if severity == "high":
        return "P2"
    if severity == "medium":
        return "P3"
    return "P4"


def _item_flow(item: BriefActionItem, labels: dict[str, str]) -> str:
    sources = list(item.source_ips[:2])
    source_text = ", ".join(sources) or "unknown source"
    if item.source_count > len(sources):
        source_text += f" (+{item.source_count - len(sources)})"
    destinations = list(item.effective_destinations[:2])
    destination_text = ", ".join(destinations) or "unknown destination"
    port_text = ",".join(str(port) for port in item.ports[:6]) or "unknown port"
    if item.allowed_event_count and item.blocked_event_count:
        action_text = (
            f"{item.allowed_event_count} ALLOWED / {item.blocked_event_count} BLOCKED"
        )
    elif item.allowed_event_count:
        action_text = "ALLOWED"
    else:
        action_text = "BLOCKED"
    nat_text = " · NAT" if item.nat_observed else ""
    return (
        f"{source_text} -> {destination_text}:{port_text} · {action_text}{nat_text}\n"
        f"{item.destination_count} {labels['destinations']}"
    )


def _item_attack_context(item: BriefActionItem) -> str:
    context = derive_attack_context(
        incident_family=item.incident_family,
        service=item.service,
        evidence_strength=item.evidence_strength,
        distinct_port_count=len(item.ports),
        distinct_destination_count=item.destination_count,
    )
    return render_attack_context(context)


def _shared_actions(
    items: Sequence[BriefActionItem],
    enrichment: BriefEnrichmentResult | None,
    lang: Language,
) -> list[str]:
    """Actions every row repeats, so they can be shown once per section."""
    if enrichment is None or len(items) < 2:
        return []
    per_item: list[set[str]] = []
    for item in items:
        entry = enrichment.for_item(item.item_id)
        if entry is None:
            return []
        actions = (
            entry.recommended_actions_tr if lang == "tr" else entry.recommended_actions_en
        )
        per_item.append(set(actions))
    if not per_item:
        return []
    shared = set.intersection(*per_item)
    # Only pull an action out of the rows if something row-specific remains.
    if any(len(actions - shared) == 0 for actions in per_item):
        return []
    return sorted(shared)


def _action_table(
    title: str,
    items: Sequence[BriefActionItem],
    enrichment: BriefEnrichmentResult | None,
    lang: Language,
    shared: Sequence[str] = (),
) -> Table:
    labels = _LABELS[lang]
    table = Table(title=title, expand=True, show_lines=True)
    table.add_column(labels["priority"], no_wrap=True)
    table.add_column(labels["what"], ratio=3)
    table.add_column(labels["events"], no_wrap=True)
    table.add_column(labels["why"], ratio=3)

    for item in items:
        priority = _priority(item.severity)
        severity_text = item.severity.upper()
        if item.verdict == "needs_review":
            severity_text = f"{severity_text}\n{labels['review']}"
        event_summary = str(item.event_count)
        if item.packet_count:
            event_summary += f"\n{item.packet_count} pkt"

        entry = enrichment.for_item(item.item_id) if enrichment else None
        if entry is not None:
            explanation = (
                entry.explanation_tr if lang == "tr" else entry.explanation_en
            )
            actions = list(
                entry.recommended_actions_tr
                if lang == "tr"
                else entry.recommended_actions_en
            )
        else:
            explanation = ""
            actions = []
        actions = [action for action in actions if action not in set(shared)]

        strength_text = (
            item.evidence_strength.value if item.evidence_strength else "unknown"
        )
        evidence_text = ", ".join(item.evidence_ids[:MAX_BRIEF_EVIDENCE_IDS]) or "none"
        why_lines = [explanation] if explanation else []
        why_lines.append(_item_attack_context(item))
        why_lines.extend(f"- {action}" for action in actions)
        why_lines.append(f"{labels['evidence']}: {evidence_text}")

        what_lines = [item.title, _item_flow(item, labels)]
        what_lines.append(f"{labels['strength']}: {strength_text}")
        if item.member_incident_count > 1:
            what_lines.append(
                f"{labels['members']}: {item.member_incident_count}"
            )

        table.add_row(
            f"[{priority}]\n{severity_text}\nconf {item.confidence:.2f}",
            "\n".join(what_lines),
            event_summary,
            "\n".join(why_lines),
        )

    if not items:
        table.add_row("-", labels["empty"], "0", "-")
    return table


def render_soc_brief(
    console: Console,
    *,
    rollup: RollupResult,
    event_lookup: Mapping[str, CanonicalLogEvent],
    source_name: str,
    job_id: str | None,
    provider_call_count: int,
    selection: BriefSelection | None = None,
    enrichment: BriefEnrichmentResult | None = None,
    lang: Language = "en",
    generated_at: datetime | None = None,
) -> None:
    """Render the brief from deterministic rows plus persisted enrichment text.

    Provider-free by construction: it receives the deterministic rollup, the
    deterministic selection and an already-persisted enrichment artifact, and
    only chooses which language to display. Rendering never triggers a call.
    """
    generated_at = generated_at or datetime.now().astimezone()
    timestamps = sorted(
        event.timestamp for event in event_lookup.values() if event.timestamp is not None
    )
    if timestamps:
        first_seen, last_seen = timestamps[0], timestamps[-1]
        source_timezone = _source_timezone(event_lookup)
        if source_timezone is not None:
            first_seen = _in_source_timezone(first_seen, source_timezone)
            last_seen = _in_source_timezone(last_seen, source_timezone)
        window = (
            f"{_format_timestamp(first_seen)} - {_format_timestamp(last_seen)} | "
            f"{_format_duration((last_seen - first_seen).total_seconds())}"
        )
    else:
        window = "unknown"

    header = (
        "SOC TRIAGE BRIEF\n"
        f"Source : {source_name}\n"
        f"Window : {window}\n"
        f"Run    : {job_id or 'not persisted'} | Generated: "
        f"{_format_timestamp(generated_at)}"
    )
    console.print(Panel(header, border_style="cyan"))

    funnel = rollup.funnel
    console.print(
        Text(
            "FUNNEL  "
            f"{funnel.get('total_events', 0):,} events -> "
            f"{funnel.get('blocked_events', 0):,} blocked -> "
            f"{funnel.get('policy_exposures', 0):,} policy exposures -> "
            f"{funnel.get('action_items', 0):,} action items",
            style="bold",
        )
    )
    act_now_items = selection.act_now if selection is not None else ()
    investigate_items = selection.investigate if selection is not None else ()

    summary = (
        f"{len(act_now_items)} high-priority item(s), "
        f"{len(investigate_items)} investigation item(s), "
        f"{len(rollup.recon_groups)} fully blocked reconnaissance group(s), and "
        f"{len(rollup.exposed_assets)} exposed asset/service row(s). "
        "Firewall pass proves policy exposure only; it does not prove authentication, "
        "exploitation, or compromise."
    )
    console.print(Panel(summary, title="ANALYST SUMMARY", border_style="yellow"))

    for title, items in (
        ("§1 ACT NOW", act_now_items),
        ("§2 INVESTIGATE", investigate_items),
    ):
        shared = _shared_actions(items, enrichment, lang)
        console.print(_action_table(title, items, enrichment, lang, shared))
        if shared:
            # Shown once instead of repeated on every row above.
            console.print(
                Text(
                    f"{_LABELS[lang]['shared']}: " + " | ".join(shared),
                    style="dim",
                )
            )

    recon = Table(title="§3 BLOCKED — FYI", expand=True)
    recon.add_column("Source scope")
    recon.add_column("Family / service scope")
    recon.add_column("Sources", justify="right")
    recon.add_column("Targets", justify="right")
    recon.add_column("Ports")
    recon.add_column("Events", justify="right")
    for group in rollup.recon_groups:
        ports = ",".join(str(port) for port in group.ports[:8]) or "none"
        # A single contributing source is shown as its exact address; a CIDR
        # is only honest when several exact sources are actually present.
        if group.source_count == 1 and group.representative_sources:
            source_text = group.representative_sources[0]
        else:
            source_text = group.source_cidr
        recon.add_row(
            source_text,
            f"{group.incident_family} / {group.service_scope}",
            str(group.source_count),
            str(group.distinct_target_count),
            ports,
            str(group.total_event_count),
        )
    if not rollup.recon_groups:
        recon.add_row("-", "No fully blocked recon groups", "0", "0", "-", "0")
    console.print(recon)

    suppressed = Table(title="§4 SUPPRESSED", expand=True)
    suppressed.add_column("Source")
    suppressed.add_column("Targets")
    suppressed.add_column("Reason")
    suppressed.add_column("Events", justify="right")
    for suppressed_entry in rollup.suppressed:
        suppressed.add_row(
            suppressed_entry.source,
            ", ".join(suppressed_entry.targets) or "unknown",
            suppressed_entry.reason,
            str(suppressed_entry.event_count),
        )
    if not rollup.suppressed:
        suppressed.add_row("-", "-", "No suppressed signals", "0")
    console.print(suppressed)

    assets = Table(title="§5 EXPOSED ASSET INVENTORY", expand=True)
    assets.add_column("Priority", no_wrap=True)
    assets.add_column("Effective destination")
    assets.add_column("Service / ports")
    assets.add_column("Evidence strength")
    assets.add_column("Sources", justify="right")
    assets.add_column("NAT / public destination")
    asset_strength = _asset_evidence_strength(rollup, event_lookup)
    ordered_assets = sorted(
        rollup.exposed_assets,
        key=lambda asset: _asset_risk_key(asset, asset_strength),
    )
    for exposed_asset in ordered_assets[:MAX_BRIEF_ASSETS]:
        nat_text = "no NAT"
        if exposed_asset.nat_observed:
            public = (
                ", ".join(exposed_asset.public_destinations)
                or "public address unknown"
            )
            nat_text = (
                f"{public} -> "
                f"{exposed_asset.internal_address or exposed_asset.effective_destination_ip}"
            )
        strength = asset_strength.get(
            exposed_asset.effective_destination_ip, EvidenceStrength.SYN_ONLY
        )
        assets.add_row(
            _asset_priority(exposed_asset, strength),
            exposed_asset.effective_destination_ip,
            f"{exposed_asset.service} / "
            f"{','.join(str(port) for port in exposed_asset.ports)}",
            strength.value,
            str(exposed_asset.distinct_external_source_count),
            nat_text,
        )
    if not rollup.exposed_assets:
        assets.add_row("-", "-", "No exposed sensitive services", "-", "0", "-")
    console.print(assets)
    if len(rollup.exposed_assets) > MAX_BRIEF_ASSETS:
        console.print(
            f"[dim]{len(rollup.exposed_assets) - MAX_BRIEF_ASSETS} additional asset/service "
            "row(s) remain available in the full canonical result.[/dim]"
        )
    console.print(f"Provider calls for this request: {provider_call_count}")
