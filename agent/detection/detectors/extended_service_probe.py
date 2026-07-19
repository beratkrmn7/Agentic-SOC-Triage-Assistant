from collections import defaultdict, deque
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any, ClassVar

from agent.detection.contracts import DetectionRuleMetadata, DetectionSignalVariant
from agent.detection.correlation import sliding_window_scan
from agent.detection.detectors.base import BaseDetectionRule, DetectionContext
from agent.detection.detectors.scan_helpers import (
    bounded_sorted_values,
    event_ratios,
    is_allowed,
    normalized_protocol,
    parse_ip_address,
)
from agent.detection.evidence import select_representative_evidence
from agent.detection.models import DetectionSignal, generate_signal_id
from agent.detection.scoring import calculate_signal_confidence
from agent.schema import CanonicalLogEvent


@dataclass(frozen=True)
class ServiceProbeProfile:
    key: str
    ports: tuple[int, ...]
    emitted_rule_id: str
    emitted_rule_name: str
    emitted_signal_type: str

    def __post_init__(self) -> None:
        if not self.key or not self.ports:
            raise ValueError("service probe profiles require a key and at least one port")
        if self.ports != tuple(sorted(set(self.ports))):
            raise ValueError("service probe profile ports must be deterministic and unique")
        if any(port < 1 or port > 65_535 for port in self.ports):
            raise ValueError("service probe profile contains an invalid TCP port")
        if not all(
            (self.emitted_rule_id, self.emitted_rule_name, self.emitted_signal_type)
        ):
            raise ValueError("service probe profiles require a complete signal identity")


def _signal_variants(
    profiles: tuple[ServiceProbeProfile, ...],
) -> tuple[DetectionSignalVariant, ...]:
    return tuple(
        DetectionSignalVariant(
            rule_id=profile.emitted_rule_id,
            rule_name=profile.emitted_rule_name,
            signal_type=profile.emitted_signal_type,
        )
        for profile in profiles
    )


class _ProfiledServiceProbeRule(BaseDetectionRule):
    profiles: ClassVar[tuple[ServiceProbeProfile, ...]] = ()
    use_web_admin_thresholds: ClassVar[bool] = False

    def evaluate(
        self,
        events: Sequence[CanonicalLogEvent],
        context: DetectionContext,
    ) -> list[DetectionSignal]:
        settings = context.settings
        if self.use_web_admin_thresholds:
            minimum_events = settings.WEB_ADMIN_PROBE_MIN_EVENTS
            minimum_targets = settings.WEB_ADMIN_PROBE_MIN_DISTINCT_TARGETS
            minimum_block_ratio = settings.WEB_ADMIN_PROBE_MIN_BLOCK_RATIO
            minimum_syn_ratio = settings.WEB_ADMIN_PROBE_MIN_SYN_RATIO
        else:
            minimum_events = settings.EXTENDED_SERVICE_PROBE_MIN_EVENTS
            minimum_targets = settings.EXTENDED_SERVICE_PROBE_MIN_DISTINCT_TARGETS
            minimum_block_ratio = settings.EXTENDED_SERVICE_PROBE_MIN_BLOCK_RATIO
            minimum_syn_ratio = settings.EXTENDED_SERVICE_PROBE_MIN_SYN_RATIO

        profiles_by_key = {profile.key: profile for profile in self.profiles}
        profiles_by_port = {
            port: profile
            for profile in self.profiles
            for port in profile.ports
        }
        groups: dict[tuple[str, str], list[CanonicalLogEvent]] = defaultdict(list)
        for event in events:
            source_address = parse_ip_address(event.src_ip)
            destination_address = parse_ip_address(event.dst_ip)
            if (
                source_address is None
                or destination_address is None
                or normalized_protocol(event) != "TCP"
                or event.dst_port is None
            ):
                continue
            profile = profiles_by_port.get(event.dst_port)
            if profile is None:
                continue
            groups[(str(source_address), profile.key)].append(event)

        signals: list[DetectionSignal] = []
        for (src_ip, profile_key), grouped_events in groups.items():
            if len(grouped_events) < minimum_events:
                continue
            profile = profiles_by_key[profile_key]
            ordered_events = sorted(
                grouped_events,
                key=lambda event: (
                    event.timestamp or context.analysis_started_at,
                    event.event_id,
                ),
            )

            def matches(window: deque[CanonicalLogEvent]) -> tuple[bool, dict[str, Any]]:
                window_events = list(window)
                if len(window_events) < minimum_events:
                    return False, {}
                targets = {
                    str(address)
                    for event in window_events
                    if (address := parse_ip_address(event.dst_ip)) is not None
                }
                if len(targets) < minimum_targets:
                    return False, {}
                block_ratio, syn_ratio = event_ratios(window_events)
                if block_ratio < minimum_block_ratio or syn_ratio < minimum_syn_ratio:
                    return False, {}
                destination_ports = sorted(
                    {
                        event.dst_port
                        for event in window_events
                        if event.dst_port is not None
                    }
                )
                return True, {
                    "service": profile.key,
                    "event_count": len(window_events),
                    "distinct_targets": len(targets),
                    "destination_ports": ",".join(
                        str(port) for port in destination_ports
                    ),
                    "block_ratio": block_ratio,
                    "syn_ratio": syn_ratio,
                    "allowed_events": sum(
                        1 for event in window_events if is_allowed(event)
                    ),
                }

            matches_found = sliding_window_scan(
                ordered_events,
                settings.EXTENDED_SERVICE_PROBE_WINDOW_SECONDS,
                matches,
            )
            for match_events, metrics in matches_found:
                event_ids = [event.event_id for event in match_events]
                first_seen = match_events[0].timestamp or context.analysis_started_at
                last_seen = match_events[-1].timestamp or context.analysis_started_at
                signal_id = generate_signal_id(
                    profile.emitted_rule_id,
                    self.version,
                    src_ip,
                    f"service_{profile.key}",
                    first_seen,
                    event_ids,
                )
                target_entities = bounded_sorted_values(
                    str(address)
                    for event in match_events
                    if (address := parse_ip_address(event.dst_ip)) is not None
                )
                signals.append(
                    DetectionSignal(
                        signal_id=signal_id,
                        rule_id=profile.emitted_rule_id,
                        rule_version=self.version,
                        rule_name=profile.emitted_rule_name,
                        signal_type=profile.emitted_signal_type,
                        signal_family=self.family,
                        severity=self.metadata.default_severity,
                        confidence=calculate_signal_confidence(
                            len(match_events),
                            minimum_events,
                            base_confidence=(
                                0.65 if self.use_web_admin_thresholds else 0.7
                            ),
                            max_confidence=(
                                0.9 if self.use_web_admin_thresholds else 0.95
                            ),
                        ),
                        first_seen=first_seen,
                        last_seen=last_seen,
                        event_ids=event_ids,
                        primary_entity=src_ip,
                        target_entities=target_entities,
                        metrics=metrics,
                        evidence=select_representative_evidence(
                            match_events,
                            max_evidence=3,
                            reason=f"Repeated TCP probing of {profile.key} services",
                            source_rule=self.rule_id,
                            correlation_context=metrics,
                        ),
                        mitre_techniques=list(self.metadata.mitre_techniques),
                        tags=["network", "probe", profile.key],
                    )
                )
        return sorted(
            signals,
            key=lambda signal: (
                signal.first_seen,
                signal.rule_id,
                signal.signal_id,
            ),
        )


SMB_PROFILE = ServiceProbeProfile(
    key="smb",
    ports=(139, 445),
    emitted_rule_id="smb_probe",
    emitted_rule_name="SMB Probe",
    emitted_signal_type="smb_probe",
)
VNC_PROFILE = ServiceProbeProfile(
    key="vnc",
    ports=(5900, 5901, 5902, 5903, 5904, 5905),
    emitted_rule_id="vnc_probe",
    emitted_rule_name="VNC Probe",
    emitted_signal_type="vnc_probe",
)
WINRM_PROFILE = ServiceProbeProfile(
    key="winrm",
    ports=(5985, 5986),
    emitted_rule_id="winrm_probe",
    emitted_rule_name="WinRM Probe",
    emitted_signal_type="winrm_probe",
)
MSSQL_PROFILE = ServiceProbeProfile(
    key="mssql",
    ports=(1433,),
    emitted_rule_id="mssql_probe",
    emitted_rule_name="MSSQL Probe",
    emitted_signal_type="mssql_probe",
)
ORACLE_PROFILE = ServiceProbeProfile(
    key="oracle",
    ports=(1521,),
    emitted_rule_id="oracle_probe",
    emitted_rule_name="Oracle Probe",
    emitted_signal_type="oracle_probe",
)
MYSQL_PROFILE = ServiceProbeProfile(
    key="mysql",
    ports=(3306,),
    emitted_rule_id="mysql_probe",
    emitted_rule_name="MySQL Probe",
    emitted_signal_type="mysql_probe",
)
POSTGRESQL_PROFILE = ServiceProbeProfile(
    key="postgresql",
    ports=(5432,),
    emitted_rule_id="postgresql_probe",
    emitted_rule_name="PostgreSQL Probe",
    emitted_signal_type="postgresql_probe",
)
REDIS_PROFILE = ServiceProbeProfile(
    key="redis",
    ports=(6379,),
    emitted_rule_id="redis_probe",
    emitted_rule_name="Redis Probe",
    emitted_signal_type="redis_probe",
)
ELASTICSEARCH_PROFILE = ServiceProbeProfile(
    key="elasticsearch",
    ports=(9200,),
    emitted_rule_id="elasticsearch_probe",
    emitted_rule_name="Elasticsearch Probe",
    emitted_signal_type="elasticsearch_probe",
)
MONGODB_PROFILE = ServiceProbeProfile(
    key="mongodb",
    ports=(27017,),
    emitted_rule_id="mongodb_probe",
    emitted_rule_name="MongoDB Probe",
    emitted_signal_type="mongodb_probe",
)
KUBERNETES_API_PROFILE = ServiceProbeProfile(
    key="kubernetes_api",
    ports=(6443,),
    emitted_rule_id="kubernetes_api_probe",
    emitted_rule_name="Kubernetes API Probe",
    emitted_signal_type="kubernetes_api_probe",
)
KUBELET_PROFILE = ServiceProbeProfile(
    key="kubelet",
    ports=(10250,),
    emitted_rule_id="kubelet_probe",
    emitted_rule_name="Kubelet Probe",
    emitted_signal_type="kubelet_probe",
)
DOCKER_DAEMON_PROFILE = ServiceProbeProfile(
    key="docker_daemon",
    ports=(2375, 2376),
    emitted_rule_id="docker_daemon_probe",
    emitted_rule_name="Docker Daemon Probe",
    emitted_signal_type="docker_daemon_probe",
)
WEB_ADMIN_PANEL_PROFILE = ServiceProbeProfile(
    key="web_admin_panel",
    ports=(8000, 8080, 8443, 8888, 9000, 9443, 10000),
    emitted_rule_id="web_admin_panel_probe",
    emitted_rule_name="Web Admin Panel Probe",
    emitted_signal_type="web_admin_panel_probe",
)
TELNET_PROFILE = ServiceProbeProfile(
    key="telnet",
    ports=(23,),
    emitted_rule_id="telnet_probe",
    emitted_rule_name="Telnet Probe",
    emitted_signal_type="telnet_probe",
)
FTP_PROFILE = ServiceProbeProfile(
    key="ftp",
    ports=(20, 21),
    emitted_rule_id="ftp_probe",
    emitted_rule_name="FTP Probe",
    emitted_signal_type="ftp_probe",
)


class SmbProbeRule(_ProfiledServiceProbeRule):
    profiles = (SMB_PROFILE,)
    metadata = DetectionRuleMetadata(
        rule_id="smb_probe",
        version="1.0.0",
        name="SMB Probe",
        family="service_probing",
        priority=52,
        supported_event_types=(),
        required_fields=("src_ip", "dst_ip", "dst_port", "protocol"),
        signal_type="smb_probe",
        default_severity="high",
        mitre_techniques=("T1046",),
        window_setting="EXTENDED_SERVICE_PROBE_WINDOW_SECONDS",
        minimum_events_setting="EXTENDED_SERVICE_PROBE_MIN_EVENTS",
    )


class VncProbeRule(_ProfiledServiceProbeRule):
    profiles = (VNC_PROFILE,)
    metadata = DetectionRuleMetadata(
        rule_id="vnc_probe",
        version="1.0.0",
        name="VNC Probe",
        family="service_probing",
        priority=53,
        supported_event_types=(),
        required_fields=("src_ip", "dst_ip", "dst_port", "protocol"),
        signal_type="vnc_probe",
        default_severity="high",
        mitre_techniques=("T1046",),
        window_setting="EXTENDED_SERVICE_PROBE_WINDOW_SECONDS",
        minimum_events_setting="EXTENDED_SERVICE_PROBE_MIN_EVENTS",
    )


class WinRmProbeRule(_ProfiledServiceProbeRule):
    profiles = (WINRM_PROFILE,)
    metadata = DetectionRuleMetadata(
        rule_id="winrm_probe",
        version="1.0.0",
        name="WinRM Probe",
        family="service_probing",
        priority=54,
        supported_event_types=(),
        required_fields=("src_ip", "dst_ip", "dst_port", "protocol"),
        signal_type="winrm_probe",
        default_severity="high",
        mitre_techniques=("T1046",),
        window_setting="EXTENDED_SERVICE_PROBE_WINDOW_SECONDS",
        minimum_events_setting="EXTENDED_SERVICE_PROBE_MIN_EVENTS",
    )


class DatabaseServiceProbeRule(_ProfiledServiceProbeRule):
    profiles = (
        MSSQL_PROFILE,
        ORACLE_PROFILE,
        MYSQL_PROFILE,
        POSTGRESQL_PROFILE,
        REDIS_PROFILE,
        ELASTICSEARCH_PROFILE,
        MONGODB_PROFILE,
    )
    metadata = DetectionRuleMetadata(
        rule_id="database_service_probe",
        version="1.0.0",
        name="Database Service Probe",
        family="service_probing",
        priority=55,
        supported_event_types=(),
        required_fields=("src_ip", "dst_ip", "dst_port", "protocol"),
        signal_type="database_service_probe",
        signal_variants=_signal_variants(profiles),
        default_severity="high",
        mitre_techniques=("T1046",),
        window_setting="EXTENDED_SERVICE_PROBE_WINDOW_SECONDS",
        minimum_events_setting="EXTENDED_SERVICE_PROBE_MIN_EVENTS",
    )


class KubernetesServiceProbeRule(_ProfiledServiceProbeRule):
    profiles = (KUBERNETES_API_PROFILE, KUBELET_PROFILE)
    metadata = DetectionRuleMetadata(
        rule_id="kubernetes_service_probe",
        version="1.0.0",
        name="Kubernetes Service Probe",
        family="service_probing",
        priority=56,
        supported_event_types=(),
        required_fields=("src_ip", "dst_ip", "dst_port", "protocol"),
        signal_type="kubernetes_service_probe",
        signal_variants=_signal_variants(profiles),
        default_severity="high",
        mitre_techniques=("T1046",),
        window_setting="EXTENDED_SERVICE_PROBE_WINDOW_SECONDS",
        minimum_events_setting="EXTENDED_SERVICE_PROBE_MIN_EVENTS",
    )


class DockerDaemonProbeRule(_ProfiledServiceProbeRule):
    profiles = (DOCKER_DAEMON_PROFILE,)
    metadata = DetectionRuleMetadata(
        rule_id="docker_daemon_probe",
        version="1.0.0",
        name="Docker Daemon Probe",
        family="service_probing",
        priority=57,
        supported_event_types=(),
        required_fields=("src_ip", "dst_ip", "dst_port", "protocol"),
        signal_type="docker_daemon_probe",
        default_severity="high",
        mitre_techniques=("T1046",),
        window_setting="EXTENDED_SERVICE_PROBE_WINDOW_SECONDS",
        minimum_events_setting="EXTENDED_SERVICE_PROBE_MIN_EVENTS",
    )


class WebAdminPanelProbeRule(_ProfiledServiceProbeRule):
    profiles = (WEB_ADMIN_PANEL_PROFILE,)
    use_web_admin_thresholds = True
    metadata = DetectionRuleMetadata(
        rule_id="web_admin_panel_probe",
        version="1.0.0",
        name="Web Admin Panel Probe",
        family="service_probing",
        priority=58,
        supported_event_types=(),
        required_fields=("src_ip", "dst_ip", "dst_port", "protocol"),
        signal_type="web_admin_panel_probe",
        default_severity="medium",
        mitre_techniques=("T1046",),
        window_setting="EXTENDED_SERVICE_PROBE_WINDOW_SECONDS",
        minimum_events_setting="WEB_ADMIN_PROBE_MIN_EVENTS",
    )


class LegacyCleartextServiceProbeRule(_ProfiledServiceProbeRule):
    profiles = (TELNET_PROFILE, FTP_PROFILE)
    metadata = DetectionRuleMetadata(
        rule_id="legacy_cleartext_service_probe",
        version="1.0.0",
        name="Legacy Cleartext Service Probe",
        family="service_probing",
        priority=59,
        supported_event_types=(),
        required_fields=("src_ip", "dst_ip", "dst_port", "protocol"),
        signal_type="legacy_cleartext_service_probe",
        signal_variants=_signal_variants(profiles),
        default_severity="medium",
        mitre_techniques=("T1046",),
        window_setting="EXTENDED_SERVICE_PROBE_WINDOW_SECONDS",
        minimum_events_setting="EXTENDED_SERVICE_PROBE_MIN_EVENTS",
    )
