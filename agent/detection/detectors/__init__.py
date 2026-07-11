"""
Detectors module
"""
def register_default_rules():
    from agent.detection.registry import default_registry

    from agent.detection.detectors.horizontal_scan import HorizontalScanRule
    from agent.detection.detectors.vertical_scan import VerticalScanRule
    from agent.detection.detectors.remote_service_probe import RemoteServiceProbeRule
    from agent.detection.detectors.spi_anomaly import SPIAnomalyRule
    from agent.detection.detectors.network_flood import NetworkFloodRule

    # Register rules
    default_registry.register(HorizontalScanRule())
    default_registry.register(VerticalScanRule())
    default_registry.register(RemoteServiceProbeRule())
    default_registry.register(SPIAnomalyRule())
    default_registry.register(NetworkFloodRule())
