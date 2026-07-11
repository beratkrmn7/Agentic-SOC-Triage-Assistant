# Rule Tuning Guide

The Agentic SOC Triage Assistant uses a deterministic detection engine configured via environment variables.

## Configuring Thresholds
All rules have customizable thresholds defined in `.env`.

### Horizontal Scan
- `HORIZONTAL_SCAN_WINDOW_SECONDS`: Time window to evaluate (default 300)
- `HORIZONTAL_SCAN_MIN_EVENTS`: Minimum total block events (default 10)
- `HORIZONTAL_SCAN_MIN_DISTINCT_TARGETS`: Minimum distinct IPs targeted (default 8)
- `HORIZONTAL_SCAN_MIN_BLOCK_RATIO`: Ratio of blocks vs allows (default 0.6)
- `HORIZONTAL_SCAN_MIN_SYN_RATIO`: Ratio of TCP SYN flags for TCP scans (default 0.5)

### Vertical Scan
- `VERTICAL_SCAN_WINDOW_SECONDS`: Time window (default 300)
- `VERTICAL_SCAN_MIN_EVENTS`: Minimum total block events (default 10)
- `VERTICAL_SCAN_MIN_DISTINCT_PORTS`: Minimum distinct ports targeted on a single IP (default 8)
- `VERTICAL_SCAN_MIN_BLOCK_RATIO`: Ratio of blocks (default 0.6)
- `VERTICAL_SCAN_MIN_SYN_RATIO`: Ratio of SYN flags for TCP (default 0.5)

### Remote Service Probe (RDP/SSH)
- `REMOTE_SERVICE_WINDOW_SECONDS`: Time window (default 300)
- `REMOTE_SERVICE_MIN_EVENTS`: Minimum probe events (default 5)
- `REMOTE_SERVICE_MIN_DISTINCT_TARGETS`: Distinct IPs probed (default 3)
- `REMOTE_SERVICE_MIN_BLOCK_RATIO`: Ratio of blocks (default 0.6)
- `REMOTE_SERVICE_MIN_SYN_RATIO`: Ratio of SYN flags (default 0.5)

### Network Flood (DoS)
- `NETWORK_FLOOD_WINDOW_SECONDS`: Time window (default 60)
- `NETWORK_FLOOD_MIN_EVENTS`: Minimum events (default 1000)
- `NETWORK_FLOOD_MIN_BLOCK_RATIO`: Ratio of blocks (default 0.9)

### SPI Anomaly Burst
- `SPI_ANOMALY_WINDOW_SECONDS`: Time window (default 300)
- `SPI_ANOMALY_MIN_EVENTS`: Minimum SPI blocks (default 5)
- `SPI_ANOMALY_MIN_DISTINCT_TARGETS`: Distinct targets (default 1)
- `SPI_ANOMALY_FALLBACK_RAW_MATCH`: Allow regex raw message match for SPI if parsing is missing (default true)
