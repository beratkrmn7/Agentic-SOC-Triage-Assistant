# False Positive Handling

The Agentic SOC Triage Assistant uses a deterministic detection engine that can generate false positives (FPs) if not tuned properly.

## Managing Suppression Rules

The Detection Engine includes a `SuppressionPolicy` component that filters out matched signals before they are passed to the Correlation Engine. This ensures that downstream incidents and AI analysis do not get polluted by known benign behavior.

Suppression can be applied dynamically via the backend. The following mechanisms are supported:

### 1. Source IP Allowlisting
Suppress all alerts originating from specific internal scanners or known benign systems.
- Use `add_allowed_source("10.1.1.0/24")` or specific IPs.
- Safety Guard: `"0.0.0.0/0"` and `"::/0"` are explicitly rejected.

### 2. Destination IP Allowlisting
Suppress alerts targeting public honeypots, sinkholes, or load balancers.
- Use `add_allowed_destination("10.0.0.100")`.
- Safety Guard: `"0.0.0.0/0"` and `"::/0"` are explicitly rejected.

### 3. IP Pair Allowlisting
The most precise method: Allow specific Source -> Destination traffic.
- Example: Allow Vulnerability Scanner (10.1.1.50) to scan Web Server (10.0.0.80).

### 4. Rule ID Allowlisting
Disable specific noisy rules globally.
- Example: Disable `network_scan_horizontal` entirely if you rely on an external SIEM for it.

## Best Practices
1. **Prefer IP Pairs over Source/Dest**: Only allow the scanner to touch what it needs to touch.
2. **Tune Thresholds First**: Before suppressing an entire subnet, consider increasing `MIN_EVENTS` or `MIN_DISTINCT_TARGETS` in `.env` if normal traffic is triggering rules.
3. **Use CIDR**: You can allowlist `/24` or `/16` ranges for large internal segments.
