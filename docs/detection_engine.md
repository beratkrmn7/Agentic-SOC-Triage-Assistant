# Phase 3 Detection and Correlation Engine

The Phase 3 Detection and Correlation engine replaces heuristic scripts with a deterministic, testable, robust, and extensible rules engine focused on generating low-false-positive `IncidentBundle` objects.

## Architecture

Data flows through the following stages:

1. **Eligibility Check**: Filters out logs without a timestamp or necessary identifiers.
2. **Rule Evaluation**: A `RuleRegistry` loads all implementations of `BaseDetectionRule`. Each rule evaluates the log sequence using `sliding_window_scan` and generates `DetectionSignal` objects.
3. **Signal Deduplication**: Redundant, identical signals across multiple windows are pruned.
4. **Signal Suppression**: Allows IP whitelisting to silently discard acceptable traffic (e.g. Vuln Scanners).
5. **Correlation & Incident Merging**: `DetectionSignal` objects related to the same primary entity or matching keys are merged into `IncidentBundle` objects.

## Rule Development

To create a new rule, extend `BaseDetectionRule` from `agent.detection.detectors.base`.

```python
from agent.detection.detectors.base import BaseDetectionRule, DetectionContext

class CustomRule(BaseDetectionRule):
    rule_id = "custom_rule"
    version = "1.0.0"
    name = "Custom Rule"
    family = "custom"
    priority = 100

    def evaluate(self, events, context: DetectionContext):
        # Implementation...
        return signals
```

The system includes pre-built rules for:
- Horizontal Scan
- Vertical Scan
- Remote Service Probe (SSH/RDP)
- Network Flood (DoS)
- SPI Anomaly Burst

## Determinism

Incidents and signals use a deterministic hashing mechanism (`generate_signal_id`, `generate_incident_id`) based on entities, temporal bounds, and correlated events. This ensures that processing the exact same batch of logs repeatedly produces exactly the same incidents.

## APIs

The Detection Engine runs automatically before the LLM triage agent is invoked, passing deterministically discovered `signals` and `candidate_evidence` to the LangGraph state.

A standalone `POST /detect/file` endpoint and `--detect-file` CLI option are available for testing detection logic without invoking LLM tokens.
