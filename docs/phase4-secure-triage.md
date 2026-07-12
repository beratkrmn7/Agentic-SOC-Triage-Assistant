# Phase 4: Secure Agentic Triage

This document outlines the Phase 4 Secure Agentic Triage architecture, providing strict boundaries, idempotency, and deterministic validation for LLM operations.

## Architecture

1. **Centralized Settings (`agent/config.py`)**
   - Implements global limits, token restrictions, and circuit breaker configurations using Pydantic `BaseSettings`.
   
2. **Deterministic Evidence Validation (`agent/triage/validation.py`)**
   - Validates candidate IDs, event scope, exact quote matches, and field-level original log parity.
   
3. **Resilient Provider (`agent/triage/groq_provider.py`)**
   - Includes Circuit Breaker pattern.
   - Retries with exponential backoff.
   - Idempotent `MAX_AGENT_ITERATIONS` limit.
   - Bounded Tool (`SearchLogsTool`).

4. **Deterministic Hash Caching (`agent/triage/cache.py`)**
   - Generates SHA-256 hash from incident content.
   - Protects token budgets by serving deep-copied results for unchanged requests.
