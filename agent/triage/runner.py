import time
from typing import Any, Optional
from agent.models import IncidentState
from agent.triage.models import TriageRunResult, TriageMetrics
from agent.triage.enums import ReviewReason
from agent.triage.provider import TriageProvider, TriageProviderRequest
from agent.triage.input_builder import build_triage_input
from agent.triage.prompt_builder import build_system_prompt, TRIAGE_PROMPT_VERSION
from agent.triage.exceptions import TriageProviderError
from agent.triage.cache import TriageCache, build_cache_key
from agent.config import get_settings

class TriageRunner:
    def __init__(self, provider: TriageProvider, cache: Optional[TriageCache] = None):
        self.provider = provider
        self.cache = cache
        self.settings = get_settings()

    def run(self, state: IncidentState, bundle: Any) -> TriageRunResult:
        start_time = time.monotonic()
        
        # 1. Build TriageInput
        triage_input = build_triage_input(
            bundle=bundle,
            detected_signals=state.get("detected_signals", []),
            candidate_evidence=state.get("candidate_evidence", [])
        )
        
        state["safe_triage_input"] = triage_input.model_dump()
        
        # 2. Check Cache
        if self.cache:
            cache_key = build_cache_key(
                incident_id=bundle.incident_id,
                incident_content_hash=str(hash(triage_input.model_dump_json())),
                model=self.settings.llm_model,
                provider="groq",
                prompt_version=TRIAGE_PROMPT_VERSION,
                schema_version="1.0"
            )
            state["cache_key"] = cache_key
            cached_result = self.cache.get(cache_key)
            if cached_result:
                cached_result.metrics.cache_hit = True
                return cached_result

        # Initialize Metrics
        metrics = TriageMetrics(
            incident_id=bundle.incident_id,
            provider="groq",
            model=self.settings.llm_model,
            prompt_version=TRIAGE_PROMPT_VERSION,
            schema_version="1.0",
            started_at=time.time().__str__(),
            completed_at=""
        )

        system_prompt = build_system_prompt(triage_input)
        request = TriageProviderRequest(
            incident_id=bundle.incident_id,
            triage_input=triage_input,
            system_prompt=system_prompt,
            context={"triage_input": triage_input}
        )
        
        # 3. Invoke Provider
        try:
            response = self.provider.invoke(request)
            
            metrics.provider_prompt_tokens = response.prompt_tokens
            metrics.provider_completion_tokens = response.completion_tokens
            metrics.total_tokens = response.prompt_tokens + response.completion_tokens
            
            # The provider should abstract away the tool loops internally,
            # or if graph handles loops, the provider does 1 step. 
            # To meet phase 4 bounded requirements without infinite graph loops,
            # the Fake/Groq provider will handle search limit loops securely.
            
            result = TriageRunResult(
                submission=response.submission,
                review_reason=ReviewReason.NONE if response.submission else ReviewReason.INVALID_LLM_OUTPUT,
                metrics=metrics,
                search_results=[] # provider can return them if it wants
            )
            
        except TriageProviderError as e:
            metrics.fallback_used = True
            metrics.review_reason = e.review_reason
            result = TriageRunResult(
                submission=None,
                review_reason=e.review_reason,
                metrics=metrics
            )
        except Exception:
            metrics.fallback_used = True
            metrics.review_reason = ReviewReason.PROVIDER_UNAVAILABLE
            result = TriageRunResult(
                submission=None,
                review_reason=ReviewReason.PROVIDER_UNAVAILABLE,
                metrics=metrics
            )
            
        metrics.completed_at = time.time().__str__()
        metrics.latency_ms = (time.monotonic() - start_time) * 1000.0
        
        # 4. Save to cache if valid
        if self.cache and result.submission and result.review_reason == ReviewReason.NONE:
            self.cache.set(state["cache_key"], result, ttl_seconds=3600)
            
        return result
