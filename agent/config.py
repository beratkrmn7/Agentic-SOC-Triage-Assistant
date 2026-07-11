from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import SecretStr, Field
from agent.ingestion.limits import IngestionLimits
from typing import Literal, Optional
from functools import lru_cache

class Settings(BaseSettings):
    app_env: str = "development"
    log_level: str = "INFO"

    llm_enabled: bool = True
    llm_provider: Literal["groq"] = "groq"
    llm_model: str = "llama-3.3-70b-versatile"
    groq_api_key: Optional[SecretStr] = None

    llm_parser_fallback_enabled: bool = False

    ingestion: IngestionLimits = Field(default_factory=IngestionLimits)

    # Phase 4: Secure Agentic Triage Settings
    max_agent_iterations: int = 5
    max_search_calls: int = 3
    max_search_results: int = 10
    max_search_query_chars: int = 100
    max_prompt_tokens: int = 30000
    max_completion_tokens: int = 2000
    max_context_events: int = 50
    max_candidate_evidence: int = 20
    max_event_preview_chars: int = 1000
    triage_timeout_seconds: int = 120
    llm_max_retries: int = 3
    llm_retry_base_seconds: float = 1.0
    llm_retry_max_seconds: float = 10.0
    circuit_breaker_failure_threshold: int = 5
    circuit_breaker_reset_seconds: int = 60
    triage_cache_enabled: bool = True
    triage_cache_ttl_seconds: int = 3600
    triage_prompt_version: str = "1.0.0"
    triage_schema_version: str = "1.0.0"

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")

@lru_cache
def get_settings() -> Settings:
    return Settings()
