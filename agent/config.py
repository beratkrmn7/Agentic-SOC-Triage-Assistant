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

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")

@lru_cache
def get_settings() -> Settings:
    return Settings()
