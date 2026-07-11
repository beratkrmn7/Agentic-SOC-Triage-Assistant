from typing import Protocol, Optional
from agent.triage.models import TriageRunResult
import time

class TriageCache(Protocol):
    def get(self, key: str) -> Optional[TriageRunResult]:
        ...
    def set(self, key: str, value: TriageRunResult, ttl_seconds: int) -> None:
        ...

class InMemoryTriageCache(TriageCache):
    def __init__(self):
        self._store = {}
        
    def get(self, key: str) -> Optional[TriageRunResult]:
        if key in self._store:
            item, expires_at = self._store[key]
            if time.time() < expires_at:
                return item
            else:
                del self._store[key]
        return None
        
    def set(self, key: str, value: TriageRunResult, ttl_seconds: int = 3600) -> None:
        self._store[key] = (value, time.time() + ttl_seconds)

def build_cache_key(
    incident_id: str,
    incident_content_hash: str,
    model: str,
    provider: str,
    prompt_version: str,
    schema_version: str
) -> str:
    import hashlib
    key_input = f"{incident_id}|{incident_content_hash}|{model}|{provider}|{prompt_version}|{schema_version}"
    return hashlib.sha256(key_input.encode('utf-8')).hexdigest()
