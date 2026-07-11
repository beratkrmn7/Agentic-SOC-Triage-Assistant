from typing import Protocol, Optional
from agent.triage.models import TriageRunResult
import time
import hashlib
import json
import threading
import copy

class TriageCache(Protocol):
    def get(self, key: str) -> Optional[TriageRunResult]:
        ...
    def set(self, key: str, value: TriageRunResult, ttl_seconds: int) -> None:
        ...

class InMemoryTriageCache(TriageCache):
    def __init__(self):
        self._store = {}
        self._lock = threading.Lock()
        
    def get(self, key: str) -> Optional[TriageRunResult]:
        with self._lock:
            if key in self._store:
                item, expires_at = self._store[key]
                if time.time() < expires_at:
                    # Return a deep copy to prevent mutation of cached object
                    return copy.deepcopy(item)
                else:
                    del self._store[key]
        return None
        
    def set(self, key: str, value: TriageRunResult, ttl_seconds: int = 3600) -> None:
        with self._lock:
            self._store[key] = (copy.deepcopy(value), time.time() + ttl_seconds)

def build_cache_key(
    incident_id: str,
    incident_content_hash: str,
    model: str,
    provider: str,
    prompt_version: str,
    schema_version: str,
    validation_policy_version: str = "1.0"
) -> str:
    cache_dict = {
        "incident_id": incident_id,
        "incident_content_hash": incident_content_hash,
        "model": model,
        "provider": provider,
        "prompt_version": prompt_version,
        "schema_version": schema_version,
        "validation_policy_version": validation_policy_version
    }
    # Stable, sorted JSON serialization
    serialized = json.dumps(cache_dict, sort_keys=True, separators=(',', ':'))
    return hashlib.sha256(serialized.encode('utf-8')).hexdigest()
