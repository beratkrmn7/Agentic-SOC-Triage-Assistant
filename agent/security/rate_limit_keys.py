from __future__ import annotations

import hashlib
import hmac
import json


class RateLimitKeyBuilder:
    """Builds stable opaque keys without placing identity data in the store."""

    def __init__(self, *, secret: bytes, prefix: str):
        if len(secret) < 32:
            raise ValueError("rate_limit_key_secret_too_short")
        self._secret = secret
        self._prefix = prefix

    def for_principal(
        self,
        *,
        subject_type: str,
        subject_id: str,
        authentication_method: str,
        category: str,
    ) -> str:
        return self._key({
            "identity_kind": "principal",
            "subject_type": subject_type,
            "subject_id": subject_id,
            "authentication_method": authentication_method,
            "category": category,
        })

    def for_anonymous(self, *, client_address: str, category: str) -> str:
        return self._key({
            "identity_kind": "anonymous",
            "client_address": client_address,
            "category": category,
        })

    def _key(self, components: dict[str, str]) -> str:
        payload = json.dumps(
            components,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
        digest = hmac.new(self._secret, payload, hashlib.sha256).hexdigest()
        return f"{self._prefix}:{digest}"
