import logging
from collections.abc import Mapping
from typing import Any

import jwt

from agent.application.authentication import (
    AuthenticatedPrincipal,
    AuthenticationRequiredError,
)
from agent.security.oidc import (
    OidcConfiguration,
    OidcProviderError,
    SigningKeyResolver,
)

logger = logging.getLogger(__name__)

MAX_TOKEN_LENGTH = 16 * 1024
MAX_SUBJECT_LENGTH = 512
MAX_DISPLAY_NAME_LENGTH = 120
MAX_EXTERNAL_ROLES = 100
MAX_EXTERNAL_ROLE_LENGTH = 128
SUPPORTED_TOKEN_TYPES = frozenset({"jwt", "at+jwt"})


class OidcJwtAuthenticationService:
    """Validates externally issued access tokens and maps trusted roles."""

    def __init__(
        self,
        configuration: OidcConfiguration,
        signing_key_resolver: SigningKeyResolver,
    ):
        self.configuration = configuration
        self.signing_key_resolver = signing_key_resolver

    def authenticate(self, token: str) -> AuthenticatedPrincipal:
        try:
            return self._authenticate(token)
        except OidcProviderError:
            logger.warning("oidc_provider_unavailable")
        except (jwt.PyJWTError, TypeError, ValueError):
            logger.warning("oidc_authentication_failed")
        raise AuthenticationRequiredError() from None

    def _authenticate(self, token: str) -> AuthenticatedPrincipal:
        if (
            not token
            or len(token) > MAX_TOKEN_LENGTH
            or len(token.split(".")) != 3
            or any(not part for part in token.split("."))
        ):
            raise ValueError("jwt_structure_invalid")

        header = jwt.get_unverified_header(token)
        algorithm = header.get("alg")
        key_id = header.get("kid")
        token_type = header.get("typ")
        if (
            not isinstance(algorithm, str)
            or algorithm not in self.configuration.allowed_algorithms
            or algorithm.lower() == "none"
            or algorithm.startswith("HS")
            or not isinstance(key_id, str)
            or not key_id
        ):
            raise ValueError("jwt_header_invalid")
        if token_type is not None and (
            not isinstance(token_type, str)
            or token_type.lower() not in SUPPORTED_TOKEN_TYPES
        ):
            raise ValueError("jwt_type_invalid")

        signing_key = self.signing_key_resolver.resolve(key_id, algorithm)
        claims = jwt.decode(
            token,
            key=signing_key,
            algorithms=list(self.configuration.allowed_algorithms),
            audience=self.configuration.audience,
            issuer=self.configuration.issuer,
            leeway=self.configuration.clock_skew_seconds,
            options={
                "require": ["exp", "sub"],
                "verify_signature": True,
                "verify_exp": True,
                "verify_nbf": True,
                "verify_iss": True,
                "verify_aud": True,
            },
        )
        if not isinstance(claims, dict):
            raise ValueError("jwt_claims_invalid")

        subject = claims.get("sub")
        if (
            not isinstance(subject, str)
            or not subject.strip()
            or len(subject) > MAX_SUBJECT_LENGTH
        ):
            raise ValueError("jwt_subject_invalid")
        token_use = claims.get("token_use")
        if token_use is not None and token_use != "access":
            raise ValueError("jwt_token_use_invalid")

        roles = self._map_roles(claims)
        display_name = self._display_name(claims)
        return AuthenticatedPrincipal(
            subject_type="human_user",
            subject_id=subject,
            display_name=display_name,
            authentication_method="oidc_jwt",
            roles=roles,
            credential_id=None,
        )

    def _map_roles(self, claims: Mapping[str, Any]) -> tuple[str, ...]:
        external_roles_value = claims.get(self.configuration.roles_claim, [])
        if isinstance(external_roles_value, str):
            external_roles = [external_roles_value]
        elif isinstance(external_roles_value, list) and all(
            isinstance(role, str) for role in external_roles_value
        ):
            external_roles = external_roles_value
        else:
            raise ValueError("jwt_roles_invalid")

        if len(external_roles) > MAX_EXTERNAL_ROLES or any(
            not role or len(role) > MAX_EXTERNAL_ROLE_LENGTH
            for role in external_roles
        ):
            raise ValueError("jwt_roles_invalid")

        role_mapping = dict(self.configuration.role_mapping)
        mapped_roles: list[str] = []
        for external_role in external_roles:
            internal_role = role_mapping.get(external_role)
            if internal_role is not None and internal_role not in mapped_roles:
                mapped_roles.append(internal_role)
        return tuple(mapped_roles)

    def _display_name(self, claims: Mapping[str, Any]) -> str:
        value = claims.get(self.configuration.display_name_claim)
        if not isinstance(value, str) or not value.strip():
            return "OIDC user"
        return value.strip()[:MAX_DISPLAY_NAME_LENGTH]

    def check_provider(self) -> None:
        self.signing_key_resolver.check_available()
