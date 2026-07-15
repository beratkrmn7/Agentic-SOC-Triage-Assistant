from collections.abc import Sequence
from ipaddress import ip_address
import re
from typing import Any
import uuid

from starlette.datastructures import MutableHeaders
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from agent.config import Settings


CORS_ALLOWED_METHODS = ("GET", "POST", "PATCH", "OPTIONS")
CORS_ALLOWED_HEADERS = (
    "Accept",
    "Authorization",
    "Content-Type",
    "If-Match",
    "X-Request-ID",
)
REQUEST_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$")
API_CONTENT_SECURITY_POLICY = (
    "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; "
    "form-action 'none'"
)
DOCS_CONTENT_SECURITY_POLICY = (
    "default-src 'none'; script-src 'self' https://cdn.jsdelivr.net; "
    "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
    "img-src 'self' data: https://fastapi.tiangolo.com; "
    "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; "
    "form-action 'none'"
)


def _header_values(scope: Scope, name: bytes) -> list[str]:
    values: list[str] = []
    for raw_name, raw_value in scope.get("headers", []):
        if raw_name.lower() != name:
            continue
        try:
            values.append(raw_value.decode("ascii"))
        except UnicodeDecodeError:
            return []
    return values


def _hostname_from_host_header(value: str) -> str | None:
    if not value or any(ord(character) < 33 for character in value):
        return None

    if value.startswith("["):
        closing_bracket = value.find("]")
        if closing_bracket < 0:
            return None
        hostname = value[1:closing_bracket]
        suffix = value[closing_bracket + 1:]
        if suffix and (not suffix.startswith(":") or not suffix[1:].isdigit()):
            return None
        if suffix and not 0 < int(suffix[1:]) <= 65535:
            return None
        try:
            return str(ip_address(hostname))
        except ValueError:
            return None

    if value.count(":") > 1:
        return None
    hostname, separator, port = value.rpartition(":")
    if separator:
        if (
            not hostname
            or not port.isdigit()
            or not 0 < int(port) <= 65535
        ):
            return None
    else:
        hostname = value
    return hostname.lower().rstrip(".")


def _host_is_allowed(hostname: str, allowed_hosts: Sequence[str]) -> bool:
    for pattern in allowed_hosts:
        if pattern == "*" or hostname == pattern:
            return True
        if pattern.startswith("*.") and hostname.endswith(pattern[1:]):
            return True
    return False


class DeploymentBoundaryMiddleware:
    """Enforces trusted Host and HTTPS policy before API request handling."""

    def __init__(self, app: ASGIApp, settings: Settings):
        self.app = app
        self.allowed_hosts = tuple(settings.trusted_hosts)
        self.https_required = settings.https_required
        self.forwarded_headers_enabled = settings.forwarded_headers_enabled
        self.trusted_proxy_ips = frozenset(settings.trusted_proxy_ips)
        self.security_headers_enabled = settings.security_headers_enabled
        self.hsts_max_age_seconds = settings.hsts_max_age_seconds

    async def __call__(
        self,
        scope: Scope,
        receive: Receive,
        send: Send,
    ) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        request_id = self._request_id(scope)
        state = scope.setdefault("state", {})
        state["request_id"] = request_id
        effective_scheme = str(scope.get("scheme", "http")).lower()

        async def send_with_security_headers(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = MutableHeaders(scope=message)
                headers["X-Request-ID"] = request_id
                if self.security_headers_enabled:
                    headers["X-Content-Type-Options"] = "nosniff"
                    headers["X-Frame-Options"] = "DENY"
                    headers["Referrer-Policy"] = "no-referrer"
                    headers["Permissions-Policy"] = (
                        "camera=(), geolocation=(), microphone=(), "
                        "payment=(), usb=()"
                    )
                    headers["Cache-Control"] = "no-store"
                    headers["Content-Security-Policy"] = self._csp_for_scope(
                        scope
                    )
                    if (
                        self.https_required
                        and effective_scheme == "https"
                        and self.hsts_max_age_seconds > 0
                    ):
                        headers["Strict-Transport-Security"] = (
                            f"max-age={self.hsts_max_age_seconds}"
                        )
                    elif "strict-transport-security" in headers:
                        del headers["strict-transport-security"]
            await send(message)

        host_values = _header_values(scope, b"host")
        hostname = (
            _hostname_from_host_header(host_values[0])
            if len(host_values) == 1
            else None
        )
        if hostname is None or not _host_is_allowed(
            hostname,
            self.allowed_hosts,
        ):
            await self._send_error(
                scope,
                receive,
                send_with_security_headers,
                status_code=400,
                code="invalid_host",
                message="The request host is not allowed.",
            )
            return

        scheme = self._request_scheme(scope)
        if scheme is None:
            await self._send_error(
                scope,
                receive,
                send_with_security_headers,
                status_code=400,
                code="forwarded_scheme_invalid",
                message="The forwarded request scheme is invalid.",
            )
            return
        effective_scheme = scheme
        if self.https_required and scheme != "https":
            await self._send_error(
                scope,
                receive,
                send_with_security_headers,
                status_code=400,
                code="https_required",
                message="HTTPS is required.",
            )
            return

        await self.app(scope, receive, send_with_security_headers)

    @staticmethod
    def _request_id(scope: Scope) -> str:
        values = _header_values(scope, b"x-request-id")
        if len(values) == 1 and REQUEST_ID_PATTERN.fullmatch(values[0]):
            return values[0]
        return uuid.uuid4().hex

    @staticmethod
    def _csp_for_scope(scope: Scope) -> str:
        path = str(scope.get("path", ""))
        if path in {"/docs", "/docs/oauth2-redirect", "/redoc"}:
            return DOCS_CONTENT_SECURITY_POLICY
        return API_CONTENT_SECURITY_POLICY

    def _request_scheme(self, scope: Scope) -> str | None:
        scheme = str(scope.get("scheme", "http")).lower()
        if not self.forwarded_headers_enabled:
            return scheme

        client = scope.get("client")
        client_host = client[0] if client is not None else None
        if client_host not in self.trusted_proxy_ips:
            return scheme

        forwarded_proto = _header_values(scope, b"x-forwarded-proto")
        if not forwarded_proto:
            return scheme
        if len(forwarded_proto) != 1:
            return None
        normalized = forwarded_proto[0].lower()
        if normalized not in {"http", "https"}:
            return None
        return normalized

    @staticmethod
    async def _send_error(
        scope: Scope,
        receive: Receive,
        send: Send,
        *,
        status_code: int,
        code: str,
        message: str,
    ) -> None:
        response = JSONResponse(
            status_code=status_code,
            content={"code": code, "message": message},
        )
        await response(scope, receive, send)


def docs_urls(settings: Settings) -> dict[str, Any]:
    if settings.api_docs_enabled:
        return {
            "docs_url": "/docs",
            "redoc_url": "/redoc",
            "openapi_url": "/openapi.json",
        }
    return {"docs_url": None, "redoc_url": None, "openapi_url": None}
