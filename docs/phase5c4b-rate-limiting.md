# Phase 5C.4B: rate limiting and abuse protection

Phase 5C.4B adds transient, centralized abuse protection around the existing
API-key, OIDC/JWT, hybrid-authentication, RBAC, job, request-boundary, error,
and health behavior. Together with the preceding authentication,
authorization, OIDC, and API-boundary phases, this completes Phase 5C.

It does not add account lockout, login, token issuance, billing quotas,
tenant quotas, ownership, UI, observability export, or deployment resources.

## Categories and defaults

All policies are server configuration. Headers, query parameters, request
bodies, JWT claims, and display names cannot select a backend or change a
limit.

| Category | Default | Applies to |
| --- | ---: | --- |
| `general` | 120 requests / 60 seconds | Anonymous broad ceiling for non-health application requests |
| `authentication_failure` | 10 failures / 60 seconds | Missing, malformed, invalid, revoked, or expired protected-route credentials |
| `job_submission` | 5 submissions / 60 seconds | Versioned and legacy synchronous or asynchronous analysis submissions |
| `mutation` | 30 mutations / 60 seconds | Cancellation, incident status changes, and other protected writes |
| `read` | 120 reads / 60 seconds | Jobs, incidents, reports, audit timelines, and workers |
| `documentation` | 120 requests / 60 seconds | OpenAPI, Swagger UI, and ReDoc when enabled |

`documentation` uses the configured general limit and window. Health probes
at `GET /health/live` and `GET /health/ready` bypass both anonymous and
principal counters. They do not invoke analysis or other expensive business
logic.

Enforcement order is:

1. the deployment boundary and broad anonymous ceiling;
2. one cached authentication operation;
3. the principal category limit;
4. existing centralized RBAC;
5. endpoint business logic.

When more than one decision applies, the response exposes only the most
restrictive remaining allowance. Headers are assigned rather than appended,
so duplicate rate-limit headers are not emitted.

## Identities and secret-safe keys

Successfully authenticated requests use `subject_type`, the verified
`subject_id`, and `authentication_method`. API-key and OIDC principals have
independent buckets in hybrid mode. User-controlled display names are not an
identity input.

Unauthenticated broad limits and authentication failures use a trusted client
address representation. The direct socket address is used by default.
`Forwarded` or `X-Forwarded-For` is considered only when forwarded headers are
enabled and the direct peer is in `TRUSTED_PROXY_IPS`. Untrusted forwarded
headers are ignored. IPv4 and IPv6 are normalized; malformed or conflicting
values use a non-identifying `anonymous` bucket.

No raw identifier is a Redis key. The server serializes the normalized
identity and category and applies HMAC-SHA256 with `RATE_LIMIT_KEY_SECRET`.
Redis receives only `RATE_LIMIT_PREFIX` and the hexadecimal HMAC digest. Raw
API keys, JWTs, authorization headers, IP addresses, subject IDs, usernames,
email addresses, URLs, filenames, and request bodies do not appear in stored
keys. Python's process-randomized `hash()` is not used.

The production HMAC secret must be explicit, independently generated, and at
least 32 bytes. Rotating it intentionally starts fresh transient buckets.

## Backends and algorithm

`RATE_LIMIT_BACKEND=memory` uses a locked, process-local fixed-window counter.
It is deterministic for tests and convenient for one-process development, but
resets on restart and cannot enforce a combined limit across workers.
Production validation rejects it.

`RATE_LIMIT_BACKEND=redis` uses a separate `soc-rate-limit` key namespace and
one Lua operation per decision. The script increments the counter, creates or
repairs a bounded TTL, and caps its stored value atomically. Counters expire;
the implementation does not use SQL, `KEYS`, `FLUSHDB`, or Redis as a
permanent result store. The same Redis service may be shared with Celery, but
the rate-limit prefix is independent of broker, queue, and future cache keys.

Fixed windows can permit a boundary burst when traffic arrives immediately
before and after a window boundary. That known limitation is accepted for
this phase; limits are still atomic within each window.

There is no silent Redis-to-memory fallback. A Redis backend failure returns a
sanitized 503 for protected application traffic. Production also requires
`RATE_LIMITING_ENABLED=true`, `RATE_LIMIT_FAIL_CLOSED=true`, a Redis backend,
and the explicit HMAC secret. The Redis URL, host, port, database number,
credentials, and exception text are not returned or logged.

## Public response contracts

An exceeded limit returns HTTP 429:

```json
{
  "code": "rate_limited",
  "message": "Too many requests. Please retry later."
}
```

The response includes bounded numeric `Retry-After`, `X-RateLimit-Limit`,
`X-RateLimit-Remaining`, and `X-RateLimit-Reset` headers. The existing
deployment middleware also supplies `X-Request-ID` and the Phase 5C.4A
security headers. Rate-limited successful application responses include the
three `X-RateLimit-*` headers. Health responses need no rate-limit headers.

An unavailable configured backend returns HTTP 503:

```json
{
  "code": "rate_limit_unavailable",
  "message": "The request cannot be processed at this time."
}
```

Neither contract reveals a category, bucket key, IP address, principal,
credential, Redis location, or internal configuration.

## Authentication abuse behavior

Every protected-route authentication failure consumes the trusted
client-address failure bucket. Missing credentials, malformed Bearer values,
invalid API keys, revoked or expired API keys, and invalid, expired,
wrong-issuer, wrong-audience, unknown-key, or bad-signature JWTs retain the
same public 401 contract before the threshold and the same generic 429 after
it.

Authentication is a cached FastAPI dependency, so an API key or JWT is not
validated twice in one request. Successful requests do not consume, inspect,
or extend the failure bucket; valid credentials from the same source continue
to work. Failure counters expire with their window and do not change credential
or identity records. The API does not revoke keys or lock users automatically.

The external OIDC provider remains responsible for brute-force protection of
its own interactive login. This resource server limits only calls made to this
API.

## Submission and mutation safety

The `job_submission` dependency runs before local staging, application-level
hashing, `IngestionJob` creation, queue publication, synchronous analysis, or
provider calls. It covers `/api/v1/analysis-jobs/file`, `/ingest/file`,
`/detect/file`, `/analyze/file`, and `/analyze`; an unversioned route is not a
bypass. A denied submission leaves no new staged file, job, Celery message,
analysis call, or mutation audit event.

The `mutation` dependency runs before cancellation and incident lifecycle
logic. A denied operation cannot change job status or attempt count, incident
status or version, publish a task, remove a staging object, or create a
mutation audit record. Rate limiting is independent of RBAC: viewers remain
denied, and analysts or administrators still need their existing permission.
Read and mutation buckets are separate.

## Readiness and operations

When limiting is enabled, readiness adds only `rate_limiter=up` or
`rate_limiter=down`. Memory reports up without network access. Redis performs
a bounded `PING`. A failure makes readiness HTTP 503 without exposing
connection details. Liveness remains HTTP 200 and never depends on Redis.

Exceeded limits and backend failures use sanitized structured operational
events: `rate_limit_exceeded`, `authentication_rate_limit_exceeded`,
`job_submission_rate_limit_exceeded`, `mutation_rate_limit_exceeded`, and
`rate_limit_backend_unavailable`. Allowed context is the category, request ID,
route identifier, authentication method, and authenticated subject type. The
events exclude subject IDs, credentials, claims, authorization headers,
addresses, bodies, filenames, and raw backend errors. A database `AuditEvent`
is deliberately not created for every rejected request. Formal metrics and
telemetry export remain Phase 6 work.

## Configuration reference

```dotenv
RATE_LIMITING_ENABLED=true
RATE_LIMIT_BACKEND=redis
RATE_LIMIT_REDIS_URL=redis://localhost:6379/1
RATE_LIMIT_KEY_SECRET=replace-with-an-independent-random-secret-of-32-plus-bytes
RATE_LIMIT_GENERAL_REQUESTS=120
RATE_LIMIT_GENERAL_WINDOW_SECONDS=60
RATE_LIMIT_AUTH_FAILURES=10
RATE_LIMIT_AUTH_FAILURE_WINDOW_SECONDS=60
RATE_LIMIT_JOB_SUBMISSIONS=5
RATE_LIMIT_JOB_SUBMISSION_WINDOW_SECONDS=60
RATE_LIMIT_MUTATIONS=30
RATE_LIMIT_MUTATION_WINDOW_SECONDS=60
RATE_LIMIT_READS=120
RATE_LIMIT_READ_WINDOW_SECONDS=60
RATE_LIMIT_PREFIX=soc-rate-limit
RATE_LIMIT_FAIL_CLOSED=true
```

The URL and secret above are placeholders only. Production operators must
provide their own protected values. Billing quotas, per-tenant quotas, and
multi-tenancy are intentionally absent.
