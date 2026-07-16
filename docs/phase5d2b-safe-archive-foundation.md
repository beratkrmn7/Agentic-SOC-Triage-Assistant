# Phase 5D.2B — Safe archive foundation

## Purpose and safety boundary

This phase adds a non-destructive operational retention archive. It exports the
same candidates reported by the retention dry-run planner, includes the bounded
dependency closure needed for structural recovery, and verifies the completed
artifact before reporting success. It does not delete database rows,
association rows, or staging files. `retention --execute` remains unsupported.

The archive is deliberately not a raw-log or forensic backup. Operational
fields needed for identification, relationships, and a limited restore smoke
test are retained. Raw records, unrestricted metadata, prompts/responses,
exception text, credentials, and private paths are excluded.

## Storage design

`ArchiveStore` is a streaming storage protocol. It starts a workspace, opens
payload writers/readers, writes the manifest, atomically finalizes an artifact,
checks existence, and aborts partial work. The interface never accepts an
entire archive as one in-memory byte string.

`LocalArchiveStore` is the first implementation. It uses strict
`ARC-<32 lowercase hex>` identifiers, a fixed filename allowlist, containment
checks, symlink rejection, exclusive file creation, and same-filesystem atomic
rename from `.partial/<archive-id>` to `<archive-id>`. A completed archive is
never overwritten. On supported POSIX systems directories use mode `0700` and
files use `0600`. The configured root is never printed or persisted as an
absolute storage key.

Local archives are not encrypted. Production object storage, encryption, key
management, and remote durability controls are later production-hardening work.

## Configuration

```text
RETENTION_ARCHIVE_BACKEND=local
RETENTION_ARCHIVE_ROOT=./var/retention-archives
RETENTION_ARCHIVE_BATCH_SIZE=1000
RETENTION_ARCHIVE_SCHEMA_VERSION=retention-archive/v1
```

The batch size is restricted to `1..10000`. The local archive root must not be
the staging root. Only the `local` backend and `retention-archive/v1` record
schema are accepted in this phase.

## Archive format

Each archive is a directory containing:

```text
manifest.json
manifest.sha256
canonical_events.ndjson.gz
detection_signals.ndjson.gz
ingestion_jobs.ndjson.gz
incidents.ndjson.gz
audit_events.ndjson.gz
dependent_records.ndjson.gz
```

Payloads are UTF-8 NDJSON compressed with streaming gzip. Every line is a
typed `retention-archive/v1` envelope with an entity type, entity ID,
`retention_candidate` or `dependency` role, UTC record timestamp, and an
explicitly allowlisted data object. JSON keys and separators are canonical;
gzip uses `mtime=0` for deterministic bytes. Line and field sizes are bounded.

The SHA-256 recorded for a payload is calculated over its final compressed
bytes. Compressed and uncompressed byte counts are recorded separately.

## Manifest V1

`retention-archive-manifest/v1` records the archive ID, policy version,
creation/completion/as-of timestamps, all retention cutoffs, gzip/NDJSON/SHA-256
algorithms, producer version, safety profile, and the ordered payload list.
Each payload entry contains its relative filename, allowed entity types,
candidate/dependency/total counts, compressed/uncompressed sizes, compressed
SHA-256, and oldest/newest record timestamps. Archive-wide candidate,
dependency, and total counts are cross-checked against payload totals.

Safety markers are fixed to `contains_raw_logs=false` and
`contains_credentials=false`. The manifest contains no absolute paths, URLs,
candidate ID lists, raw exceptions, prompts, or credentials. `manifest.json`
is canonical JSON, and `manifest.sha256` contains only the checksum of those
exact manifest bytes.

## Candidate and dependency handling

Retention aggregation and archive iteration use the same centralized
eligibility specifications. A single `archive_as_of`, policy, and cutoff set is
used for both the plan and export. Candidate iteration is ordered by
`(timestamp, primary key)` and uses bounded keyset pages; it does not use a
large offset or collect all IDs in Python memory.

Incident dependencies include triage runs, evidence, reports, and incident
event/signal associations. Job dependencies include job event/signal/incident
associations. Referenced event, signal, incident, or job roots that are not
themselves candidates are emitted as `dependency`. Database unions/distinct
queries and deterministic keys prevent duplicate dependency output. Being a
dependency does not make a record eligible for later deletion.

## Explicit safe allowlist

Serializers name every archived field. They exclude raw event text,
`safe_message_excerpt`, `original_fields`, original upload filenames,
arbitrary metrics/details/error dictionaries, evidence quotes, report content,
triage messages/search history/errors/token usage, provider prompt/response,
database and Redis URLs, staging paths, API keys, JWTs, Authorization headers,
and raw exception text. Bounded scalar labels are sanitized; unsafe values are
redacted or rejected by the typed archive schema.

Operational restore can therefore recreate safe roots and relationships, but
excluded sensitive/raw fields are absent or use safe database defaults. This is
an intentional safety property, not full forensic fidelity.

## Lifecycle, verification, and failures

`RetentionArchiveRun` stores one row per run with an opaque archive ID/storage
key, versions, as-of timestamp, `creating/completed/verified/failed` status,
manifest checksum, safe counts, timestamps, and a controlled error code. It
does not store per-record membership or exception messages. Audit output is
limited to started/completed/verified/failed summary events with safe counts.

Creation writes into `.partial`, verifies all bytes there, records completed
metadata, atomically exposes the directory, and records verified metadata. A
pre-finalization failure aborts partial work, marks the run failed, and never
changes source data. If the artifact is atomically exposed but the last metadata
update fails, the completed artifact and `completed` run remain recoverable for
a later explicit verify operation.

Verification checks the exact file set, manifest schema and sidecar, canonical
manifest bytes, payload checksums and sizes, complete gzip streams, every typed
NDJSON line, roles/entity allowlists, counts, timestamp ranges, and duplicate
`(entity_type, entity_id)` keys. Duplicate detection uses a temporary SQLite
index rather than an unbounded Python set.

## Commands

Create and verify a new non-destructive archive:

```shell
python -m agent.maintenance.archive create
```

Verify a known archive by its opaque identifier:

```shell
python -m agent.maintenance.archive verify --archive-id ARC-0123456789abcdef0123456789abcdef
```

Both commands print only a safe summary. They accept no arbitrary output path.
Invalid IDs are rejected before database or storage access. Integrity,
not-found, and operational failures use generic messages and non-zero exit
codes.

## Deferred to Phase 5D.2C

Database and association deletion, rechecking eligibility before cleanup,
resumable cleanup cursors, staging cleanup, production restore tooling,
OpenSearch cleanup, scheduled/Celery execution, public APIs, object storage,
encryption, and deployment/UI work are not part of this phase.
