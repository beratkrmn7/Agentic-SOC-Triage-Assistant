"""add structured search indexes

Revision ID: 5d1a9c2e7f40
Revises: c7d9e2a4b6f1
Create Date: 2026-07-16
"""

from collections.abc import Sequence

from alembic import op


revision: str = "5d1a9c2e7f40"
down_revision: str | Sequence[str] | None = "c7d9e2a4b6f1"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


INDEXES: tuple[tuple[str, str, list[str]], ...] = (
    ("ix_incidents_created_id", "incidents", ["created_at", "incident_id"]),
    ("ix_incidents_status_created", "incidents", ["status", "created_at"]),
    ("ix_incidents_severity_created", "incidents", ["severity", "created_at"]),
    ("ix_incidents_type_created", "incidents", ["incident_type", "created_at"]),
    ("ix_incidents_first_seen_id", "incidents", ["first_seen", "incident_id"]),
    ("ix_incidents_last_seen_id", "incidents", ["last_seen", "incident_id"]),
    (
        "ix_canonical_events_timestamp_id",
        "canonical_events",
        ["timestamp", "event_id"],
    ),
    (
        "ix_canonical_events_src_timestamp",
        "canonical_events",
        ["src_ip", "timestamp"],
    ),
    (
        "ix_canonical_events_dst_timestamp",
        "canonical_events",
        ["dst_ip", "timestamp"],
    ),
    (
        "ix_canonical_events_source_timestamp",
        "canonical_events",
        ["source_name", "timestamp"],
    ),
    (
        "ix_detection_signals_created_id",
        "detection_signals",
        ["created_at", "signal_id"],
    ),
    (
        "ix_detection_signals_rule_created",
        "detection_signals",
        ["rule_id", "created_at"],
    ),
    (
        "ix_detection_signals_severity_created",
        "detection_signals",
        ["severity", "created_at"],
    ),
    (
        "ix_detection_signals_first_seen_id",
        "detection_signals",
        ["first_seen", "signal_id"],
    ),
    (
        "ix_detection_signals_last_seen_id",
        "detection_signals",
        ["last_seen", "signal_id"],
    ),
    (
        "ix_detection_signals_suppressed_created",
        "detection_signals",
        ["suppressed", "created_at"],
    ),
    (
        "ix_ingestion_jobs_created_id",
        "ingestion_jobs",
        ["created_at", "id"],
    ),
    (
        "ix_ingestion_jobs_status_created",
        "ingestion_jobs",
        ["status", "created_at"],
    ),
    (
        "ix_ingestion_jobs_mode_created",
        "ingestion_jobs",
        ["analysis_mode", "created_at"],
    ),
    (
        "ix_ingestion_jobs_completed_id",
        "ingestion_jobs",
        ["completed_at", "id"],
    ),
    (
        "ix_ingestion_jobs_source_created",
        "ingestion_jobs",
        ["source_name", "created_at"],
    ),
)


def upgrade() -> None:
    for name, table, columns in INDEXES:
        op.create_index(name, table, columns, unique=False)


def downgrade() -> None:
    for name, table, _columns in reversed(INDEXES):
        op.drop_index(name, table_name=table)
