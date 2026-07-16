"""add retention archive runs

Revision ID: 5d2b8f6a1c42
Revises: 5d2a7e4c9b31
Create Date: 2026-07-16
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op


revision: str = "5d2b8f6a1c42"
down_revision: str | Sequence[str] | None = "5d2a7e4c9b31"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "retention_archive_runs",
        sa.Column("archive_id", sa.String(length=45), nullable=False),
        sa.Column("policy_version", sa.String(length=32), nullable=False),
        sa.Column("schema_version", sa.String(length=64), nullable=False),
        sa.Column(
            "status",
            sa.String(length=16),
            server_default="creating",
            nullable=False,
        ),
        sa.Column("archive_as_of", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("verified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("storage_key", sa.String(length=64), nullable=False),
        sa.Column("manifest_sha256", sa.String(length=64), nullable=True),
        sa.Column(
            "candidate_record_count",
            sa.Integer(),
            server_default="0",
            nullable=False,
        ),
        sa.Column(
            "dependency_record_count",
            sa.Integer(),
            server_default="0",
            nullable=False,
        ),
        sa.Column(
            "total_record_count",
            sa.Integer(),
            server_default="0",
            nullable=False,
        ),
        sa.Column("sanitized_error_code", sa.String(length=64), nullable=True),
        sa.CheckConstraint(
            "status IN ('creating', 'completed', 'verified', 'failed')",
            name="ck_retention_archive_runs_status",
        ),
        sa.CheckConstraint(
            "candidate_record_count >= 0 AND dependency_record_count >= 0 "
            "AND total_record_count >= 0",
            name="ck_retention_archive_runs_nonnegative_counts",
        ),
        sa.CheckConstraint(
            "total_record_count = candidate_record_count + dependency_record_count",
            name="ck_retention_archive_runs_total_count",
        ),
        sa.CheckConstraint(
            "manifest_sha256 IS NULL OR length(manifest_sha256) = 64",
            name="ck_retention_archive_runs_manifest_sha256",
        ),
        sa.PrimaryKeyConstraint("archive_id"),
        sa.UniqueConstraint("storage_key"),
    )
    op.create_index(
        "ix_retention_archive_runs_status",
        "retention_archive_runs",
        ["status"],
        unique=False,
    )
    op.create_index(
        "ix_retention_archive_runs_archive_as_of",
        "retention_archive_runs",
        ["archive_as_of"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(
        "ix_retention_archive_runs_archive_as_of",
        table_name="retention_archive_runs",
    )
    op.drop_index(
        "ix_retention_archive_runs_status",
        table_name="retention_archive_runs",
    )
    op.drop_table("retention_archive_runs")
