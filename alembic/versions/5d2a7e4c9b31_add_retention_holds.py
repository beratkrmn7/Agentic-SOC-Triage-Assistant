"""add retention holds

Revision ID: 5d2a7e4c9b31
Revises: 5d1a9c2e7f40
Create Date: 2026-07-16
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op


revision: str = "5d2a7e4c9b31"
down_revision: str | Sequence[str] | None = "5d1a9c2e7f40"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "retention_holds",
        sa.Column("hold_id", sa.String(length=45), nullable=False),
        sa.Column("entity_type", sa.String(length=32), nullable=False),
        sa.Column("entity_id", sa.String(length=128), nullable=False),
        sa.Column("reason", sa.String(length=500), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("released_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "entity_type IN ('canonical_event', 'detection_signal', "
            "'ingestion_job', 'incident', 'audit_event')",
            name="ck_retention_holds_entity_type",
        ),
        sa.CheckConstraint(
            "length(trim(reason)) > 0",
            name="ck_retention_holds_reason_not_blank",
        ),
        sa.CheckConstraint(
            "expires_at IS NULL OR expires_at > created_at",
            name="ck_retention_holds_expiry_after_creation",
        ),
        sa.PrimaryKeyConstraint("hold_id"),
    )
    op.create_index(
        "ix_retention_holds_entity_active",
        "retention_holds",
        ["entity_type", "entity_id", "released_at", "expires_at"],
        unique=False,
    )
    op.create_index(
        "ix_retention_holds_expires_at",
        "retention_holds",
        ["expires_at"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(
        "ix_retention_holds_expires_at",
        table_name="retention_holds",
    )
    op.drop_index(
        "ix_retention_holds_entity_active",
        table_name="retention_holds",
    )
    op.drop_table("retention_holds")
