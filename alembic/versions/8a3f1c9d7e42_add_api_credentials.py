"""add API credentials

Revision ID: 8a3f1c9d7e42
Revises: c4b31f7d2a9e
Create Date: 2026-07-14 17:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "8a3f1c9d7e42"
down_revision: Union[str, Sequence[str], None] = "c4b31f7d2a9e"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Create the API credential store without any plaintext secret field."""
    op.create_table(
        "api_credentials",
        sa.Column("credential_id", sa.String(length=45), nullable=False),
        sa.Column("name", sa.String(length=120), nullable=False),
        sa.Column("key_prefix", sa.String(length=32), nullable=False),
        sa.Column("key_hash", sa.String(length=64), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_by_type", sa.String(length=32), nullable=False),
        sa.Column("created_by_id", sa.String(length=128), nullable=False),
        sa.Column("description", sa.String(length=500), nullable=True),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.CheckConstraint(
            "status IN ('active', 'revoked', 'expired')",
            name="ck_api_credentials_status",
        ),
        sa.PrimaryKeyConstraint("credential_id"),
        sa.UniqueConstraint("key_hash", name="uq_api_credentials_key_hash"),
    )
    op.create_index(
        op.f("ix_api_credentials_key_prefix"),
        "api_credentials",
        ["key_prefix"],
        unique=False,
    )
    op.create_index(
        op.f("ix_api_credentials_status"),
        "api_credentials",
        ["status"],
        unique=False,
    )


def downgrade() -> None:
    """Remove the API credential store."""
    op.drop_index(op.f("ix_api_credentials_status"), table_name="api_credentials")
    op.drop_index(op.f("ix_api_credentials_key_prefix"), table_name="api_credentials")
    op.drop_table("api_credentials")
