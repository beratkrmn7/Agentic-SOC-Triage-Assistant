"""add durable search projection states

Revision ID: 7b9c2e4f6a81
Revises: 02a14b4d18bf
Create Date: 2026-07-17 18:00:00.000000

"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "7b9c2e4f6a81"
down_revision: Union[str, Sequence[str], None] = "02a14b4d18bf"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "search_projection_states",
        sa.Column("entity_type", sa.String(length=32), nullable=False),
        sa.Column("entity_id", sa.String(length=256), nullable=False),
        sa.Column("schema_version", sa.String(length=64), nullable=False),
        sa.Column("projection_version", sa.Integer(), nullable=False),
        sa.Column("projection_sha256", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.CheckConstraint(
            "entity_type IN ('canonical_event', 'detection_signal')",
            name="ck_search_projection_states_entity_type",
        ),
        sa.CheckConstraint(
            "length(trim(schema_version)) > 0",
            name="ck_search_projection_states_schema_version",
        ),
        sa.CheckConstraint(
            "projection_version > 0",
            name="ck_search_projection_states_projection_version",
        ),
        sa.CheckConstraint(
            "version > 0",
            name="ck_search_projection_states_version",
        ),
        sa.CheckConstraint(
            "length(projection_sha256) = 64 AND "
            "length(replace(replace(replace(replace(replace(replace(replace("
            "replace(replace(replace(replace(replace(replace(replace(replace("
            "replace(projection_sha256, '0', ''), '1', ''), '2', ''), '3', ''), "
            "'4', ''), '5', ''), '6', ''), '7', ''), '8', ''), '9', ''), "
            "'a', ''), 'b', ''), 'c', ''), 'd', ''), 'e', ''), 'f', '')) = 0",
            name="ck_search_projection_states_sha256",
        ),
        sa.PrimaryKeyConstraint(
            "entity_type",
            "entity_id",
            "schema_version",
            name="pk_search_projection_states",
        ),
    )


def downgrade() -> None:
    op.drop_table("search_projection_states")
