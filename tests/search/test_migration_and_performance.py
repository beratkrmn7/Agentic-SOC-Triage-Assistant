from __future__ import annotations

from dataclasses import replace
from datetime import timedelta
import inspect as python_inspect

from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect, insert, text
from sqlalchemy.orm import sessionmaker

from agent.application.search_service import IncidentSearchCriteria, SearchService
from agent.persistence.database import Base
from agent.persistence.orm_models import Incident
from agent.persistence.search_repositories import SqlAlchemySearchRepository
from tests.search.conftest import BASE_TIME, make_settings


SEARCH_INDEXES = {
    "incidents": {
        "ix_incidents_created_id",
        "ix_incidents_status_created",
        "ix_incidents_severity_created",
        "ix_incidents_type_created",
        "ix_incidents_first_seen_id",
        "ix_incidents_last_seen_id",
    },
    "canonical_events": {
        "ix_canonical_events_timestamp_id",
        "ix_canonical_events_src_timestamp",
        "ix_canonical_events_dst_timestamp",
        "ix_canonical_events_source_timestamp",
    },
    "detection_signals": {
        "ix_detection_signals_created_id",
        "ix_detection_signals_rule_created",
        "ix_detection_signals_severity_created",
        "ix_detection_signals_first_seen_id",
        "ix_detection_signals_last_seen_id",
        "ix_detection_signals_suppressed_created",
    },
    "ingestion_jobs": {
        "ix_ingestion_jobs_created_id",
        "ix_ingestion_jobs_status_created",
        "ix_ingestion_jobs_mode_created",
        "ix_ingestion_jobs_completed_id",
        "ix_ingestion_jobs_source_created",
    },
}


def alembic_config(path) -> Config:
    config = Config("alembic.ini")
    config.set_main_option("sqlalchemy.url", f"sqlite:///{path}")
    return config


def index_names(engine, table):
    return {item["name"] for item in inspect(engine).get_indexes(table)}


def test_fresh_database_upgrade_creates_required_indexes(tmp_path):
    database = tmp_path / "fresh-head.db"
    config = alembic_config(database)
    command.upgrade(config, "head")
    engine = create_engine(f"sqlite:///{database}")
    try:
        for table, required in SEARCH_INDEXES.items():
            assert required <= index_names(engine, table)
    finally:
        engine.dispose()


def test_downgrade_removes_only_search_indexes(tmp_path):
    database = tmp_path / "downgrade.db"
    config = alembic_config(database)
    command.upgrade(config, "head")
    engine = create_engine(f"sqlite:///{database}")
    before_status_indexes = index_names(engine, "incidents")
    command.downgrade(config, "c7d9e2a4b6f1")
    try:
        for table, introduced in SEARCH_INDEXES.items():
            assert not introduced & index_names(engine, table)
        assert "ix_incidents_status" in index_names(engine, "incidents")
        assert "ix_incidents_status" in before_status_indexes
    finally:
        engine.dispose()


def test_previous_revision_upgrades_to_search_head(tmp_path):
    database = tmp_path / "previous-head.db"
    config = alembic_config(database)
    command.upgrade(config, "c7d9e2a4b6f1")
    engine = create_engine(f"sqlite:///{database}")
    assert "ix_incidents_created_id" not in index_names(engine, "incidents")
    engine.dispose()
    command.upgrade(config, "head")
    engine = create_engine(f"sqlite:///{database}")
    try:
        assert "ix_incidents_created_id" in index_names(engine, "incidents")
    finally:
        engine.dispose()


def test_representative_sqlite_plan_uses_status_search_index(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'plan.db'}")
    Base.metadata.create_all(engine)
    try:
        with engine.connect() as connection:
            plan = connection.execute(
                text(
                    "EXPLAIN QUERY PLAN SELECT incident_id FROM incidents "
                    "WHERE status = 'new' ORDER BY created_at DESC LIMIT 51"
                )
            ).fetchall()
        assert "ix_incidents_status_created" in " ".join(str(row) for row in plan)
    finally:
        engine.dispose()


def test_ten_thousand_metadata_rows_paginate_without_full_load(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'ten-thousand.db'}")
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine)
    rows = [
        {
            "incident_id": f"bulk-{index:05d}",
            "title": "Generated metadata",
            "incident_type": "performance_smoke",
            "incident_family": "test",
            "status": "new",
            "severity": "medium",
            "confidence": 0.5,
            "first_seen": BASE_TIME - timedelta(seconds=index),
            "last_seen": BASE_TIME - timedelta(seconds=index),
            "created_at": BASE_TIME - timedelta(seconds=index),
            "primary_entity": f"entity-{index}",
            "target_entities": [],
            "mitre_techniques": [],
            "metrics": {},
        }
        for index in range(10_000)
    ]
    with factory() as session:
        session.execute(insert(Incident), rows)
        session.commit()
    del rows
    settings = make_settings()
    with factory() as session:
        service = SearchService(SqlAlchemySearchRepository(session), settings)
        criteria = IncidentSearchCriteria(page_size=200)
        first = service.search_incidents(criteria)
        second = service.search_incidents(
            replace(criteria, cursor=first.next_cursor)
        )
    engine.dispose()
    assert len(first.items) == len(second.items) == 200
    assert first.has_more and second.has_more
    assert {item.incident_id for item in first.items}.isdisjoint(
        item.incident_id for item in second.items
    )


def test_search_repository_executes_one_bounded_statement():
    source = python_inspect.getsource(SqlAlchemySearchRepository._execute_page)
    assert "page_size + 1" in source
    assert ".limit(" in source
    assert "fetchmany(page_size + 1)" in source
