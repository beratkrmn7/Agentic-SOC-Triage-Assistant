from __future__ import annotations

import argparse
from collections.abc import Callable, Sequence
from datetime import datetime
import sys
from typing import TextIO

from sqlalchemy import Engine

from agent.application.archive import (
    ArchiveOperationError,
    ArchiveOperationResult,
    ArchiveService,
)
from agent.archive.schemas import validate_archive_id
from agent.archive.storage import ArchiveStore, LocalArchiveStore
from agent.config import Settings, get_settings
from agent.persistence.database import create_engine_factory, create_session_factory
from agent.persistence.unit_of_work import UnitOfWork


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Create and verify non-destructive retention archives",
    )
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("create", help="Create and verify a safe archive")
    verify = commands.add_parser("verify", help="Verify an existing archive")
    verify.add_argument("--archive-id", required=True)
    return parser


def _print_result(result: ArchiveOperationResult, output: TextIO) -> None:
    print(f"Archive ID: {result.archive_id}", file=output)
    print(f"Policy version: {result.policy_version}", file=output)
    print(f"Status: {result.status}", file=output)
    print(f"Candidate records: {result.candidate_record_count}", file=output)
    print(f"Dependency records: {result.dependency_record_count}", file=output)
    print(f"Total records: {result.total_record_count}", file=output)
    print(f"Payloads: {result.payload_count}", file=output)
    print(f"Manifest checksum: {result.manifest_sha256[:12]}", file=output)
    print(f"Verified: {'yes' if result.verified else 'no'}", file=output)
    print("Database records were not deleted.", file=output)


def main(
    argv: Sequence[str] | None = None,
    *,
    settings: Settings | None = None,
    store: ArchiveStore | None = None,
    uow_factory: Callable[[], UnitOfWork] | None = None,
    clock: Callable[[], datetime] | None = None,
    stdout: TextIO | None = None,
    stderr: TextIO | None = None,
) -> int:
    args = _build_parser().parse_args(argv)
    output = stdout or sys.stdout
    error_output = stderr or sys.stderr

    if args.command == "verify":
        try:
            validate_archive_id(args.archive_id)
        except ValueError:
            print("Archive verification failed safely.", file=error_output)
            return 2

    active_settings = settings or get_settings()
    active_store = store or LocalArchiveStore(
        active_settings.retention_archive_root
    )
    engine: Engine | None = None
    make_uow: Callable[[], UnitOfWork]
    if uow_factory is None:
        engine = create_engine_factory(active_settings)
        session_factory = create_session_factory(engine)

        def default_uow() -> UnitOfWork:
            return UnitOfWork(session_factory)

        make_uow = default_uow
    else:
        make_uow = uow_factory

    try:
        service = ArchiveService(
            make_uow,
            active_store,
            active_settings,
            clock=clock,
        )
        if args.command == "create":
            result = service.create()
        else:
            result = service.verify(args.archive_id)
        _print_result(result, output)
        return 0
    except (ArchiveOperationError, ValueError):
        message = (
            "Archive creation failed safely."
            if args.command == "create"
            else "Archive verification failed safely."
        )
        print(message, file=error_output)
        return 1
    except Exception:
        print("Archive operation failed safely.", file=error_output)
        return 1
    finally:
        if engine is not None:
            engine.dispose()


if __name__ == "__main__":
    raise SystemExit(main())
