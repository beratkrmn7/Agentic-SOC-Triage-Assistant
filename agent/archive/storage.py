from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Protocol
import hashlib
import os
import shutil
import uuid

from agent.archive.schemas import (
    EXPECTED_PAYLOAD_FILES,
    MAX_MANIFEST_BYTES,
    SHA256_PATTERN,
    validate_archive_id,
)


MANIFEST_FILENAME = "manifest.json"
MANIFEST_CHECKSUM_FILENAME = "manifest.sha256"
ARCHIVE_METADATA_FILES = (MANIFEST_FILENAME, MANIFEST_CHECKSUM_FILENAME)


class ArchiveStorageError(Exception):
    def __init__(self, code: str = "archive_storage_failed") -> None:
        super().__init__(code)
        self.code = code


class ArchiveAlreadyExistsError(ArchiveStorageError):
    def __init__(self) -> None:
        super().__init__("archive_already_exists")


class ArchiveNotFoundError(ArchiveStorageError):
    def __init__(self) -> None:
        super().__init__("archive_not_found")


@dataclass(frozen=True)
class ArchiveWorkspace:
    archive_id: str
    storage_key: str


def new_archive_id() -> str:
    return f"ARC-{uuid.uuid4().hex}"


class ArchiveStore(Protocol):
    def begin(self, archive_id: str) -> ArchiveWorkspace: ...

    @contextmanager
    def open_payload_writer(
        self,
        workspace: ArchiveWorkspace,
        filename: str,
    ) -> Iterator[BinaryIO]: ...

    def write_manifest(
        self,
        workspace: ArchiveWorkspace,
        manifest_bytes: bytes,
        manifest_sha256: str,
    ) -> None: ...

    def finalize(self, workspace: ArchiveWorkspace) -> None: ...

    def abort(self, workspace: ArchiveWorkspace) -> None: ...

    def exists(self, archive_id: str) -> bool: ...

    def read_small_file(
        self,
        archive_id: str,
        filename: str,
        *,
        workspace: ArchiveWorkspace | None = None,
    ) -> bytes: ...

    @contextmanager
    def open_payload_reader(
        self,
        archive_id: str,
        filename: str,
        *,
        workspace: ArchiveWorkspace | None = None,
    ) -> Iterator[BinaryIO]: ...

    def list_files(
        self,
        archive_id: str,
        *,
        workspace: ArchiveWorkspace | None = None,
    ) -> tuple[str, ...]: ...

    def file_size(
        self,
        archive_id: str,
        filename: str,
        *,
        workspace: ArchiveWorkspace | None = None,
    ) -> int: ...


class LocalArchiveStore:
    def __init__(self, archive_root: str) -> None:
        root = Path(archive_root)
        root.mkdir(parents=True, exist_ok=True)
        self._root = root.resolve(strict=True)
        self._partial_root = self._root / ".partial"
        self._partial_root.mkdir(mode=0o700, exist_ok=True)
        self._apply_directory_permissions(self._root)
        self._apply_directory_permissions(self._partial_root)
        self._assert_directory(self._root)
        self._assert_directory(self._partial_root)

    @property
    def root(self) -> Path:
        return self._root

    def begin(self, archive_id: str) -> ArchiveWorkspace:
        validate_archive_id(archive_id)
        completed = self._completed_directory(archive_id)
        partial = self._partial_directory(archive_id)
        if completed.exists() or partial.exists():
            raise ArchiveAlreadyExistsError()
        try:
            partial.mkdir(mode=0o700)
            self._apply_directory_permissions(partial)
            self._assert_directory(partial)
        except ArchiveStorageError:
            raise
        except Exception as exc:
            raise ArchiveStorageError() from exc
        return ArchiveWorkspace(archive_id=archive_id, storage_key=archive_id)

    @contextmanager
    def open_payload_writer(
        self,
        workspace: ArchiveWorkspace,
        filename: str,
    ) -> Iterator[BinaryIO]:
        directory = self._workspace_directory(workspace)
        path = self._safe_file(directory, filename, payload_only=True)
        try:
            stream = path.open("xb")
            self._apply_file_permissions(path)
        except ArchiveStorageError:
            raise
        except Exception as exc:
            raise ArchiveStorageError() from exc
        with stream:
            yield stream
            try:
                stream.flush()
                os.fsync(stream.fileno())
            except Exception as exc:
                raise ArchiveStorageError() from exc

    def write_manifest(
        self,
        workspace: ArchiveWorkspace,
        manifest_bytes: bytes,
        manifest_sha256: str,
    ) -> None:
        if len(manifest_bytes) > MAX_MANIFEST_BYTES:
            raise ArchiveStorageError("archive_manifest_too_large")
        if (
            not SHA256_PATTERN.fullmatch(manifest_sha256)
            or hashlib.sha256(manifest_bytes).hexdigest() != manifest_sha256
        ):
            raise ArchiveStorageError("archive_manifest_checksum_invalid")
        directory = self._workspace_directory(workspace)
        try:
            self._write_exclusive(
                self._safe_file(directory, MANIFEST_FILENAME),
                manifest_bytes,
            )
            self._write_exclusive(
                self._safe_file(directory, MANIFEST_CHECKSUM_FILENAME),
                f"{manifest_sha256}\n".encode("ascii"),
            )
        except ArchiveStorageError:
            raise
        except Exception as exc:
            raise ArchiveStorageError() from exc

    def finalize(self, workspace: ArchiveWorkspace) -> None:
        partial = self._workspace_directory(workspace)
        completed = self._completed_directory(workspace.archive_id)
        if completed.exists():
            raise ArchiveAlreadyExistsError()
        expected = set(EXPECTED_PAYLOAD_FILES) | set(ARCHIVE_METADATA_FILES)
        if set(self.list_files(workspace.archive_id, workspace=workspace)) != expected:
            raise ArchiveStorageError("archive_incomplete")
        try:
            os.replace(partial, completed)
            self._apply_directory_permissions(completed)
            self._fsync_directory(self._root)
        except Exception as exc:
            raise ArchiveStorageError("archive_finalize_failed") from exc

    def abort(self, workspace: ArchiveWorkspace) -> None:
        try:
            partial = self._partial_directory(workspace.archive_id)
            if not partial.exists():
                return
            self._assert_directory(partial)
            shutil.rmtree(partial)
        except ArchiveStorageError:
            raise
        except Exception as exc:
            raise ArchiveStorageError("archive_partial_cleanup_failed") from exc

    def exists(self, archive_id: str) -> bool:
        validate_archive_id(archive_id)
        path = self._completed_directory(archive_id)
        if not path.exists():
            return False
        self._assert_directory(path)
        return True

    def read_small_file(
        self,
        archive_id: str,
        filename: str,
        *,
        workspace: ArchiveWorkspace | None = None,
    ) -> bytes:
        directory = self._read_directory(archive_id, workspace)
        path = self._safe_file(directory, filename)
        self._assert_regular_file(path)
        size = path.stat().st_size
        if size > MAX_MANIFEST_BYTES:
            raise ArchiveStorageError("archive_metadata_too_large")
        try:
            return path.read_bytes()
        except Exception as exc:
            raise ArchiveStorageError() from exc

    @contextmanager
    def open_payload_reader(
        self,
        archive_id: str,
        filename: str,
        *,
        workspace: ArchiveWorkspace | None = None,
    ) -> Iterator[BinaryIO]:
        directory = self._read_directory(archive_id, workspace)
        path = self._safe_file(directory, filename, payload_only=True)
        self._assert_regular_file(path)
        try:
            stream = path.open("rb")
        except Exception as exc:
            raise ArchiveStorageError() from exc
        with stream:
            yield stream

    def list_files(
        self,
        archive_id: str,
        *,
        workspace: ArchiveWorkspace | None = None,
    ) -> tuple[str, ...]:
        directory = self._read_directory(archive_id, workspace)
        try:
            names: list[str] = []
            for entry in directory.iterdir():
                if entry.is_symlink():
                    raise ArchiveStorageError("archive_symlink_forbidden")
                self._ensure_contained(entry, directory)
                if not entry.is_file():
                    raise ArchiveStorageError("archive_entry_invalid")
                names.append(entry.name)
            return tuple(sorted(names))
        except ArchiveStorageError:
            raise
        except Exception as exc:
            raise ArchiveStorageError() from exc

    def file_size(
        self,
        archive_id: str,
        filename: str,
        *,
        workspace: ArchiveWorkspace | None = None,
    ) -> int:
        directory = self._read_directory(archive_id, workspace)
        path = self._safe_file(directory, filename, payload_only=True)
        self._assert_regular_file(path)
        return path.stat().st_size

    def _write_exclusive(self, path: Path, content: bytes) -> None:
        with path.open("xb") as stream:
            self._apply_file_permissions(path)
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())

    def _completed_directory(self, archive_id: str) -> Path:
        validate_archive_id(archive_id)
        return self._safe_directory(self._root, archive_id)

    def _partial_directory(self, archive_id: str) -> Path:
        validate_archive_id(archive_id)
        return self._safe_directory(self._partial_root, archive_id)

    def _workspace_directory(self, workspace: ArchiveWorkspace) -> Path:
        validate_archive_id(workspace.archive_id)
        if workspace.storage_key != workspace.archive_id:
            raise ArchiveStorageError("archive_storage_key_invalid")
        path = self._partial_directory(workspace.archive_id)
        if not path.exists():
            raise ArchiveNotFoundError()
        self._assert_directory(path)
        return path

    def _read_directory(
        self,
        archive_id: str,
        workspace: ArchiveWorkspace | None,
    ) -> Path:
        validate_archive_id(archive_id)
        if workspace is not None:
            if workspace.archive_id != archive_id:
                raise ArchiveStorageError("archive_workspace_mismatch")
            return self._workspace_directory(workspace)
        path = self._completed_directory(archive_id)
        if not path.exists():
            raise ArchiveNotFoundError()
        self._assert_directory(path)
        return path

    def _safe_directory(self, parent: Path, name: str) -> Path:
        path = parent / name
        self._ensure_contained(path, parent)
        return path

    def _safe_file(
        self,
        directory: Path,
        filename: str,
        *,
        payload_only: bool = False,
    ) -> Path:
        allowed = set(EXPECTED_PAYLOAD_FILES)
        if not payload_only:
            allowed.update(ARCHIVE_METADATA_FILES)
        if filename not in allowed or Path(filename).name != filename:
            raise ArchiveStorageError("archive_filename_invalid")
        path = directory / filename
        self._ensure_contained(path, directory)
        if path.is_symlink():
            raise ArchiveStorageError("archive_symlink_forbidden")
        return path

    @staticmethod
    def _ensure_contained(path: Path, parent: Path) -> None:
        try:
            path.resolve(strict=False).relative_to(parent.resolve(strict=True))
        except (OSError, ValueError) as exc:
            raise ArchiveStorageError("archive_path_escape") from exc

    def _assert_directory(self, path: Path) -> None:
        if path.is_symlink() or not path.is_dir():
            raise ArchiveStorageError("archive_directory_invalid")
        self._ensure_contained(path, self._root)

    def _assert_regular_file(self, path: Path) -> None:
        if path.is_symlink() or not path.is_file():
            raise ArchiveStorageError("archive_file_invalid")
        self._ensure_contained(path, self._root)

    @staticmethod
    def _apply_directory_permissions(path: Path) -> None:
        try:
            path.chmod(0o700)
        except OSError:
            if os.name != "nt":
                raise

    @staticmethod
    def _apply_file_permissions(path: Path) -> None:
        try:
            path.chmod(0o600)
        except OSError:
            if os.name != "nt":
                raise

    @staticmethod
    def _fsync_directory(path: Path) -> None:
        if os.name == "nt":
            return
        descriptor = os.open(path, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
