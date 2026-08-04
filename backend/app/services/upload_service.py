"""Upload ingestion — validate and safely stage local uploads.

Two accepted shapes (backend is authoritative; frontend convenience only):
- archive: a single .zip / .tar.gz / .tgz file. Magic-byte sniffing is
  authoritative, the extension is advisory. Content is extracted with the
  same security guarantees as GitHub tarballs (path traversal, symlinks,
  zip bombs, size/count caps).
- folder: multiple files whose filename carries the relative path
  (browser ``webkitRelativePath``). Every relative path is validated with
  the tarball member-name validator and the tree is rebuilt on disk.

All content is staged under ``settings.tmp_dir/upload-{task_id}`` (tmpfs),
never persisted to the database, and removed by the background runner
after the scan completes.

Security:
- Never executes any uploaded code.
- Streaming reads with enforced caps; oversized uploads abort immediately.
- Every staged directory is cleaned up on failure.
"""

from __future__ import annotations

import logging
import tarfile
from dataclasses import dataclass
from pathlib import Path

from fastapi import UploadFile

from app.core.config import settings
from app.core.error_codes import (
    EXTRACTION_LIMIT_EXCEEDED,
    INVALID_UPLOAD,
    UNSAFE_ARCHIVE,
    UPLOAD_TOO_LARGE,
)
from app.core.safe_extract import (
    ExtractionError,
    _validate_member_name,
    cleanup_temp_dir,
    safe_extract,
)
from app.core.zip_extract import safe_extract_zip, sniff_archive_type

logger = logging.getLogger(__name__)

# Marker prefix for upload-sourced tasks in the tasks table.
# A task whose repo_url starts with this prefix skips the GitHub
# download/extract stages in the background runner.
LOCAL_UPLOAD_PREFIX = "local://upload/"

_ARCHIVE_EXTENSIONS: frozenset[str] = frozenset({".zip", ".tar.gz", ".tgz"})

_FOLDER_CHUNK_SIZE = 256 * 1024


class UploadError(Exception):
    """Raised when an upload is rejected with a machine-readable code."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


@dataclass
class UploadArtifact:
    """Staged upload content — ready for the scanner."""
    dest_dir: str
    file_count: int
    total_size: int
    top_level_dir: str | None


def upload_source_dir(task_id: str) -> Path:
    """Directory where upload content for a task is staged."""
    return Path(settings.tmp_dir) / f"upload-{task_id}"


def _map_extraction_error(error: ExtractionError) -> UploadError:
    """Map an ExtractionError to the appropriate UploadError code."""
    msg = str(error).lower()
    if "too large" in msg or "exceeds limit" in msg or "too many files" in msg:
        return UploadError(
            EXTRACTION_LIMIT_EXCEEDED, str(error)
        )
    return UploadError(UNSAFE_ARCHIVE, str(error))


async def store_archive_upload(
    file: UploadFile,
    dest_root: Path,
) -> UploadArtifact:
    """Sniff, size-check and safely extract a single archive upload.

    Raises:
        UploadError: with a machine-readable code on any rejection.
    """
    filename = (file.filename or "").strip()
    if not filename:
        raise UploadError(INVALID_UPLOAD, "Missing upload filename")

    lowered = filename.lower()
    if not any(lowered.endswith(ext) for ext in _ARCHIVE_EXTENSIONS):
        raise UploadError(
            INVALID_UPLOAD,
            f"Unsupported archive extension: {filename!r}",
        )

    # Read the first 4 bytes for magic sniffing, then stream the rest with
    # an enforced size cap (never materializes more than max_archive_size).
    header = await file.read(4)
    sniffed = sniff_archive_type(header)
    if sniffed is None:
        raise UploadError(INVALID_UPLOAD, "Unrecognized archive format")

    if sniffed == "zip" and not lowered.endswith(".zip"):
        raise UploadError(
            INVALID_UPLOAD,
            f"Extension {filename!r} does not match ZIP content",
        )
    if sniffed == "tar.gz" and not (
        lowered.endswith(".tar.gz") or lowered.endswith(".tgz")
    ):
        raise UploadError(
            INVALID_UPLOAD,
            f"Extension {filename!r} does not match gzip content",
        )

    chunks = bytearray(header)
    while True:
        chunk = await file.read(1024 * 1024)
        if not chunk:
            break
        chunks.extend(chunk)
        if len(chunks) > settings.max_archive_size:
            raise UploadError(
                UPLOAD_TOO_LARGE,
                f"Archive too large: {len(chunks)} bytes "
                f"(limit: {settings.max_archive_size} bytes)",
            )

    data = bytes(chunks)
    try:
        if sniffed == "zip":
            result = safe_extract_zip(data, dest_root)
        else:
            result = safe_extract(data, dest_root)
    except tarfile.TarError:
        cleanup_temp_dir(dest_root)
        raise UploadError(INVALID_UPLOAD, "Malformed archive")
    except ExtractionError as e:
        cleanup_temp_dir(dest_root)
        raise _map_extraction_error(e)
    except Exception as e:
        logger.error("Unexpected upload extraction failure: %s", type(e).__name__)
        cleanup_temp_dir(dest_root)
        raise UploadError(UNSAFE_ARCHIVE, "Upload could not be processed")

    return UploadArtifact(
        dest_dir=str(dest_root),
        file_count=result.file_count,
        total_size=result.total_size,
        top_level_dir=result.top_level_dir,
    )


async def store_folder_upload(
    files: list[UploadFile],
    dest_root: Path,
) -> UploadArtifact:
    """Rebuild a folder tree from relative-path multipart files.

    Every file is validated (path traversal, null bytes, backslashes,
    absolute paths, control characters) and written with chunked,
    size-enforced streaming. On any violation the staged tree is removed.

    Raises:
        UploadError: with a machine-readable code on any rejection.
    """
    if not files:
        raise UploadError(INVALID_UPLOAD, "Folder upload contains no files")

    dest_root.mkdir(parents=True, exist_ok=True)
    file_count = 0
    total_size = 0

    def _reject(code: str, message: str) -> None:
        cleanup_temp_dir(dest_root)
        raise UploadError(code, message)

    for upload_file in files:
        rel_path = (upload_file.filename or "").strip()
        if not rel_path:
            _reject(INVALID_UPLOAD, "Folder upload contains a file without a path")

        try:
            _validate_member_name(rel_path)
        except ExtractionError as e:
            _reject(INVALID_UPLOAD, str(e))

        target = dest_root / rel_path
        try:
            if not target.resolve().is_relative_to(dest_root.resolve()):
                _reject(INVALID_UPLOAD, f"Path escapes destination: {rel_path!r}")
        except (OSError, ValueError):
            _reject(INVALID_UPLOAD, f"Path escapes destination: {rel_path!r}")

        file_count += 1
        if file_count > settings.max_file_count:
            _reject(
                UPLOAD_TOO_LARGE,
                f"Too many files: {file_count} (limit: {settings.max_file_count})",
            )

        target.parent.mkdir(parents=True, exist_ok=True)
        written = 0
        try:
            with open(target, "wb") as dst:
                while True:
                    chunk = await upload_file.read(_FOLDER_CHUNK_SIZE)
                    if not chunk:
                        break
                    written += len(chunk)
                    if written > settings.max_single_file_size:
                        _reject(
                            UPLOAD_TOO_LARGE,
                            f"File too large: {rel_path!r} "
                            f"(limit: {settings.max_single_file_size} bytes)",
                        )
                    dst.write(chunk)
        except Exception:
            cleanup_temp_dir(dest_root)
            raise

        total_size += written
        if total_size > settings.max_extracted_total_size:
            _reject(
                UPLOAD_TOO_LARGE,
                f"Total upload size exceeds limit: {total_size} bytes "
                f"(limit: {settings.max_extracted_total_size} bytes)",
            )

    return UploadArtifact(
        dest_dir=str(dest_root),
        file_count=file_count,
        total_size=total_size,
        top_level_dir=None,
    )
