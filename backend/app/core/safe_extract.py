"""Safe tarball extraction with comprehensive security checks.

Security guarantees:
- Path traversal prevention (rejects '..', absolute paths, null bytes).
- Rejects symlinks, hardlinks, device files, FIFO, socket, and abnormal paths.
- Cumulative limits enforced DURING extraction (total size, file count,
  single file size) — extraction aborts immediately when any limit is hit.
- Never executes any code, build script, or test from the extracted files.
- All temp files cleaned up via try/finally on success or failure.
- Cleanup handles read-only files via onerror callback.
- Persistent cleanup failures are logged without sensitive content.
"""

import io
import logging
import os
import shutil
import stat
import tarfile
import threading
from dataclasses import dataclass, field
from pathlib import Path

from app.core.config import settings

logger = logging.getLogger(__name__)


class ExtractionError(Exception):
    """Raised when extraction fails or a security check is triggered."""


@dataclass
class ExtractionResult:
    """Result of a safe extraction."""
    dest_dir: str
    file_count: int = 0
    total_size: int = 0
    top_level_dir: str | None = None
    rejected_entries: list[str] = field(default_factory=list)


@dataclass
class _PendingExtract:
    """Handoff for a reserved extraction destination + cancellation event.

    Only one task is processed at a time (background runner global lock),
    so a single shared slot is sufficient.
    """
    dest_dir: Path
    cancel_event: threading.Event


# Reserved by the background runner before starting the extraction thread,
# consumed by safe_extract_to_temp. Lets the runner locate the partially
# written directory and signal cancellation even on a stage timeout.
_pending_extract: _PendingExtract | None = None


def reserve_extract(tmp_root: str | Path | None = None) -> _PendingExtract:
    """Reserve an extraction destination + cancel event for the next call."""
    global _pending_extract
    slot = _PendingExtract(
        dest_dir=prepare_extract_dest(tmp_root),
        cancel_event=threading.Event(),
    )
    _pending_extract = slot
    return slot


def consume_extract() -> _PendingExtract | None:
    """Consume (and clear) the reserved extraction slot, if any."""
    global _pending_extract
    slot = _pending_extract
    _pending_extract = None
    return slot


# --- Member validation ---

def _validate_member_name(name: str) -> str:
    """Validate a tarball member name for path safety.

    Returns the cleaned name if safe.
    Raises ExtractionError if the name is dangerous.
    """
    # Reject null bytes
    if "\x00" in name:
        raise ExtractionError(f"Rejected entry with null byte in name: {name!r}")

    # Reject backslashes (could be path separator on Windows)
    if "\\" in name:
        raise ExtractionError(f"Rejected entry with backslash in name: {name!r}")

    # Reject absolute paths
    if name.startswith("/"):
        raise ExtractionError(f"Rejected absolute path: {name!r}")

    # Reject Windows-style absolute paths
    if len(name) >= 2 and name[1] == ":":
        raise ExtractionError(f"Rejected Windows absolute path: {name!r}")

    # Reject path traversal
    parts = name.split("/")
    for part in parts:
        if part == "..":
            raise ExtractionError(f"Rejected path traversal: {name!r}")

    # Reject control characters
    for ch in name:
        if ord(ch) < 32 and ch not in ("\t",):
            raise ExtractionError(
                f"Rejected entry with control character in name: {name!r}"
            )

    return name


def _validate_member_type(member: tarfile.TarInfo) -> str:
    """Validate the type of a tarball member.

    Returns the member type category if safe.
    Raises ExtractionError if the type is dangerous.
    """
    # Only allow regular files and directories
    if member.isdir():
        return "dir"
    if member.isreg():
        return "file"

    # Reject all dangerous types with specific messages
    if member.issym():
        raise ExtractionError(
            f"Rejected symlink entry: {member.name!r}"
        )
    if member.islnk():
        raise ExtractionError(
            f"Rejected hardlink entry: {member.name!r}"
        )
    if member.ischr():
        raise ExtractionError(
            f"Rejected character device entry: {member.name!r}"
        )
    if member.isblk():
        raise ExtractionError(
            f"Rejected block device entry: {member.name!r}"
        )
    if member.isfifo():
        raise ExtractionError(
            f"Rejected FIFO entry: {member.name!r}"
        )

    # Catch any other non-regular type (socket, etc.)
    raise ExtractionError(
        f"Rejected non-regular entry (type={member.type!r}): {member.name!r}"
    )


def _is_within_directory(directory: Path, target: Path) -> bool:
    """Check if a target path is within the directory.

    Uses path-component-aware comparison (not a raw string prefix), so a
    sibling like ``/x/tmpfoo`` is correctly rejected.
    """
    try:
        return target.resolve().is_relative_to(directory.resolve())
    except (OSError, ValueError):
        return False


def _remove_readonly(func, path, exc_info):
    """Error handler for shutil.rmtree — force-remove read-only files."""
    try:
        os.chmod(path, stat.S_IWRITE)
        func(path)
    except Exception:
        pass


def _safe_remove_tree(path: Path) -> bool:
    """Remove a directory tree, handling read-only files. Returns True on success.

    On persistent failure, logs an error message without sensitive content
    (file paths in temp dirs are not considered sensitive).
    """
    if not path.exists():
        return True
    try:
        shutil.rmtree(path, onerror=_remove_readonly)
        if path.exists():
            # Persistent failure — log without sensitive content
            logger.error(
                "Failed to fully clean up temp directory: %s "
                "(some files may remain)", path
            )
            return False
        return True
    except Exception as e:
        logger.error(
            "Failed to clean up temp directory: %s (error: %s, no sensitive content)",
            path, type(e).__name__
        )
        return False


# --- Safe extraction ---

def safe_extract(
    tarball_bytes: bytes,
    dest_dir: str | Path,
    *,
    max_archive_size: int | None = None,
    max_total_size: int | None = None,
    max_file_count: int | None = None,
    max_single_file_size: int | None = None,
    cancel_event: threading.Event | None = None,
) -> ExtractionResult:
    """Safely extract a tarball to a destination directory.

    All security checks are enforced during extraction. On any failure,
    the destination directory is cleaned up (try/finally).

    Members are consumed incrementally via ``tar.next()`` instead of
    ``getmembers()``, so limits are enforced during iteration and the
    whole archive header list is never materialized in memory.

    ``cancel_event`` (optional) lets a caller abort a long-running
    extraction between members / file chunks. When set, extraction stops
    promptly with an ExtractionError and the partial tree is cleaned up.

    Args:
        tarball_bytes: Raw tarball data (gzip compressed).
        dest_dir: Destination directory for extraction.
        max_archive_size: Override for max archive size.
        max_total_size: Override for max total extracted size.
        max_file_count: Override for max file count.
        max_single_file_size: Override for max single file size.
        cancel_event: Optional event; when set, extraction is cancelled.

    Returns:
        ExtractionResult with extraction details.

    Raises:
        ExtractionError: On any security violation or limit breach.
    """
    # Use settings defaults if not overridden
    _max_archive = max_archive_size or settings.max_archive_size
    _max_total = max_total_size or settings.max_extracted_total_size
    _max_count = max_file_count or settings.max_file_count
    _max_single = max_single_file_size or settings.max_single_file_size

    dest_path = Path(dest_dir)
    dest_path.mkdir(parents=True, exist_ok=True)

    result = ExtractionResult(dest_dir=str(dest_path))
    extracted = False

    def _cancelled() -> bool:
        return cancel_event is not None and cancel_event.is_set()

    try:
        # Check archive size before opening
        if len(tarball_bytes) > _max_archive:
            raise ExtractionError(
                f"Archive too large: {len(tarball_bytes)} bytes "
                f"(limit: {_max_archive} bytes)"
            )

        # Open tarball from bytes
        tar = tarfile.open(fileobj=io.BytesIO(tarball_bytes), mode="r:gz")

        try:
            member_count = 0
            cumulative_size = 0

            while True:
                if _cancelled():
                    raise ExtractionError("Extraction cancelled")

                member = tar.next()
                if member is None:
                    break

                member_count += 1

                # Check file count
                if member_count > _max_count:
                    raise ExtractionError(
                        f"Too many files in archive: {member_count} "
                        f"(limit: {_max_count})"
                    )

                # Validate name (path traversal, null bytes, etc.)
                _validate_member_name(member.name)

                # Validate type (reject symlinks, devices, FIFO, socket, etc.)
                member_type = _validate_member_type(member)

                # Check single file size
                if member_type == "file" and member.size > _max_single:
                    raise ExtractionError(
                        f"File too large: {member.name!r} "
                        f"({member.size} bytes, limit: {_max_single} bytes)"
                    )

                # Check cumulative total size
                cumulative_size += member.size
                if cumulative_size > _max_total:
                    raise ExtractionError(
                        f"Total extracted size exceeds limit: "
                        f"{cumulative_size} bytes (limit: {_max_total} bytes)"
                    )

                # Resolve the target path and verify it's within dest
                target_path = dest_path / member.name
                if not _is_within_directory(dest_path, target_path):
                    raise ExtractionError(
                        f"Path escapes destination directory: {member.name!r}"
                    )

                # Extract the member
                if member_type == "dir":
                    target_path.mkdir(parents=True, exist_ok=True)
                elif member_type == "file":
                    target_path.parent.mkdir(parents=True, exist_ok=True)
                    src = tar.extractfile(member)
                    if src is None:
                        raise ExtractionError(
                            f"Cannot extract file: {member.name!r}"
                        )
                    with src, open(target_path, "wb") as dst:
                        # Read in chunks to handle large files safely
                        while True:
                            if _cancelled():
                                raise ExtractionError(
                                    "Extraction cancelled"
                                )
                            chunk = src.read(65536)
                            if not chunk:
                                break
                            dst.write(chunk)

                    result.file_count += 1
                    result.total_size += member.size

                # Track top-level directory
                if result.top_level_dir is None and "/" in member.name:
                    result.top_level_dir = member.name.split("/")[0]

            extracted = True

        finally:
            tar.close()

    finally:
        # Clean up on failure — handle read-only files via onerror
        if not extracted:
            _safe_remove_tree(dest_path)

    return result


def prepare_extract_dest(tmp_root: str | Path | None = None) -> Path:
    """Return a unique destination path under tmp_root without creating it.

    The caller passes this path into extraction so it is known even when
    the extraction thread is interrupted (e.g. by a stage timeout) and
    the partially-written directory can still be cleaned up.
    """
    import uuid

    root = Path(tmp_root or settings.tmp_dir)
    return root / f"task-{uuid.uuid4().hex[:12]}"


def safe_extract_to_temp(
    tarball_bytes: bytes,
    tmp_root: str | Path | None = None,
    *,
    dest_dir: str | Path | None = None,
    cancel_event: threading.Event | None = None,
) -> ExtractionResult:
    """Extract tarball to an isolated temporary directory.

    When ``dest_dir``/``cancel_event`` are omitted, any slot reserved via
    :func:`reserve_extract` is consumed (used by the background runner so a
    stage timeout can locate and clean up the partial directory). Falls back
    to a freshly generated unique subdirectory under tmp_root.
    The caller is responsible for cleaning up the directory when done.
    """
    if dest_dir is None or cancel_event is None:
        pending = consume_extract()
        if pending is not None:
            dest_dir = dest_dir or pending.dest_dir
            cancel_event = cancel_event or pending.cancel_event
    if dest_dir is None:
        dest_dir = prepare_extract_dest(tmp_root)

    return safe_extract(tarball_bytes, dest_dir, cancel_event=cancel_event)


def cleanup_temp_dir(dest_dir: str | Path) -> None:
    """Clean up a temporary extraction directory.

    Handles read-only files via onerror callback. On persistent failure,
    logs an error without sensitive content.
    """
    _safe_remove_tree(Path(dest_dir))
