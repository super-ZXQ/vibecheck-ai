"""Safe tarball extraction with comprehensive security checks.

Security guarantees:
- Path traversal prevention (rejects '..', absolute paths, null bytes).
- Rejects symlinks, hardlinks, device files, FIFO, socket, and abnormal paths.
- Cumulative limits enforced DURING extraction (total size, file count,
  single file size) — extraction aborts immediately when any limit is hit.
- Never executes any code, build script, or test from the extracted files.
- All temp files cleaned up via try/finally on success or failure.
"""

import io
import os
import shutil
import tarfile
from dataclasses import dataclass, field
from pathlib import Path

from app.core.config import settings


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
        f"Rejected non-regular entry (type={member.type}): {member.name!r}"
    )


def _is_within_directory(directory: Path, target: Path) -> bool:
    """Check if a target path is within the directory."""
    try:
        directory_resolved = directory.resolve()
        target_resolved = target.resolve()
        return str(target_resolved).startswith(str(directory_resolved))
    except (OSError, ValueError):
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
) -> ExtractionResult:
    """Safely extract a tarball to a destination directory.

    All security checks are enforced during extraction. On any failure,
    the destination directory is cleaned up (try/finally).

    Args:
        tarball_bytes: Raw tarball data (gzip compressed).
        dest_dir: Destination directory for extraction.
        max_archive_size: Override for max archive size.
        max_total_size: Override for max total extracted size.
        max_file_count: Override for max file count.
        max_single_file_size: Override for max single file size.

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
            members = tar.getmembers()

            # Check file count
            if len(members) > _max_count:
                raise ExtractionError(
                    f"Too many files in archive: {len(members)} "
                    f"(limit: {_max_count})"
                )

            cumulative_size = 0

            for member in members:
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
                    with tar.extractfile(member) as src:
                        if src is None:
                            raise ExtractionError(
                                f"Cannot extract file: {member.name!r}"
                            )
                        with open(target_path, "wb") as dst:
                            # Read in chunks to handle large files safely
                            while True:
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
        # Clean up on failure
        if not extracted:
            if dest_path.exists():
                shutil.rmtree(dest_path, ignore_errors=True)
            raise_last = True
        else:
            raise_last = False

    if raise_last:
        # This shouldn't be reached, but just in case
        raise ExtractionError("Extraction failed for unknown reason")

    return result


def safe_extract_to_temp(
    tarball_bytes: bytes,
    tmp_root: str | Path | None = None,
) -> ExtractionResult:
    """Extract tarball to an isolated temporary directory.

    Creates a unique subdirectory under tmp_root for this extraction.
    The caller is responsible for cleaning up the directory when done.
    """
    import tempfile
    import uuid

    root = Path(tmp_root or settings.tmp_dir)
    root.mkdir(parents=True, exist_ok=True)

    # Create unique subdirectory
    task_id = uuid.uuid4().hex[:12]
    dest = root / f"task-{task_id}"

    return safe_extract(tarball_bytes, dest)


def cleanup_temp_dir(dest_dir: str | Path) -> None:
    """Clean up a temporary extraction directory."""
    dest_path = Path(dest_dir)
    if dest_path.exists():
        shutil.rmtree(dest_path, ignore_errors=True)
