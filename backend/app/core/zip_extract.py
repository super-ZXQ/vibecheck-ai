"""Safe ZIP extraction with comprehensive security checks.

Mirrors the security guarantees of ``safe_extract`` (tarball):

- Path traversal prevention (rejects '..', absolute paths, null bytes,
  backslashes, drive letters, control characters) — the same member-name
  validator used for tarballs is reused.
- Rejects symlinks and other non-regular file modes (device/FIFO/socket)
  encoded in the ZIP ``external_attr`` unix mode bits.
- Cumulative limits enforced DURING extraction (total size, file count,
  single file size) — extraction aborts immediately when any limit is hit.
  Streaming writes with actual-chunk accounting guard against a corrupt
  central directory declaring small sizes while the real payload is huge.
- Never executes any code or file from the archive.
- All temp files cleaned up via try/finally on success or failure.
"""

import io
import stat
import threading
import zipfile
from collections.abc import Callable
from pathlib import Path
from typing import IO

from app.core.config import settings
from app.core.safe_extract import (
    ExtractionError,
    ExtractionResult,
    _is_within_directory,
    _safe_remove_tree,
    _validate_member_name,
)

# ZIP local file header magic: PK\x03\x04
ZIP_MAGIC = b"PK\x03\x04"
# gzip magic (tar.gz)
GZIP_MAGIC = b"\x1f\x8b"

# Unsupported unix file modes that must never be materialized on disk.
_UNSAFE_IFMT = frozenset({
    stat.S_IFLNK,   # symlink
    stat.S_IFCHR,   # character device
    stat.S_IFBLK,   # block device
    stat.S_IFIFO,   # FIFO
    stat.S_IFSOCK,  # socket
})

_CHUNK_SIZE = 65536


def sniff_archive_type(data: bytes) -> str | None:
    """Return the archive category ('zip' | 'tar.gz') or None.

    Magic-byte sniffing is authoritative; extension checks are advisory.
    """
    if data.startswith(ZIP_MAGIC):
        return "zip"
    if data.startswith(GZIP_MAGIC):
        return "tar.gz"
    return None


def safe_extract_zip(
    zip_bytes: bytes,
    dest_dir: str | Path,
    *,
    max_archive_size: int | None = None,
    max_total_size: int | None = None,
    max_file_count: int | None = None,
    max_single_file_size: int | None = None,
    cancel_event: threading.Event | None = None,
) -> ExtractionResult:
    """Safely extract a ZIP bytes archive to ``dest_dir``.

    All security checks are enforced during extraction. On any failure the
    destination directory is cleaned up (try/finally).

    Each member is extracted via ``ZipFile.open(member)`` and written with
    chunked reads, so a defective archive cannot inflate the real written
    bytes beyond the declared limits.

    Args:
        zip_bytes: Raw ZIP data.
        dest_dir: Destination directory for extraction.
        max_archive_size: Override for max archive size (compressed input).
        max_total_size: Override for max total extracted size.
        max_file_count: Override for max extracted file count.
        max_single_file_size: Override for max single extracted file size.
        cancel_event: Optional event; when set, extraction is cancelled.

    Raises:
        ExtractionError: On any security violation or limit breach.
    """
    _max_archive = max_archive_size or settings.max_archive_size
    _max_total = max_total_size or settings.max_extracted_total_size
    _max_count = max_file_count or settings.max_file_count
    _max_single = max_single_file_size or settings.max_single_file_size

    dest_path = Path(dest_dir)
    dest_path.mkdir(parents=True, exist_ok=True)

    result = ExtractionResult(dest_dir=str(dest_path))
    extracted = False
    extracted_file_count = 0
    cumulative_size = 0

    def _cancelled() -> bool:
        return cancel_event is not None and cancel_event.is_set()

    try:
        if len(zip_bytes) > _max_archive:
            raise ExtractionError(
                f"Archive too large: {len(zip_bytes)} bytes "
                f"(limit: {_max_archive} bytes)"
            )
        if sniff_archive_type(zip_bytes) != "zip":
            raise ExtractionError("Not a valid ZIP archive")

        try:
            with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
                for info in zf.infolist():
                    if _cancelled():
                        raise ExtractionError("Extraction cancelled")

                    # Validate member name (path traversal, null bytes, etc.).
                    _validate_member_name(info.filename)

                    # Reject unix special modes encoded in the ZIP attributes.
                    _reject_special_modes(info)

                    if info.is_dir():
                        target_path = dest_path / info.filename
                        if not _is_within_directory(dest_path, target_path):
                            raise ExtractionError(
                                "Path escapes destination directory: "
                                f"{info.filename!r}"
                            )
                        target_path.mkdir(parents=True, exist_ok=True)
                        continue

                    # Only regular files reach here.
                    # Declared size is an advisory fast-fail; the actual
                    # decompressed chunk accounting in _extract_member is
                    # authoritative.
                    if info.file_size > _max_single:
                        raise ExtractionError(
                            f"File too large: {info.filename!r} "
                            f"({info.file_size} bytes, limit: {_max_single} bytes)"
                        )

                    extracted_file_count += 1
                    if extracted_file_count > _max_count:
                        raise ExtractionError(
                            f"Too many files in archive: {extracted_file_count} "
                            f"(limit: {_max_count})"
                        )

                    target_path = dest_path / info.filename
                    if not _is_within_directory(dest_path, target_path):
                        raise ExtractionError(
                            "Path escapes destination directory: "
                            f"{info.filename!r}"
                        )
                    target_path.parent.mkdir(parents=True, exist_ok=True)

                    with zf.open(info, "r") as src:
                        written = _copy_member(
                            src,
                            target_path,
                            _max_single,
                            info.filename,
                            _cancelled,
                        )

                    cumulative_size += written
                    if cumulative_size > _max_total:
                        raise ExtractionError(
                            "Total extracted size exceeds limit: "
                            f"{cumulative_size} bytes (limit: {_max_total} bytes)"
                        )

                    result.file_count += 1
                    result.total_size += written

                    # Track top-level directory (same convention as tarballs).
                    if result.top_level_dir is None and "/" in info.filename:
                        result.top_level_dir = info.filename.split("/")[0]

            extracted = True
        except zipfile.BadZipFile:
            raise ExtractionError("Malformed ZIP archive")
    finally:
        # Clean up on failure — handle read-only files via onerror.
        if not extracted:
            _safe_remove_tree(dest_path)

    return result


def _reject_special_modes(info: zipfile.ZipInfo) -> None:
    """Reject ZIP entries whose unix mode denotes a non-regular type."""
    mode_bits = (info.external_attr >> 16) & 0xFFFF
    if mode_bits == 0:
        return  # No unix attrs (e.g. Windows-generated) — treat as regular.
    file_type = stat.S_IFMT(mode_bits)
    if file_type in _UNSAFE_IFMT:
        raise ExtractionError(f"Rejected non-regular entry: {info.filename!r}")


def _copy_member(
    src: IO[bytes],
    target_path: Path,
    max_single_size: int,
    name: str,
    cancelled: Callable[[], bool],
) -> int:
    """Stream-copy one ZIP member with chunked, size-enforced writes.

    Returns the number of actual bytes written (authoritative for limits).
    """
    written = 0
    try:
        with open(target_path, "wb") as dst:
            while True:
                if cancelled():
                    raise ExtractionError("Extraction cancelled")
                chunk = src.read(_CHUNK_SIZE)
                if not chunk:
                    break
                written += len(chunk)
                if written > max_single_size:
                    raise ExtractionError(
                        f"File too large while extracting: {name!r} "
                        f"(limit: {max_single_size} bytes)"
                    )
                dst.write(chunk)
        return written
    except ExtractionError:
        raise
    except Exception as exc:
        raise ExtractionError(
            f"Cannot extract file: {name!r} ({type(exc).__name__})"
        ) from exc
