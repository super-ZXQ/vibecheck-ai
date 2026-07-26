"""Scanner core -- secure directory traversal, rule execution, and deduplication.

Security guarantees:
- Path containment: every file is resolved and verified to be inside
  scan_root via Path.resolve() + relative_to(). Files that resolve outside
  the root are skipped as "outside_root". This prevents symlink-based escapes
  that os.path.relpath alone cannot detect.
- Symlink files and symlink directories are always skipped.
- All returned paths use POSIX format (forward slashes).
- Never executes code from the scanned repository.
- File content is read as bytes first; NUL bytes and invalid UTF-8 cause
  files to be skipped as "binary". UTF-8-SIG decoding handles BOM; CRLF
  is handled by splitlines().
- Files larger than scan_max_file_size are skipped as "too_large".
- All result object paths (Finding, ScanNotice, SkippedFile, ScanError)
  are sanitized via mask_untrusted_text to mask explicit-format secrets
  that may be embedded in user-controlled filenames and directory names.
- Files are scanned in FULL -- no line limit, so secrets in later lines
  are never missed.
- All error messages are fixed reason codes -- no str(exception),
  repr(exception), absolute paths, or file content in any output.

Deduplication (per file):
1. Content findings on the same line with overlapping column ranges:
   keep the higher-priority finding (lower RULE_PRIORITY_MAP number).
2. File-type findings never overlap with content-type findings.
3. R011 is only suppressed on the SAME LINE where it column-overlaps
   with a higher-priority specific format rule (R001-R005). R011 on a
   different line is always kept.

Stable ordering:
- dirnames and filenames are sorted in os.walk for deterministic traversal.
- Final findings are sorted by (file_path, line_start, column_start,
  rule_priority, rule_id).
- notices, skipped_files, and scan_errors are also stably sorted.

Import structure (no circular imports):
- imports from: base, default_rules, core.config
"""

from __future__ import annotations

import os
from pathlib import Path

from app.core.config import settings
from app.core.security.desensitize import mask_untrusted_text
from app.scanner.base import (
    Finding,
    FindingType,
    ScanError,
    ScanNotice,
    ScanResult,
    SkippedFile,
)
from app.scanner.default_rules import (
    DEFAULT_RULES,
    RULE_PRIORITY_MAP,
)


# ---------------------------------------------------------------------------
# --- Fixed reason codes (never expose exception text or paths) ---
# ---------------------------------------------------------------------------

REASON_STAT_ERROR = "stat_error"
REASON_READ_ERROR = "read_error"
REASON_OUTSIDE_ROOT = "outside_root"
REASON_TOO_LARGE = "too_large"
REASON_BINARY = "binary"

# Example/template env files — documentation, not real config.
# High-confidence format rules still scan them; generic heuristic rules
# (R006-R008) are skipped to avoid noise from placeholder values.
EXAMPLE_ENV_FILES: frozenset[str] = frozenset({".env.example", ".env.sample", ".env.template"})

# Rule IDs that are high-confidence (explicit format / private key).
# These run on ALL files, including template env files.
HIGH_CONFIDENCE_RULE_IDS: frozenset[str] = frozenset({
    "R001_GITHUB_TOKEN",
    "R002_AWS_ACCESS_KEY",
    "R003_AWS_SECRET_KEY",
    "R004_GOOGLE_API_KEY",
    "R005_PRIVATE_KEY",
})

# Fixed error messages — safe to return, contain no sensitive data.
_SAFE_ERROR_MESSAGES: dict[str, str] = {
    REASON_STAT_ERROR: "Unable to read file metadata",
    REASON_READ_ERROR: "Unable to read file content",
    REASON_OUTSIDE_ROOT: "File resolved outside scan root",
}


# ---------------------------------------------------------------------------
# --- Path containment validation (testable internal function) ---
# ---------------------------------------------------------------------------

def _is_path_inside_root(
    file_path: str, root_resolved: Path,
) -> tuple[bool, str | None]:
    """Check if a file path resolves inside the scan root.

    Uses Path.resolve() + relative_to() — NOT os.path.relpath.
    This catches symlink-based escapes that relpath alone cannot detect.

    Args:
        file_path:     Absolute or relative file path (string).
        root_resolved: The resolved scan root directory.

    Returns:
        (is_inside, posix_relative_path):
        - If inside:  (True,  "relative/path/to/file")
        - If outside: (False, None)
        - If unresolvable (OSError): (False, None)
    """
    try:
        file_resolved = Path(file_path).resolve()
        rel_to_root = file_resolved.relative_to(root_resolved)
        return True, rel_to_root.as_posix()
    except ValueError:
        return False, None
    except OSError:
        return False, None


# ---------------------------------------------------------------------------
# --- Deduplication ---
# ---------------------------------------------------------------------------

def _ranges_overlap(a: Finding, b: Finding) -> bool:
    """Check if two content findings have overlapping column ranges on the same line.

    Both findings must be on the same file_path and line_start, and both must
    have non-None column_start/column_end.
    """
    if a.file_path != b.file_path:
        return False
    if a.line_start != b.line_start:
        return False
    if a.column_start is None or a.column_end is None:
        return False
    if b.column_start is None or b.column_end is None:
        return False
    return a.column_start < b.column_end and b.column_start < a.column_end


def _deduplicate_findings(findings: list[Finding]) -> list[Finding]:
    """Deduplicate findings for a single file.

    Steps:
    1. Separate content-type and file-type findings.
    2. Line-level dedup: group content findings by (file_path, line_start),
       sort by priority, keep non-overlapping ones.
    3. File-type findings are kept as-is (they don't overlap with content).

    NOTE: There is NO file-level suppression of R011. R011 is only
    suppressed when it column-overlaps with a higher-priority finding
    on the SAME LINE (handled by step 2).
    """
    if not findings:
        return []

    content_findings = [f for f in findings if f.finding_type == FindingType.CONTENT]
    file_findings = [f for f in findings if f.finding_type == FindingType.FILE]

    # --- Line-level dedup for content findings ---
    # Group by (file_path, line_start)
    groups: dict[tuple[str, int | None], list[Finding]] = {}
    for f in content_findings:
        key = (f.file_path, f.line_start)
        groups.setdefault(key, []).append(f)

    deduped_content: list[Finding] = []
    for key, group in groups.items():
        # Sort by priority (lower number = higher priority)
        group.sort(key=lambda f: RULE_PRIORITY_MAP.get(f.rule_id, 999))

        kept: list[Finding] = []
        for f in group:
            # Check if this finding overlaps with any already-kept finding
            overlaps = False
            for k in kept:
                if _ranges_overlap(f, k):
                    overlaps = True
                    break
            if not overlaps:
                kept.append(f)
        deduped_content.extend(kept)

    return deduped_content + file_findings


# ---------------------------------------------------------------------------
# --- Scanner core ---
# ---------------------------------------------------------------------------

def scan_directory(
    root_dir: Path,
    rules: list | None = None,
) -> ScanResult:
    """Scan a directory for sensitive information.

    Args:
        root_dir: Path to the directory to scan (typically the extracted repo).
        rules:    List of Rule instances. If None, uses DEFAULT_RULES.

    Returns:
        ScanResult with findings, notices, skipped files, and errors.
        All collection fields are tuples (immutable).

    Raises:
        ValueError: If root_dir does not exist or is not a directory.
    """
    if not root_dir.exists():
        raise ValueError("Scan root directory does not exist")
    if not root_dir.is_dir():
        raise ValueError("Scan root path is not a directory")

    if rules is None:
        rules = DEFAULT_RULES

    # Resolve the root once — all files must be inside this resolved path.
    root_resolved = root_dir.resolve()

    all_findings: list[Finding] = []
    all_notices: list[ScanNotice] = []
    all_skipped: list[SkippedFile] = []
    all_errors: list[ScanError] = []
    total_files_scanned = 0
    total_lines_scanned = 0

    ignore_dirs = set(settings.scan_ignore_dirs)
    binary_exts = set(settings.scan_binary_extensions)

    for dirpath, dirnames, filenames in os.walk(str(root_dir)):
        # --- Stable ordering: sort dirnames and filenames ---
        # This ensures deterministic traversal order regardless of
        # filesystem creation order or OS-specific ordering.
        dirnames.sort()
        filenames.sort()

        # --- Remove ignored directories (in-place) ---
        # This includes .git — Git history is NOT scanned.
        dirnames[:] = [
            d for d in dirnames
            if d not in ignore_dirs
        ]

        # --- Remove symlink directories (in-place) ---
        dirnames[:] = [
            d for d in dirnames
            if not os.path.islink(os.path.join(dirpath, d))
        ]

        for filename in filenames:
            full_path = os.path.join(dirpath, filename)

            # --- Skip symlink files ---
            if os.path.islink(full_path):
                continue

            # --- Path containment validation ---
            # Resolve the file path and verify it is inside root_resolved.
            # This catches edge cases where relpath alone is insufficient.
            is_inside, posix_path = _is_path_inside_root(full_path, root_resolved)
            if not is_inside:
                all_skipped.append(SkippedFile(
                    file_path="<outside_root>",
                    reason=REASON_OUTSIDE_ROOT,
                ))
                continue

            if posix_path is None:
                all_skipped.append(SkippedFile(
                    file_path="<unresolvable>",
                    reason=REASON_STAT_ERROR,
                ))
                continue

            # --- Sanitize path for result objects ---
            # File names and directory names are untrusted input — they may
            # contain format-correct secrets (e.g., ghp_XXXX... .py).
            # All result objects use the sanitized path. File system
            # operations continue using the real full_path.
            safe_path = mask_untrusted_text(posix_path)

            # --- Check file size ---
            try:
                file_size = os.path.getsize(full_path)
            except OSError:
                all_errors.append(ScanError(
                    file_path=safe_path,
                    error_type=REASON_STAT_ERROR,
                    error_message=_SAFE_ERROR_MESSAGES[REASON_STAT_ERROR],
                ))
                continue

            if file_size > settings.scan_max_file_size:
                all_skipped.append(SkippedFile(
                    file_path=safe_path,
                    reason=REASON_TOO_LARGE,
                ))
                continue

            # --- Check binary extension ---
            ext = os.path.splitext(filename)[1].lower()
            if ext in binary_exts:
                all_skipped.append(SkippedFile(
                    file_path=safe_path,
                    reason=REASON_BINARY,
                ))
                continue

            # --- Read file content as bytes (bytes-first binary detection) ---
            try:
                with open(full_path, "rb") as f:
                    raw_bytes = f.read()
            except OSError:
                all_errors.append(ScanError(
                    file_path=safe_path,
                    error_type=REASON_READ_ERROR,
                    error_message=_SAFE_ERROR_MESSAGES[REASON_READ_ERROR],
                ))
                continue

            # --- Check for NUL bytes (binary indicator) ---
            if b"\x00" in raw_bytes:
                all_skipped.append(SkippedFile(
                    file_path=safe_path,
                    reason=REASON_BINARY,
                ))
                continue

            # --- Decode as UTF-8-SIG (handles BOM; CRLF via splitlines) ---
            try:
                content = raw_bytes.decode("utf-8-sig")
            except UnicodeDecodeError:
                all_skipped.append(SkippedFile(
                    file_path=safe_path,
                    reason=REASON_BINARY,
                ))
                continue

            lines = content.splitlines()

            # --- No line limit: scan full content ---
            total_files_scanned += 1
            total_lines_scanned += len(lines)

            # --- Run rules ---
            # Template env files (.env.example, .env.sample, .env.template):
            # - File-type rules always run (R010 generates ScanNotice).
            # - High-confidence content rules (R001-R005) still scan to catch
            #   real tokens/keys accidentally committed to template files.
            # - Generic heuristic rules (R006-R008) are skipped to avoid
            #   noise from placeholder values.
            basename = safe_path.split("/")[-1]
            is_example_env = basename in EXAMPLE_ENV_FILES

            file_findings: list[Finding] = []
            for rule in rules:
                if rule.finding_type == FindingType.CONTENT:
                    if is_example_env and rule.rule_id not in HIGH_CONFIDENCE_RULE_IDS:
                        continue
                    file_findings.extend(rule.scan_content(safe_path, lines))
                elif rule.finding_type == FindingType.FILE:
                    result = rule.check_file(safe_path, file_size)
                    if isinstance(result, Finding):
                        file_findings.append(result)
                    elif isinstance(result, ScanNotice):
                        all_notices.append(result)

            # --- Deduplicate findings for this file ---
            deduped = _deduplicate_findings(file_findings)
            all_findings.extend(deduped)

    # --- Stable sorting of all result collections ---
    # Findings: sort by file_path, line_start, column_start, rule_priority, rule_id
    all_findings.sort(key=lambda f: (
        f.file_path,
        f.line_start if f.line_start is not None else -1,
        f.column_start if f.column_start is not None else -1,
        RULE_PRIORITY_MAP.get(f.rule_id, 999),
        f.rule_id,
    ))
    # Notices: sort by file_path, then rule_id
    all_notices.sort(key=lambda n: (n.file_path or "", n.rule_id))
    # Skipped files: sort by file_path, then reason
    all_skipped.sort(key=lambda s: (s.file_path, s.reason))
    # Scan errors: sort by file_path, then error_type
    all_errors.sort(key=lambda e: (e.file_path, e.error_type))

    return ScanResult(
        findings=tuple(all_findings),
        notices=tuple(all_notices),
        skipped_files=tuple(all_skipped),
        scan_errors=tuple(all_errors),
        total_files_scanned=total_files_scanned,
        total_lines_scanned=total_lines_scanned,
    )
