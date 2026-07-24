"""Scanner core -- secure directory traversal, rule execution, and deduplication.

Security guarantees:
- Path containment: every file is resolved and verified to be inside
  scan_root via Path.resolve() + relative_to(). Files that resolve outside
  the root are skipped as "outside_root". This prevents symlink-based escapes
  that os.path.relpath alone cannot detect.
- Symlink files and symlink directories are always skipped.
- All returned paths use POSIX format (forward slashes).
- Never executes code from the scanned repository.
- File content is read as UTF-8; non-UTF-8 files are skipped as "binary".
- Files larger than scan_max_file_size are skipped as "too_large".
- Files are scanned in FULL -- no line limit, so secrets in later lines
  are never missed.
- All error messages are fixed reason codes -- no str(exception),
  repr(exception), absolute paths, or file content in any output.

Deduplication (per file):
1. Content findings on the same line with overlapping column ranges:
   keep the higher-priority finding (lower RULE_PRIORITY_MAP number).
2. File-type findings never overlap with content-type findings.
3. PRODUCTION_ENV_WITH_SECRET (R011) is suppressed entirely for a file
   if any specific rule (R001-R008) already produced a finding in that file.

Import structure (no circular imports):
- imports from: base, default_rules, core.config
"""

from __future__ import annotations

import os
from pathlib import Path

from app.core.config import settings
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
    SPECIFIC_RULE_IDS,
)


# ---------------------------------------------------------------------------
# --- Fixed reason codes (never expose exception text or paths) ---
# ---------------------------------------------------------------------------

REASON_STAT_ERROR = "stat_error"
REASON_READ_ERROR = "read_error"
REASON_OUTSIDE_ROOT = "outside_root"
REASON_TOO_LARGE = "too_large"
REASON_BINARY = "binary"

# Example/template env files — these are documentation, not real config.
# Content rules are NOT run on them; only file-type rules (e.g. R010 ScanNotice).
EXAMPLE_ENV_FILES: frozenset[str] = frozenset({".env.example", ".env.sample"})

# Fixed error messages — safe to return, contain no sensitive data.
_SAFE_ERROR_MESSAGES: dict[str, str] = {
    REASON_STAT_ERROR: "Unable to read file metadata",
    REASON_READ_ERROR: "Unable to read file content",
    REASON_OUTSIDE_ROOT: "File resolved outside scan root",
}


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
    3. File-level suppression: if any specific rule (R001-R008) produced a
       finding, suppress all R011 findings for this file.
    4. File-type findings are kept as-is (they don't overlap with content).
    """
    if not findings:
        return []

    content_findings = [f for f in findings if f.finding_type == FindingType.CONTENT]
    file_findings = [f for f in findings if f.finding_type == FindingType.FILE]

    # --- Step 1: Line-level dedup for content findings ---
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

    # --- Step 2: File-level suppression of R011 ---
    # Collect files that have specific sensitive findings
    files_with_specific: set[str] = set()
    for f in deduped_content:
        if f.rule_id in SPECIFIC_RULE_IDS:
            files_with_specific.add(f.file_path)
    for f in file_findings:
        if f.rule_id in SPECIFIC_RULE_IDS:
            files_with_specific.add(f.file_path)

    # Suppress R011 findings for files that already have specific findings
    final_content: list[Finding] = []
    for f in deduped_content:
        if f.rule_id == "R011_PRODUCTION_ENV_WITH_SECRET" and f.file_path in files_with_specific:
            continue
        final_content.append(f)

    final_file: list[Finding] = []
    for f in file_findings:
        if f.rule_id == "R011_PRODUCTION_ENV_WITH_SECRET" and f.file_path in files_with_specific:
            continue
        final_file.append(f)

    return final_content + final_file


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
            try:
                file_resolved = Path(full_path).resolve()
                rel_to_root = file_resolved.relative_to(root_resolved)
                posix_path = rel_to_root.as_posix()
            except ValueError:
                # File resolved outside the scan root
                all_skipped.append(SkippedFile(
                    file_path="<outside_root>",
                    reason=REASON_OUTSIDE_ROOT,
                ))
                continue
            except OSError:
                all_skipped.append(SkippedFile(
                    file_path="<unresolvable>",
                    reason=REASON_STAT_ERROR,
                ))
                continue

            # --- Check file size ---
            try:
                file_size = os.path.getsize(full_path)
            except OSError:
                all_errors.append(ScanError(
                    file_path=posix_path,
                    error_type=REASON_STAT_ERROR,
                    error_message=_SAFE_ERROR_MESSAGES[REASON_STAT_ERROR],
                ))
                continue

            if file_size > settings.scan_max_file_size:
                all_skipped.append(SkippedFile(
                    file_path=posix_path,
                    reason=REASON_TOO_LARGE,
                ))
                continue

            # --- Check binary extension ---
            ext = os.path.splitext(filename)[1].lower()
            if ext in binary_exts:
                all_skipped.append(SkippedFile(
                    file_path=posix_path,
                    reason=REASON_BINARY,
                ))
                continue

            # --- Read file content as UTF-8 ---
            try:
                with open(full_path, "r", encoding="utf-8", errors="strict") as f:
                    content = f.read()
            except UnicodeDecodeError:
                all_skipped.append(SkippedFile(
                    file_path=posix_path,
                    reason=REASON_BINARY,
                ))
                continue
            except OSError:
                all_errors.append(ScanError(
                    file_path=posix_path,
                    error_type=REASON_READ_ERROR,
                    error_message=_SAFE_ERROR_MESSAGES[REASON_READ_ERROR],
                ))
                continue

            lines = content.splitlines()

            # --- No line limit: scan full content ---
            total_files_scanned += 1
            total_lines_scanned += len(lines)

            # --- Run rules ---
            # Example env files (.env.example, .env.sample) are documentation.
            # Only file-type rules run on them; content rules are skipped so
            # placeholder values in templates never become security findings.
            basename = posix_path.split("/")[-1]
            is_example_env = basename in EXAMPLE_ENV_FILES

            file_findings: list[Finding] = []
            for rule in rules:
                if rule.finding_type == FindingType.CONTENT:
                    if is_example_env:
                        continue
                    file_findings.extend(rule.scan_content(posix_path, lines))
                elif rule.finding_type == FindingType.FILE:
                    result = rule.check_file(posix_path, file_size)
                    if isinstance(result, Finding):
                        file_findings.append(result)
                    elif isinstance(result, ScanNotice):
                        all_notices.append(result)

            # --- Deduplicate findings for this file ---
            deduped = _deduplicate_findings(file_findings)
            all_findings.extend(deduped)

    return ScanResult(
        findings=tuple(all_findings),
        notices=tuple(all_notices),
        skipped_files=tuple(all_skipped),
        scan_errors=tuple(all_errors),
        total_files_scanned=total_files_scanned,
        total_lines_scanned=total_lines_scanned,
    )
