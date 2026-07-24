"""Scanner core -- secure directory traversal, rule execution, and deduplication.

Security guarantees:
- Path traversal: calculates rel_path BEFORE use, skips symlink files,
  removes symlink directories from os.walk dirs list, all returned paths
  use POSIX format (forward slashes).
- Never executes code from the scanned repository.
- File content is read as UTF-8; non-UTF-8 files are skipped as "binary".
- Files larger than scan_max_file_size are skipped as "too_large".
- Files with binary extensions are skipped as "binary".
- Only the first max_line_read lines of each file are scanned.

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
        raise ValueError(f"Directory does not exist: {root_dir}")
    if not root_dir.is_dir():
        raise ValueError(f"Path is not a directory: {root_dir}")

    if rules is None:
        rules = DEFAULT_RULES

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

            # --- Calculate rel_path BEFORE using it ---
            rel_path = os.path.relpath(full_path, str(root_dir))
            # Convert to POSIX format (forward slashes)
            posix_path = Path(rel_path).as_posix()

            # --- Check file size ---
            try:
                file_size = os.path.getsize(full_path)
            except OSError:
                all_errors.append(ScanError(
                    file_path=posix_path,
                    error_type="stat_error",
                    error_message="Unable to read file metadata",
                ))
                continue

            if file_size > settings.scan_max_file_size:
                all_skipped.append(SkippedFile(
                    file_path=posix_path,
                    reason="too_large",
                ))
                continue

            # --- Check binary extension ---
            ext = os.path.splitext(filename)[1].lower()
            if ext in binary_exts:
                all_skipped.append(SkippedFile(
                    file_path=posix_path,
                    reason="binary",
                ))
                continue

            # --- Read file content as UTF-8 ---
            try:
                with open(full_path, "r", encoding="utf-8", errors="strict") as f:
                    content = f.read()
            except UnicodeDecodeError:
                all_skipped.append(SkippedFile(
                    file_path=posix_path,
                    reason="binary",
                ))
                continue
            except OSError as e:
                all_errors.append(ScanError(
                    file_path=posix_path,
                    error_type="read_error",
                    error_message=f"Unable to read file: {type(e).__name__}",
                ))
                continue

            lines = content.splitlines()

            # --- Limit lines read ---
            if len(lines) > settings.max_line_read:
                lines = lines[:settings.max_line_read]

            total_files_scanned += 1
            total_lines_scanned += len(lines)

            # --- Run rules ---
            file_findings: list[Finding] = []
            for rule in rules:
                if rule.finding_type == FindingType.CONTENT:
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
