"""Single-pass repository index shared by quality analyzers.

The index only records path, size and language metadata. File content is read
on demand and capped by the same limits as the core scanner. Build outputs are
excluded from this round because only the route analyzer consumes the index.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from app.core.config import settings

_LANGUAGE_BY_SUFFIX = {
    ".py": "python",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".js": "javascript",
    ".jsx": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".vue": "vue",
    ".svelte": "svelte",
    ".go": "go",
    ".java": "java",
    ".kt": "kotlin",
    ".rb": "ruby",
    ".php": "php",
    ".cs": "csharp",
    ".rs": "rust",
    ".md": "markdown",
    ".mdx": "markdown",
    ".json": "json",
    ".yaml": "yaml",
    ".yml": "yaml",
    ".toml": "toml",
    ".txt": "text",
    ".css": "css",
    ".scss": "css",
    ".sass": "css",
    ".less": "css",
}


@dataclass(frozen=True, slots=True)
class RepoFile:
    """A repository file discovered during the quality-stage walk."""

    rel_path: str
    size: int
    suffix: str
    language: str


class RepositoryIndex:
    """Deterministic file index with bounded text reads."""

    def __init__(self, root: Path) -> None:
        self.root = root.resolve()
        self.files: list[RepoFile] = []
        self._ignored_dirs = set(settings.scan_ignore_dirs)
        self.max_file_size = settings.scan_max_file_size
        self._build()

    def _build(self) -> None:
        for dirpath, dirnames, filenames in os.walk(self.root):
            dirnames[:] = sorted(
                d for d in dirnames if d not in self._ignored_dirs
            )
            for name in sorted(filenames):
                absolute = Path(dirpath) / name
                try:
                    stat = absolute.stat()
                except OSError:
                    continue
                if not absolute.is_file():
                    continue
                rel = os.path.relpath(absolute, self.root).replace(os.sep, "/")
                suffix = absolute.suffix.lower()
                self.files.append(
                    RepoFile(
                        rel_path=rel,
                        size=stat.st_size,
                        suffix=suffix,
                        language=_LANGUAGE_BY_SUFFIX.get(suffix, "other"),
                    )
                )

    def read_text(self, rel_path: str) -> str | None:
        """Read a text file, bounded by the scanner size limit."""
        absolute = (self.root / rel_path).resolve()
        try:
            absolute.relative_to(self.root)
        except ValueError:
            return None
        try:
            if absolute.stat().st_size > self.max_file_size:
                return None
            return absolute.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return None

    def read_bytes(self, rel_path: str, max_bytes: int) -> bytes | None:
        """Read a binary file with an explicit caller-supplied cap.

        Font assets are skipped by the scanner's binary-extension list, so the
        quality stage must read them itself. The cap keeps a hostile archive
        from forcing a multi-megabyte allocation during license parsing.
        """
        absolute = (self.root / rel_path).resolve()
        try:
            absolute.relative_to(self.root)
        except ValueError:
            return None
        try:
            if absolute.stat().st_size > max_bytes:
                return None
            return absolute.read_bytes()
        except OSError:
            return None

    def exists(self, rel_path: str) -> bool:
        return (self.root / rel_path).is_file()

    def by_suffix(self, *suffixes: str) -> list[RepoFile]:
        wanted = set(suffixes)
        return [item for item in self.files if item.suffix in wanted]
