"""Deterministic, offline font-license audit.

The analyzer enumerates every way a frontend repository can reference a font:

- CSS ``@font-face`` blocks, ``font-family`` declarations, ``@import`` rules
- ``next/font/local`` and ``next/font/google`` calls
- files under ``public``/``static`` and committed build-output ``media`` dirs
- ``data:`` inlined fonts
- npm font packages declared in ``package.json``
- external CDN / Google Fonts stylesheets

License evidence is evaluated in a fixed offline priority order:

1. ``LICENSE``/``OFL.txt`` next to the font asset
2. the font binary's ``name`` table (nameID 13/14)
3. npm package ``license`` metadata (requires ``node_modules``)
4. upstream release page (recorded URL + fetched_at; v1 never fetches)

The tri-state (``verified`` / ``not_distributed`` / ``unverified``) is
computed only from those deterministic channels. No model participates.
"""

from __future__ import annotations

import base64
import json
import os
import posixpath
import re
import struct
import zlib
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from app.quality.models import (
    CONFIDENCE_HIGH,
    CONFIDENCE_LOW,
    CONFIDENCE_MEDIUM,
    DIMENSION_FONT_LICENSE,
    FIXABILITY_REPORT,
    REASON_INPUT_MISSING,
    REASON_PARTIAL_ENUMERATION,
    STATUS_COMPLETED,
    STATUS_NOT_APPLICABLE,
    STATUS_PARTIAL,
    QualityBlock,
    QualityEvidence,
    QualityItem,
)
from app.quality.repository_index import RepoFile, RepositoryIndex

FONT_SUFFIXES = (".ttf", ".otf", ".woff", ".woff2", ".eot")

STATE_VERIFIED = "verified"
STATE_NOT_DISTRIBUTED = "not_distributed"
STATE_UNVERIFIED = "unverified"

_DISTRIBUTION_LOCAL = "distributed_local"
_DISTRIBUTION_INLINE = "distributed_inline"
_DISTRIBUTION_BUILD = "distributed_build_output"
_DISTRIBUTION_EXTERNAL = "external_not_distributed"
_DISTRIBUTION_SYSTEM = "not_distributed"

_MAX_FONT_PARSE_BYTES = 8 * 1024 * 1024
_MAX_BUILD_FONT_FILES = 200
_MAX_BUILD_DIRS = 5000
_MAX_BUILD_FONTS_LISTED = 200
_MAX_PACKAGE_FILES = 50
_MAX_PACKAGE_DEPTH = 2

_BUILD_DIRS = (".next", "dist", "build", "out", ".output", "storybook-static")
_BUILD_SKIP_DIRS = {
    "node_modules",
    ".git",
    "cache",
    "cache-webpack",
    "cache-turbopack",
    ".cache",
}

_LICENSE_FILE_NAMES = (
    "license",
    "license.txt",
    "license.md",
    "ofl",
    "ofl.txt",
    "ofl.md",
    "copying",
    "copying.txt",
    "notice",
    "notice.txt",
    "unlicense",
    "unlicense.txt",
)

_SYSTEM_FAMILIES = {
    "-apple-system",
    "blinkmacsystemfont",
    "roboto",
    "arial",
    "helvetica",
    "helvetica neue",
    "times",
    "times new roman",
    "georgia",
    "garamond",
    "verdana",
    "tahoma",
    "trebuchet ms",
    "courier",
    "courier new",
    "consolas",
    "menlo",
    "monaco",
    "sf mono",
    "cascadia mono",
    "segoe ui",
    "segoe ui mono",
    "pingfang sc",
    "hiragino sans gb",
    "hiragino sans",
    "microsoft yahei",
    "microsoft jhenghei",
    "noto sans cjk sc",
    "source han sans sc",
    "dengxian",
    "simsun",
    "simhei",
    "kaiti",
    "fangsong",
    "lucida grande",
    "lucida sans unicode",
    "palatino",
    "cambria",
    "calibri",
    "optima",
    "geneva",
    "monospace",
    "ui-monospace",
    "ui-sans-serif",
    "ui-serif",
    "ui-rounded",
    "system-ui",
    "sans-serif",
    "serif",
    "cursive",
    "fantasy",
    "emoji",
    "math",
}

_GENERIC_FAMILIES = {
    "inherit",
    "initial",
    "unset",
    "revert",
    "revert-layer",
    "default",
}

_LICENSE_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("OFL-1.1", re.compile(r"sil open font license|open font license|\bofl\b", re.IGNORECASE)),
    ("CC0-1.0", re.compile(r"\bcc0\b|creative commons zero", re.IGNORECASE)),
    ("CC-BY-4.0", re.compile(r"creative commons attribution", re.IGNORECASE)),
    ("Apache-2.0", re.compile(r"apache license", re.IGNORECASE)),
    (
        "MIT",
        re.compile(r"mit license|permission is hereby granted, free of charge", re.IGNORECASE),
    ),
    ("GPL", re.compile(r"gnu general public license|\bgpl\b", re.IGNORECASE)),
    ("BSD", re.compile(r"\bbsd\b", re.IGNORECASE)),
    ("Public Domain", re.compile(r"public domain|unlicense", re.IGNORECASE)),
)

_RESERVED_NAME_RE = re.compile(r"reserved[ -]?font[ -]?name", re.IGNORECASE)
_CSS_COMMENT_RE = re.compile(r"/\*.*?\*/", re.DOTALL)
_FONT_FACE_OPEN_RE = re.compile(r"@font-face\s*\{", re.IGNORECASE)
_FONT_FAMILY_DECL_RE = re.compile(r"font-family\s*:\s*([^;{}]+)", re.IGNORECASE)
_IMPORT_RE = re.compile(
    r"@import\s+(?:url\(\s*)?(?:['\"]?)([^'\");]+)", re.IGNORECASE
)
_URL_RE = re.compile(r"url\(\s*(?:['\"]?)([^'\")]+)(?:['\"]?)\s*\)", re.IGNORECASE)
_GOOGLE_IMPORT_FAMILY_RE = re.compile(r"family=([^&'\")]+)", re.IGNORECASE)
_GOOGLE_NAMED_IMPORT_RE = re.compile(
    r"import\s*\{([^}]*)\}\s*from\s*['\"]next/font/google['\"]"
)
_GOOGLE_DEFAULT_IMPORT_RE = re.compile(
    r"import\s+(\w+)\s+from\s*['\"]next/font/google['\"]"
)
_LOCAL_IMPORT_RE = re.compile(
    r"import\s+(\w+)\s+from\s*['\"]next/font/local['\"]"
)
_JS_STYLE_FAMILY_RE = re.compile(
    r"fontFamily\s*:\s*['\"]([^'\"]+)['\"]"
)
_DATA_URI_RE = re.compile(
    r"data:(?P<mime>font/[a-zA-Z0-9.+-]+)"
    r"(?:;charset=[^;,]+)?(?:;base64)?,(?P<payload>[^'\")\s]+)"
)

_NPM_FONT_PREFIXES = (
    "@fontsource/",
    "@fontsource-variable/",
    "typeface-",
)
_NPM_FONT_PACKAGES = {
    "@ibm/plex",
    "font-awesome",
    "@fortawesome/fontawesome-free",
    "material-icons",
    "@mdi/font",
}


@dataclass(slots=True)
class _LicenseResult:
    """Outcome of the offline license evidence channels for one asset."""

    state: str
    license_name: str = ""
    license_url: str = ""
    reserved_font_name: bool = False
    channels: list[dict[str, Any]] = field(default_factory=list)
    missing: list[str] = field(default_factory=list)


@dataclass(slots=True)
class _AssetRecord:
    """A font file that ships with the repository."""

    rel_path: str
    size: int
    kind: str  # local_asset | build_output | inline_data
    license: _LicenseResult


@dataclass(slots=True)
class _UsedFamily:
    family: str
    file_path: str
    line: int


def analyze_font_licenses(index: RepositoryIndex) -> QualityBlock:
    """Build the font compliance block for a repository index."""
    css_files = index.by_suffix(".css", ".scss", ".sass", ".less")
    frontend_files = [
        item
        for item in index.files
        if item.suffix in {".css", ".scss", ".sass", ".less", ".html", ".htm"}
        or _is_next_font_source(item)
    ]
    source_assets = index.by_suffix(*FONT_SUFFIXES)
    build_assets, build_truncated = _collect_build_fonts(index, source_assets)
    package_fonts = _collect_npm_font_packages(index)

    if not frontend_files and not source_assets and not build_assets and not package_fonts:
        return _not_applicable_block()

    files_by_dir: dict[str, list[str]] = defaultdict(list)
    for item in index.files:
        files_by_dir[posixpath.dirname(item.rel_path)].append(item.rel_path)
    asset_by_path = {item.rel_path: item for item in source_assets}

    used: dict[str, _UsedFamily] = {}
    faces: list[dict[str, Any]] = []
    next_fonts: list[dict[str, Any]] = []
    external_sources: list[dict[str, Any]] = []
    loaded_families: set[str] = set()
    loaded_vars: set[str] = set()
    reference_paths: dict[str, list[dict[str, Any]]] = defaultdict(list)
    referenced: set[str] = set()
    missing_assets: list[dict[str, Any]] = []
    inline_assets: list[_AssetRecord] = []
    parse_issues = 0

    for item in frontend_files:
        source = index.read_text(item.rel_path)
        if source is None:
            parse_issues += 1
            continue
        if item.suffix in {".css", ".scss", ".sass", ".less"}:
            _parse_css(
                item.rel_path,
                source,
                faces=faces,
                used=used,
                external_sources=external_sources,
                loaded_families=loaded_families,
            )
        elif item.suffix in {".html", ".htm"}:
            for declared in _parse_html(
                item.rel_path,
                source,
                used=used,
                external_sources=external_sources,
            ):
                resolved = _locate_asset(
                    index, item.rel_path, declared, asset_by_path
                )
                if resolved is None:
                    missing_assets.append(
                        {
                            "declared": declared,
                            "file_path": item.rel_path,
                            "line": 1,
                            "family": "",
                        }
                    )
                    continue
                referenced.add(resolved)
                reference_paths[resolved].append(
                    {
                        "kind": "html_link",
                        "family": "",
                        "file_path": item.rel_path,
                        "line": 1,
                    }
                )
        elif _is_next_font_source(item):
            parse_issues += _parse_next_font(
                item.rel_path,
                source,
                next_fonts=next_fonts,
                used=used,
                loaded_families=loaded_families,
                loaded_vars=loaded_vars,
            )

    for face in faces:
        family = face["family"]
        if not face["src_urls"] and not face["data_uris"]:
            continue
        if family:
            loaded_families.add(family.lower())
        for url in face["src_urls"]:
            if url.startswith(("http://", "https://", "//")):
                external_sources.append(
                    {
                        "url": url,
                        "kind": "font_face_src",
                        "file_path": face["file_path"],
                        "line": face["line"],
                        "families": [family] if family else [],
                    }
                )
                continue
            resolved = _locate_asset(index, face["file_path"], url, asset_by_path)
            if resolved is None:
                missing_assets.append(
                    {
                        "declared": url,
                        "file_path": face["file_path"],
                        "line": face["line"],
                        "family": family,
                    }
                )
                continue
            referenced.add(resolved)
            reference_paths[resolved].append(
                {
                    "kind": "font_face",
                    "family": family,
                    "file_path": face["file_path"],
                    "line": face["line"],
                }
            )
        for data in face["data_uris"]:
            decoded = _decode_data_uri(data["payload"])
            license = _evaluate_font_bytes(decoded, data["mime"])
            inline_assets.append(
                _AssetRecord(
                    rel_path=f"{face['file_path']}#data-{len(inline_assets) + 1}",
                    size=len(decoded) if decoded is not None else 0,
                    kind="inline_data",
                    license=license,
                )
            )

    for next_font in next_fonts:
        family = next_font["family"]
        if family:
            loaded_families.add(family.lower())
        if next_font["variable"]:
            loaded_vars.add(next_font["variable"])
        if next_font["mode"] == "google":
            external_sources.append(
                {
                    "url": f"next/font/google:{family or next_font['identifier']}",
                    "kind": "next_font_google",
                    "file_path": next_font["file_path"],
                    "line": next_font["line"],
                    "families": [family] if family else [],
                }
            )
            continue
        for declared in next_font["src_paths"]:
            resolved = _locate_asset(
                index, next_font["file_path"], declared, asset_by_path
            )
            if resolved is None:
                missing_assets.append(
                    {
                        "declared": declared,
                        "file_path": next_font["file_path"],
                        "line": next_font["line"],
                        "family": family,
                    }
                )
                continue
            referenced.add(resolved)
            reference_paths[resolved].append(
                {
                    "kind": "next_font_local",
                    "family": family,
                    "file_path": next_font["file_path"],
                    "line": next_font["line"],
                }
            )

    for source in external_sources:
        if source.get("kind") in {"css_import", "html_link"}:
            for family in source.get("families", []):
                loaded_families.add(family.lower())

    # Local assets: referenced, unreferenced, and committed build outputs.
    source_records: list[_AssetRecord] = []
    for item in source_assets:
        license = _evaluate_local_asset(index, item, files_by_dir)
        source_records.append(
            _AssetRecord(
                rel_path=item.rel_path,
                size=item.size,
                kind="local_asset",
                license=license,
            )
        )

    build_records: list[_AssetRecord] = []
    source_by_signature = {
        (posixpath.basename(record.rel_path).lower(), record.size): record
        for record in source_records
    }
    for build in build_assets:
        matched = source_by_signature.get(
            (posixpath.basename(build["rel_path"]).lower(), build["size"])
        )
        if matched is not None:
            license = matched.license
        else:
            license = _unverified_result(
                "构建产物字体未匹配到源字体，无法定位许可文件或二进制 name 表证据"
            )
        build_records.append(
            _AssetRecord(
                rel_path=build["rel_path"],
                size=build["size"],
                kind="build_output",
                license=license,
            )
        )

    all_records = source_records + build_records + inline_assets

    items: list[QualityItem] = []
    classifications: list[dict[str, Any]] = []
    system_families = sorted(
        {used[key].family for key in used if _is_system_family(key)}
    )
    distributed_records = [
        record
        for record in all_records
        if record.kind != "inline_data" or record.size > 0
    ]
    distributed_bytes = sum(record.size for record in distributed_records)

    for record in all_records:
        entry = _asset_entry(record, reference_paths.get(record.rel_path, []))
        classifications.append(entry)
        if record.license.state == STATE_UNVERIFIED:
            items.append(_unverified_asset_item(record, entry))
        elif record.kind in {"local_asset", "build_output"} and record.rel_path not in referenced:
            items.append(_unreferenced_asset_item(record, entry))

    for external in external_sources:
        items.append(_external_font_item(external))

    for package in package_fonts:
        items.append(_npm_font_item(package))

    for face in faces:
        if face["src_urls"] or face["data_uris"]:
            continue
        items.append(
            QualityItem(
                item_id=_item_id("font-face-empty", face["file_path"], face["line"]),
                dimension=DIMENSION_FONT_LICENSE,
                category="font_face_without_source",
                conclusion="missing_source",
                confidence=CONFIDENCE_HIGH,
                severity="P2",
                title=f"@font-face 声明了字体族 {face['family'] or '<unknown>'} 但没有 src",
                impact="浏览器无法加载该字体，声明实际无效。",
                suggestion="补充有效的 src（本地资产路径或明确的远程地址），或删除该声明。",
                fixability=FIXABILITY_REPORT,
                rule_id="font-audit-v1",
                evidence=[_line_evidence(face["file_path"], face["line"])],
            )
        )

    for missing in missing_assets:
        items.append(
            QualityItem(
                item_id=_item_id(
                    "font-missing-asset", missing["file_path"], missing["line"]
                ),
                dimension=DIMENSION_FONT_LICENSE,
                category="missing_font_asset",
                conclusion="missing_asset",
                confidence=CONFIDENCE_HIGH,
                severity="P2",
                title=f"引用的字体文件不存在：{missing['declared']}",
                impact="构建或运行时字体加载会失败，并可能回退到系统字体。",
                suggestion="确认路径拼写与 public 目录映射，或移除失效引用。",
                fixability=FIXABILITY_REPORT,
                rule_id="font-audit-v1",
                evidence=[
                    _line_evidence(missing["file_path"], missing["line"]),
                ],
                details={"declared": missing["declared"], "family": missing["family"]},
            )
        )

    dead_references = _dead_family_items(used, loaded_families, external_sources)
    items.extend(dead_references)
    items = _dedupe_items(items)

    verified_count = len(
        [record for record in distributed_records if record.license.state == STATE_VERIFIED]
    )
    unverified_count = len(
        [record for record in distributed_records if record.license.state == STATE_UNVERIFIED]
    )
    external_count = len(external_sources) + len(package_fonts)
    risk_counts = defaultdict(int)
    for item in items:
        risk_counts[item.severity] += 1

    counts = {
        "font_assets": len(source_assets),
        "distributed_font_assets": len(distributed_records),
        "distributed_bytes": distributed_bytes,
        "build_output_fonts": len(build_records),
        "inline_fonts": len(inline_assets),
        "fonts_verified": verified_count,
        "fonts_unverified": unverified_count,
        "fonts_not_distributed": len(system_families),
        "external_font_sources": external_count,
        "npm_font_packages": len(package_fonts),
        "dead_references": len(dead_references),
        "unreferenced_assets": len(
            [
                record
                for record in source_records
                if record.rel_path not in referenced
            ]
        ),
        "license_risk_items": unverified_count + external_count,
        "risk_p0": risk_counts.get("P0", 0),
        "risk_p1": risk_counts.get("P1", 0),
        "risk_p2": risk_counts.get("P2", 0),
        "risk_p3": risk_counts.get("P3", 0),
    }

    status = STATUS_COMPLETED
    reason_code: str | None = None
    reason_message = ""
    enumeration_issues = parse_issues + (1 if build_truncated else 0)
    if enumeration_issues:
        status = STATUS_PARTIAL
        reason_code = REASON_PARTIAL_ENUMERATION
        reason_message = (
            "部分字体引用无法完整枚举：存在无法解析的样式/配置或构建产物枚举截断，"
            "相关条目按现有证据报告。"
        )

    if items:
        headline = (
            f"随仓库分发的字体资产 {len(distributed_records)} 个（{distributed_bytes} 字节）；"
            f"verified {verified_count} / unverified {unverified_count} / "
            f"not_distributed {len(system_families)}；共 {len(items)} 项待处理"
            f"（P2 {risk_counts.get('P2', 0)} / P3 {risk_counts.get('P3', 0)}）。"
        )
    else:
        headline = (
            "在已覆盖输入范围内未发现问题：未发现随仓库分发的字体文件或授权风险。"
        )

    checks = [
        {
            "name": "css_font_face_enumeration",
            "status": "passed" if not parse_issues else "partial",
            "detail": f"解析 {len(css_files)} 个样式文件，枚举 {len(faces)} 个 @font-face",
        },
        {
            "name": "next_font_enumeration",
            "status": "passed",
            "detail": f"枚举 {len(next_fonts)} 个 next/font 调用",
        },
        {
            "name": "font_binary_name_table",
            "status": "partial",
            "detail": "TTF/OTF/WOFF 使用内置 name 表解析；WOFF2 需 Brotli，v1 不支持",
        },
        {
            "name": "license_file_channel",
            "status": "passed",
            "detail": "字体同目录及上一级 LICENSE/OFL 检索完成",
        },
        {
            "name": "npm_license_channel",
            "status": "skipped",
            "detail": "node_modules 被扫描忽略，无法读取字体包 license 字段",
        },
        {
            "name": "upstream_publish_page",
            "status": "skipped",
            "detail": "v1 默认离线，未抓取上游发布页",
        },
    ]

    uncovered = [
        "上游发布页未抓取（v1 默认离线），第 4 优先级许可证据不可用",
        "node_modules 被扫描忽略，npm 字体包的 license 字段与字体文件无法读取",
        "CDN 与 Google Fonts 字体未随仓库分发，实际许可需人工确认",
    ]
    if any(record.kind == "build_output" for record in build_records):
        uncovered.append("构建产物字体仅按文件名+体积匹配源资产，未做内容哈希比对")
    if build_truncated:
        uncovered.append("构建产物字体枚举达到上限，可能遗漏部分文件")
    if any(item.suffix == ".woff2" for item in source_assets):
        uncovered.append("WOFF2 字体未解析 name 表（需 Brotli 解压）")

    return QualityBlock(
        dimension=DIMENSION_FONT_LICENSE,
        status=status,
        reason_code=reason_code,
        reason_message=reason_message,
        conclusion={
            "headline": headline,
            "counts": counts,
            "tri_state": {
                STATE_VERIFIED: verified_count,
                STATE_UNVERIFIED: unverified_count,
                STATE_NOT_DISTRIBUTED: len(system_families),
            },
        },
        evidence=[
            QualityEvidence(
                method="静态字体枚举",
                detail=(
                    f"{len(faces)} 个 @font-face，{len(next_fonts)} 个 next/font，"
                    f"{len(source_assets)} 个源字体文件，{len(build_records)} 个构建产物字体"
                ),
            )
        ],
        items=items,
        verification={
            "checks_run": checks,
            "uncovered_risks": uncovered,
            "license_evidence_priority": [
                "sibling LICENSE/OFL.txt",
                "font binary name table nameID 13/14",
                "npm package license field",
                "upstream release page (URL + fetched_at)",
            ],
            "offline": True,
        },
        coverage={
            "files_considered": len(frontend_files),
            "css_files": len(css_files),
            "font_assets": len(source_assets),
            "build_outputs": len(build_records),
            "inputs_missing": (
                ["node_modules", "upstream publish pages"]
                if package_fonts or source_assets
                else []
            ),
        },
        details={
            "fonts": classifications[:_MAX_BUILD_FONTS_LISTED],
            "system_family_names": system_families,
            "external_sources": external_sources,
            "npm_font_packages": package_fonts,
            "unreferenced_assets": [
                {"path": record.rel_path, "bytes": record.size}
                for record in source_records
                if record.rel_path not in referenced
            ],
            "build_output_fonts": [
                {"path": record.rel_path, "bytes": record.size}
                for record in build_records
            ],
            "limitations": uncovered,
        },
    )


def _not_applicable_block() -> QualityBlock:
    message = "未检测到前端样式/HTML、next/font 用法或字体资产，字体合规检查不适用。"
    return QualityBlock(
        dimension=DIMENSION_FONT_LICENSE,
        status=STATUS_NOT_APPLICABLE,
        reason_code=REASON_INPUT_MISSING,
        reason_message=message,
        conclusion={"headline": message, "counts": {}},
        coverage={"inputs_missing": ["frontend sources", "font assets"]},
        verification={"checks_run": [], "uncovered_risks": [message]},
    )


def _is_next_font_source(item: RepoFile) -> bool:
    return item.suffix in {".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"}


def _strip_css_comments(source: str) -> str:
    def _blank(match: re.Match[str]) -> str:
        return re.sub(r"[^\n]", " ", match.group(0))

    return _CSS_COMMENT_RE.sub(_blank, source)


def _line_of(source: str, offset: int) -> int:
    return source.count("\n", 0, offset) + 1


def _parse_css(
    rel_path: str,
    source: str,
    *,
    faces: list[dict[str, Any]],
    used: dict[str, _UsedFamily],
    external_sources: list[dict[str, Any]],
    loaded_families: set[str],
) -> None:
    cleaned = _strip_css_comments(source)

    face_spans: list[tuple[int, int]] = []
    for match in _FONT_FACE_OPEN_RE.finditer(cleaned):
        start = match.end()
        depth = 1
        index = start
        while index < len(cleaned) and depth:
            char = cleaned[index]
            if char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
            index += 1
        if depth != 0:
            break
        block = cleaned[start : index - 1]
        face_spans.append((match.start(), index))
        family = _declaration_value(block, "font-family")
        families = _split_families(family)
        src = _declaration_value(block, "src")
        urls = [
            url
            for url in _URL_RE.findall(src)
            if not url.strip().lower().startswith("data:")
        ]
        data_uris = _data_uris(src)
        for name in families:
            face = {
                "family": name,
                "src_urls": urls,
                "data_uris": data_uris,
                "file_path": rel_path,
                "line": _line_of(cleaned, match.start()),
            }
            faces.append(face)
            if urls or data_uris:
                loaded_families.add(name.lower())

    for match in _FONT_FAMILY_DECL_RE.finditer(cleaned):
        if any(start <= match.start() < end for start, end in face_spans):
            continue
        for name in _split_families(match.group(1)):
            key = name.lower()
            if key in used:
                continue
            used[key] = _UsedFamily(
                family=name,
                file_path=rel_path,
                line=_line_of(cleaned, match.start()),
            )

    for match in _IMPORT_RE.finditer(cleaned):
        url = match.group(1).strip()
        if not url.lower().startswith(("http://", "https://", "//")):
            continue
        external_sources.append(
            {
                "url": url,
                "kind": "css_import",
                "file_path": rel_path,
                "line": _line_of(cleaned, match.start()),
                "families": _google_import_families(url),
            }
        )

    for match in _URL_RE.finditer(cleaned):
        url = match.group(1).strip()
        if url.lower().startswith(("http://", "https://", "//")) and "font" in url.lower():
            external_sources.append(
                {
                    "url": url,
                    "kind": "css_url",
                    "file_path": rel_path,
                    "line": _line_of(cleaned, match.start()),
                    "families": _google_import_families(url),
                }
            )


def _parse_html(
    rel_path: str,
    source: str,
    *,
    used: dict[str, _UsedFamily],
    external_sources: list[dict[str, Any]],
) -> list[str]:
    local_assets: list[str] = []
    for match in _IMPORT_RE.finditer(source):
        url = match.group(1).strip()
        if url.lower().startswith(("http://", "https://", "//")):
            external_sources.append(
                {
                    "url": url,
                    "kind": "html_link",
                    "file_path": rel_path,
                    "line": _line_of(source, match.start()),
                    "families": _google_import_families(url),
                }
            )
    for match in re.finditer(
        r"<link[^>]+href\s*=\s*['\"]([^'\"]+)['\"][^>]*>", source, re.IGNORECASE
    ):
        tag_start = source.rfind("<link", 0, match.start() + 1)
        tag = source[tag_start : match.end()] if tag_start >= 0 else match.group(0)
        url = match.group(1).strip()
        is_font = (
            "as=" in tag.lower()
            and "font" in tag.lower()
            or url.lower().endswith(FONT_SUFFIXES)
            or "fonts.googleapis.com" in url.lower()
        )
        if not is_font:
            continue
        if url.lower().startswith(("http://", "https://", "//")):
            external_sources.append(
                {
                    "url": url,
                    "kind": "html_link",
                    "file_path": rel_path,
                    "line": _line_of(source, match.start()),
                    "families": _google_import_families(url),
                }
            )
        else:
            local_assets.append(url)
    for match in _JS_STYLE_FAMILY_RE.finditer(source):
        for name in _split_families(match.group(1)):
            key = name.lower()
            if key not in used:
                used[key] = _UsedFamily(
                    family=name,
                    file_path=rel_path,
                    line=_line_of(source, match.start()),
                )
    return local_assets


def _parse_next_font(
    rel_path: str,
    source: str,
    *,
    next_fonts: list[dict[str, Any]],
    used: dict[str, _UsedFamily],
    loaded_families: set[str],
    loaded_vars: set[str],
) -> int:
    issues = 0

    def _record(identifier: str, mode: str) -> None:
        nonlocal issues
        call = re.search(rf"\b{re.escape(identifier)}\s*\(", source)
        if call is None:
            return
        open_brace = source.find("{", call.end())
        if open_brace < 0:
            issues += 1
            return
        options, complete = _balanced_options(source, open_brace)
        if not complete:
            issues += 1
        family = identifier.replace("_", " ")
        variable = ""
        variable_match = re.search(
            r"variable\s*:\s*['\"]([^'\"]+)['\"]", options
        )
        if variable_match:
            variable = variable_match.group(1)
            loaded_vars.add(variable)
        declarations_match = re.search(
            r"prop\s*:\s*['\"]font-family['\"][^}]*?value\s*:\s*['\"]([^'\"]+)['\"]",
            options,
            re.DOTALL,
        )
        if declarations_match:
            family = declarations_match.group(1)
        src_paths: list[str] = []
        if mode == "local":
            src_paths = _local_font_paths(options)
        next_fonts.append(
            {
                "identifier": identifier,
                "mode": mode,
                "family": family,
                "variable": variable,
                "src_paths": src_paths,
                "file_path": rel_path,
                "line": _line_of(source, call.start()),
            }
        )
        loaded_families.add(family.lower())

    for match in _GOOGLE_NAMED_IMPORT_RE.finditer(source):
        names = match.group(1)
        for part in names.split(","):
            part = part.strip()
            if not part:
                continue
            identifier = part.split(" as ")[0].strip()
            _record(identifier, "google")
    for match in _GOOGLE_DEFAULT_IMPORT_RE.finditer(source):
        _record(match.group(1), "google")
    for match in _LOCAL_IMPORT_RE.finditer(source):
        _record(match.group(1), "local")
    for match in _JS_STYLE_FAMILY_RE.finditer(source):
        for name in _split_families(match.group(1)):
            key = name.lower()
            if key not in used:
                used[key] = _UsedFamily(
                    family=name,
                    file_path=rel_path,
                    line=_line_of(source, match.start()),
                )
    return issues


def _balanced_options(source: str, open_brace: int) -> tuple[str, bool]:
    depth = 0
    index = open_brace
    while index < len(source):
        char = source[index]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return source[open_brace + 1 : index], True
        index += 1
    return source[open_brace + 1 :], False


def _local_font_paths(options: str) -> list[str]:
    paths: list[str] = []
    array_match = re.search(r"src\s*:\s*\[([\s\S]*?)\]", options)
    if array_match:
        for match in re.finditer(r"path\s*:\s*['\"]([^'\"]+)['\"]", array_match.group(1)):
            paths.append(match.group(1))
        for match in re.finditer(r"['\"]([^'\"]+)['\"]", array_match.group(1)):
            value = match.group(1)
            if value.lower().endswith(FONT_SUFFIXES) and value not in paths:
                paths.append(value)
        return paths
    string_match = re.search(r"src\s*:\s*['\"]([^'\"]+)['\"]", options)
    if string_match:
        paths.append(string_match.group(1))
    return paths


def _declaration_value(block: str, name: str) -> str:
    """Read a CSS declaration value, ignoring ``;`` inside ``url(...)``/strings.

    A naive ``[^;]+`` split truncates ``data:`` URIs at ``;base64``, so the
    scanner tracks parenthesis depth and quote state and only ends the value
    at a top-level ``;``.
    """
    match = re.search(rf"{re.escape(name)}\s*:\s*", block, re.IGNORECASE)
    if not match:
        return ""
    chars: list[str] = []
    depth = 0
    quote = ""
    for char in block[match.end() :]:
        if quote:
            chars.append(char)
            if char == quote:
                quote = ""
            continue
        if char in "'\"":
            quote = char
        elif char == "(":
            depth += 1
        elif char == ")":
            depth = max(0, depth - 1)
        elif char in ";}" and depth == 0:
            break
        chars.append(char)
    return "".join(chars).strip()


def _split_families(value: str) -> list[str]:
    names: list[str] = []
    for part in value.split(","):
        name = part.strip().strip("'\"").strip()
        lower = name.lower()
        if not name or lower in _GENERIC_FAMILIES:
            continue
        if lower.startswith("var(") or "var(" in lower:
            continue
        if lower.startswith(("url(", "format(")):
            continue
        names.append(name)
    return names


def _data_uris(src: str) -> list[dict[str, str]]:
    return [
        {"mime": match.group("mime"), "payload": match.group("payload")}
        for match in _DATA_URI_RE.finditer(src)
    ]


def _google_import_families(url: str) -> list[str]:
    families: list[str] = []
    for match in _GOOGLE_IMPORT_FAMILY_RE.finditer(url):
        raw = match.group(1)
        raw = raw.split(":")[0]
        name = raw.replace("+", " ").strip()
        if name:
            families.append(name)
    return families


def _locate_asset(
    index: RepositoryIndex,
    base_file: str,
    declared: str,
    asset_by_path: dict[str, RepoFile],
) -> str | None:
    url = declared.strip().strip("'\"").split("?")[0].split("#")[0]
    if not url or url.lower().startswith(("http://", "https://", "//", "data:")):
        return None
    if url.startswith("/"):
        candidates = [url.lstrip("/"), f"public/{url.lstrip('/')}"]
    else:
        resolved = posixpath.normpath(posixpath.join(posixpath.dirname(base_file), url))
        candidates = [resolved, f"public/{resolved}"]
    for candidate in candidates:
        if candidate in asset_by_path or index.exists(candidate):
            return candidate
    return None


def _collect_build_fonts(
    index: RepositoryIndex, source_assets: list[RepoFile]
) -> tuple[list[dict[str, Any]], bool]:
    known = {item.rel_path for item in source_assets}
    results: list[dict[str, Any]] = []
    visited = 0
    truncated = False
    seen: set[str] = set()
    for dirname in _BUILD_DIRS:
        base = index.root / dirname
        if not base.is_dir():
            continue
        for dirpath, dirnames, filenames in os.walk(base):
            dirnames[:] = sorted(
                name for name in dirnames if name not in _BUILD_SKIP_DIRS
            )
            visited += 1
            if visited > _MAX_BUILD_DIRS:
                truncated = True
                break
            for name in filenames:
                if Path(name).suffix.lower() not in FONT_SUFFIXES:
                    continue
                absolute = Path(dirpath) / name
                try:
                    size = absolute.stat().st_size
                except OSError:
                    continue
                rel = os.path.relpath(absolute, index.root).replace(os.sep, "/")
                if rel in known or rel in seen:
                    continue
                seen.add(rel)
                results.append({"rel_path": rel, "size": size})
                if len(results) >= _MAX_BUILD_FONT_FILES:
                    truncated = True
                    break
            if truncated:
                break
        if truncated:
            break
    return results, truncated


def _collect_npm_font_packages(index: RepositoryIndex) -> list[dict[str, Any]]:
    packages: list[dict[str, Any]] = []
    package_files = [
        item
        for item in index.by_suffix(".json")
        if posixpath.basename(item.rel_path) == "package.json"
        and len(posixpath.normpath(item.rel_path).split("/")) <= _MAX_PACKAGE_DEPTH + 1
    ][:_MAX_PACKAGE_FILES]
    for item in package_files:
        source = index.read_text(item.rel_path)
        if source is None:
            continue
        try:
            payload = json.loads(source)
        except (json.JSONDecodeError, ValueError):
            continue
        if not isinstance(payload, dict):
            continue
        for section in ("dependencies", "devDependencies", "peerDependencies"):
            deps = payload.get(section)
            if not isinstance(deps, dict):
                continue
            for name in deps:
                if not isinstance(name, str) or not _is_font_package(name):
                    continue
                packages.append(
                    {
                        "name": name,
                        "section": section,
                        "file_path": item.rel_path,
                        "version": str(deps.get(name, "")),
                    }
                )
    return _dedupe_packages(packages)


def _is_font_package(name: str) -> bool:
    lower = name.lower()
    return lower.startswith(_NPM_FONT_PREFIXES) or lower in _NPM_FONT_PACKAGES


def _dedupe_packages(packages: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[tuple[str, str]] = set()
    result: list[dict[str, Any]] = []
    for package in packages:
        key = (package["name"], package["file_path"])
        if key in seen:
            continue
        seen.add(key)
        result.append(package)
    return result


def _evaluate_local_asset(
    index: RepositoryIndex,
    item: RepoFile,
    files_by_dir: dict[str, list[str]],
) -> _LicenseResult:
    channels: list[dict[str, Any]] = []
    missing: list[str] = []
    reserved_font_name = False

    license_path = _find_license_file(item.rel_path, files_by_dir)
    if license_path is not None:
        text = index.read_text(license_path)
        if text is None:
            channels.append(
                {"priority": 1, "channel": "sibling_license_file", "status": "unreadable"}
            )
            missing.append("字体旁的许可文件超过读取上限或无法读取")
        else:
            name, reserved_font_name = _classify_license(text)
            if name:
                channels.append(
                    {
                        "priority": 1,
                        "channel": "sibling_license_file",
                        "status": "verified",
                        "license": name,
                        "path": license_path,
                    }
                )
                return _LicenseResult(
                    state=STATE_VERIFIED,
                    license_name=name,
                    reserved_font_name=reserved_font_name,
                    channels=channels,
                    missing=[],
                    license_url="",
                )
            channels.append(
                {
                    "priority": 1,
                    "channel": "sibling_license_file",
                    "status": "unrecognized",
                    "path": license_path,
                }
            )
            missing.append("字体旁的许可文件存在但内容无法识别")
    else:
        channels.append(
            {"priority": 1, "channel": "sibling_license_file", "status": "not_found"}
        )
        missing.append("字体旁未发现 LICENSE/OFL.txt")

    name_info = _read_font_name_table(index, item)
    if name_info is None:
        channels.append(
            {"priority": 2, "channel": "font_binary_name_table", "status": "unreadable"}
        )
        if item.suffix == ".woff2":
            missing.append("WOFF2 字体需要 Brotli 解压才能读取 name 表，v1 未实现")
        elif item.size > _MAX_FONT_PARSE_BYTES:
            missing.append("字体文件超过 8MB 解析上限")
        else:
            missing.append("字体二进制 name 表无法解析或格式不支持")
    else:
        license_text = name_info.get("license_description", "")
        license_url = name_info.get("license_url", "")
        name, reserved_font_name = _classify_license(f"{license_text} {license_url}")
        if name:
            channels.append(
                {
                    "priority": 2,
                    "channel": "font_binary_name_table",
                    "status": "verified",
                    "license": name,
                    "license_url": license_url,
                }
            )
            return _LicenseResult(
                state=STATE_VERIFIED,
                license_name=name,
                license_url=license_url,
                reserved_font_name=reserved_font_name,
                channels=channels,
                missing=[],
            )
        channels.append(
            {
                "priority": 2,
                "channel": "font_binary_name_table",
                "status": "unrecognized",
                "license_description": license_text[:200],
                "license_url": license_url,
            }
        )
        detail = "字体二进制 name 表缺少可识别的 nameID 13/14 许可信息"
        if license_text or license_url:
            detail = "字体二进制 name 表的许可描述无法识别"
        missing.append(detail)

    channels.append(
        {"priority": 3, "channel": "npm_license_field", "status": "unavailable"}
    )
    missing.append("node_modules 未索引，无法读取 npm 包 license 字段")
    channels.append(
        {
            "priority": 4,
            "channel": "upstream_publish_page",
            "status": "not_checked",
            "fetched_at": None,
        }
    )
    missing.append("上游发布页未抓取（v1 默认离线）")

    return _LicenseResult(
        state=STATE_UNVERIFIED,
        reserved_font_name=reserved_font_name,
        channels=channels,
        missing=missing,
    )


def _evaluate_font_bytes(data: bytes | None, mime: str) -> _LicenseResult:
    channels: list[dict[str, Any]] = []
    missing: list[str] = []
    if data is None:
        return _unverified_result("data: 内联字体解码失败或超过解析上限")
    name_info = _parse_font_name_table(data)
    if name_info is None:
        if "woff2" in mime.lower():
            missing.append("data: WOFF2 字体需要 Brotli 解压，v1 未实现")
        else:
            missing.append("data: 内联字体 name 表无法解析")
        channels.append(
            {"priority": 2, "channel": "font_binary_name_table", "status": "unreadable"}
        )
    else:
        combined = (
            f"{name_info.get('license_description', '')} "
            f"{name_info.get('license_url', '')}"
        )
        name, reserved_font_name = _classify_license(combined)
        if name:
            channels.append(
                {
                    "priority": 2,
                    "channel": "font_binary_name_table",
                    "status": "verified",
                    "license": name,
                    "license_url": name_info.get("license_url", ""),
                }
            )
            return _LicenseResult(
                state=STATE_VERIFIED,
                license_name=name,
                license_url=name_info.get("license_url", ""),
                reserved_font_name=reserved_font_name,
                channels=channels,
                missing=[],
            )
        missing.append("data: 内联字体的 name 表许可描述无法识别")
        channels.append(
            {"priority": 2, "channel": "font_binary_name_table", "status": "unrecognized"}
        )

    channels.append({"priority": 1, "channel": "sibling_license_file", "status": "not_found"})
    missing.append("data: 内联字体没有独立的许可文件")
    channels.append({"priority": 4, "channel": "upstream_publish_page", "status": "not_checked"})
    missing.append("上游发布页未抓取（v1 默认离线）")
    return _LicenseResult(state=STATE_UNVERIFIED, channels=channels, missing=missing)


def _unverified_result(reason: str) -> _LicenseResult:
    return _LicenseResult(
        state=STATE_UNVERIFIED,
        channels=[{"priority": 0, "channel": "input", "status": "unavailable"}],
        missing=[reason, "上游发布页未抓取（v1 默认离线）"],
    )


def _find_license_file(
    rel_path: str, files_by_dir: dict[str, list[str]]
) -> str | None:
    directory = posixpath.dirname(rel_path)
    for _ in range(2):
        for candidate in files_by_dir.get(directory, []):
            if posixpath.basename(candidate).lower() in _LICENSE_FILE_NAMES:
                return candidate
        if not directory:
            break
        directory = posixpath.dirname(directory)
    return None


def _classify_license(text: str) -> tuple[str | None, bool]:
    reserved = bool(_RESERVED_NAME_RE.search(text))
    for name, pattern in _LICENSE_PATTERNS:
        if pattern.search(text):
            return name, reserved
    return None, reserved


def _read_font_name_table(
    index: RepositoryIndex, item: RepoFile
) -> dict[str, str] | None:
    if item.size > _MAX_FONT_PARSE_BYTES:
        return None
    data = index.read_bytes(item.rel_path, _MAX_FONT_PARSE_BYTES)
    if data is None:
        return None
    return _parse_font_name_table(data)


def _parse_font_name_table(data: bytes) -> dict[str, str] | None:
    if not data:
        return None
    if data[:4] == b"wOF2":
        return None
    if data[:4] == b"wOFF":
        table = _woff_name_table(data)
        return _parse_name_table(table) if table is not None else None
    if data[:4] == b"ttcf":
        if len(data) < 16:
            return None
        offset = struct.unpack(">I", data[12:16])[0]
        if offset <= 0 or offset >= len(data):
            return None
        table = _sfnt_name_table(data, offset)
        return _parse_name_table(table) if table is not None else None
    if data[:4] not in {b"\x00\x01\x00\x00", b"OTTO", b"true", b"typ1"}:
        return None
    table = _sfnt_name_table(data, 0)
    return _parse_name_table(table) if table is not None else None


def _sfnt_name_table(data: bytes, base: int) -> bytes | None:
    if len(data) < base + 12:
        return None
    num_tables = struct.unpack(">H", data[base + 4 : base + 6])[0]
    if num_tables <= 0 or num_tables > 512:
        return None
    for index in range(num_tables):
        record = base + 12 + 16 * index
        if record + 16 > len(data):
            return None
        tag = data[record : record + 4]
        offset = struct.unpack(">I", data[record + 8 : record + 12])[0]
        length = struct.unpack(">I", data[record + 12 : record + 16])[0]
        if tag == b"name":
            if offset < 0 or length <= 0 or offset + length > len(data):
                return None
            return data[offset : offset + length]
    return None


def _woff_name_table(data: bytes) -> bytes | None:
    if len(data) < 44:
        return None
    num_tables = struct.unpack(">H", data[12:14])[0]
    if num_tables <= 0 or num_tables > 512:
        return None
    for index in range(num_tables):
        record = 44 + 20 * index
        if record + 20 > len(data):
            return None
        tag = data[record : record + 4]
        if tag != b"name":
            continue
        offset = struct.unpack(">I", data[record + 4 : record + 8])[0]
        comp_length = struct.unpack(">I", data[record + 8 : record + 12])[0]
        orig_length = struct.unpack(">I", data[record + 12 : record + 16])[0]
        if offset <= 0 or comp_length <= 0 or offset + comp_length > len(data):
            return None
        raw = data[offset : offset + comp_length]
        if comp_length < orig_length:
            try:
                return zlib.decompress(raw)
            except zlib.error:
                return None
        return raw
    return None


def _parse_name_table(table: bytes) -> dict[str, str] | None:
    if len(table) < 6:
        return None
    _format, count, string_offset = struct.unpack(">HHH", table[:6])
    if count <= 0 or count > 4096:
        return None
    entries: list[tuple[int, int, int, str]] = []
    for index in range(count):
        record = 6 + 12 * index
        if record + 12 > len(table):
            break
        platform, _encoding, language, name_id, length, offset = struct.unpack(
            ">HHHHHH", table[record : record + 12]
        )
        if name_id not in (13, 14):
            continue
        start = string_offset + offset
        end = start + length
        if length <= 0 or start < 0 or end > len(table):
            continue
        raw = table[start:end]
        if platform in (0, 3):
            try:
                text = raw.decode("utf-16-be")
            except UnicodeDecodeError:
                continue
        else:
            text = raw.decode("latin-1", errors="replace")
        text = text.strip("\x00").strip()
        if text:
            entries.append((name_id, platform, language, text))

    if not entries:
        return None
    preferred = sorted(
        entries,
        key=lambda row: (
            0 if row[0] == 13 else 1,
            0 if row[1] == 3 and row[2] in (0x0409, 0) else 1,
            0 if row[1] == 0 else 1,
        ),
    )
    result: dict[str, str] = {}
    for name_id, _platform, _language, text in preferred:
        key = "license_description" if name_id == 13 else "license_url"
        result.setdefault(key, text)
    return result


def _decode_data_uri(payload: str) -> bytes | None:
    try:
        data = base64.b64decode(payload, validate=False)
    except (ValueError, TypeError):
        return None
    if len(data) > _MAX_FONT_PARSE_BYTES:
        return None
    return data


def _asset_entry(
    record: _AssetRecord, references: list[dict[str, Any]]
) -> dict[str, Any]:
    return {
        "fingerprint": record.rel_path,
        "path": None if record.kind == "inline_data" else record.rel_path,
        "kind": record.kind,
        "bytes": record.size,
        "license_state": record.license.state,
        "license": record.license.license_name or None,
        "license_url": record.license.license_url or None,
        "reserved_font_name": record.license.reserved_font_name,
        "evidence_channels": record.license.channels,
        "missing_evidence": record.license.missing,
        "references": references,
    }


def _unverified_asset_item(record: _AssetRecord, entry: dict[str, Any]) -> QualityItem:
    return QualityItem(
        item_id=_item_id("font-license-unverified", record.rel_path),
        dimension=DIMENSION_FONT_LICENSE,
        category="font_license_unverified",
        conclusion="unverified",
        confidence=CONFIDENCE_LOW,
        severity="P2",
        title=f"字体许可无法离线确认：{record.rel_path}",
        impact="无法确认该字体是否允许随项目分发；不确定，需人工决策。",
        suggestion="补充 OFL/LICENSE 文件，或核实字体二进制的 name 表许可描述后再分发。",
        fixability=FIXABILITY_REPORT,
        manual_decision_required=True,
        limitation="不确定，需人工决策：离线许可证据缺失。",
        rule_id="font-audit-v1",
        evidence=[
            QualityEvidence(
                method="字体许可证据链",
                detail="；".join(record.license.missing[:3]) or "未取得可识别的许可证据",
                file_path=(
                    None if record.kind == "inline_data" else record.rel_path
                ),
            )
        ],
        details=entry,
    )


def _unreferenced_asset_item(record: _AssetRecord, entry: dict[str, Any]) -> QualityItem:
    return QualityItem(
        item_id=_item_id("font-unreferenced", record.rel_path),
        dimension=DIMENSION_FONT_LICENSE,
        category="unreferenced_font_asset",
        conclusion="unused_candidate",
        confidence=CONFIDENCE_MEDIUM,
        severity="P3",
        title=f"未被引用的字体资产：{record.rel_path}（{record.size} 字节）",
        impact="字体文件随仓库分发但未被任何 @font-face/next/font 引用，占用体积。",
        suggestion="确认是否仍需分发；删除前检查构建脚本、内联样式与外部引用。",
        fixability=FIXABILITY_REPORT,
        rule_id="font-audit-v1",
        evidence=[
            QualityEvidence(
                method="静态引用检索",
                detail="未在 @font-face、next/font/local 或字体 URL 中找到引用",
                file_path=record.rel_path,
            )
        ],
        details={"path": record.rel_path, "bytes": record.size, "license": entry},
    )


def _external_font_item(external: dict[str, Any]) -> QualityItem:
    return QualityItem(
        item_id=_item_id("font-external", external["url"], external["file_path"]),
        dimension=DIMENSION_FONT_LICENSE,
        category="external_font_source",
        conclusion="manual_confirm",
        confidence=CONFIDENCE_MEDIUM,
        severity="P2",
        title=f"外部字体源需人工确认许可：{external['url']}",
        impact="字体未随仓库分发，但运行时/构建时仍依赖第三方许可与服务条款。",
        suggestion="确认字体提供方的许可与自托管要求；必要时改为随仓库分发并附许可文件。",
        fixability=FIXABILITY_REPORT,
        manual_decision_required=True,
        limitation="CDN/Google Fonts 许可与服务条款需人工确认。",
        rule_id="font-audit-v1",
        evidence=[
            _line_evidence(external["file_path"], external["line"]),
        ],
        details={
            "url": external["url"],
            "kind": external["kind"],
            "families": external.get("families", []),
        },
    )


def _npm_font_item(package: dict[str, Any]) -> QualityItem:
    return QualityItem(
        item_id=_item_id("font-npm", package["name"], package["file_path"]),
        dimension=DIMENSION_FONT_LICENSE,
        category="npm_font_package",
        conclusion="unverified",
        confidence=CONFIDENCE_LOW,
        severity="P2",
        title=f"npm 字体包许可无法确认：{package['name']}",
        impact="字体包会被打包进产物，但 node_modules 未索引，无法读取包内 license 与字体文件。",
        suggestion="在构建环境核对包的 license 字段与字体文件的许可文件；不确定，需人工决策。",
        fixability=FIXABILITY_REPORT,
        manual_decision_required=True,
        limitation="node_modules 被忽略，npm 字体包证据不全。",
        rule_id="font-audit-v1",
        evidence=[
            QualityEvidence(
                method="package.json 依赖声明",
                detail=f"{package['section']} {package['name']}@{package['version']}",
                file_path=package["file_path"],
            )
        ],
        details=package,
    )


def _dead_family_items(
    used: dict[str, _UsedFamily],
    loaded_families: set[str],
    external_sources: list[dict[str, Any]],
) -> list[QualityItem]:
    items: list[QualityItem] = []
    external_stylesheets = [
        source
        for source in external_sources
        if source.get("kind") in {"css_import", "html_link"}
    ]
    for key, usage in used.items():
        if _is_system_family(key) or _is_generic_family(key):
            continue
        if key in loaded_families:
            continue
        manual = bool(external_stylesheets)
        limitation = (
            "外部样式表可能提供该字体族，需人工确认。"
            if manual
            else "未发现任何加载该字体族的 @font-face、next/font 或外部字体源。"
        )
        items.append(
            QualityItem(
                item_id=_item_id("font-dead-reference", key, usage.file_path),
                dimension=DIMENSION_FONT_LICENSE,
                category="dead_font_reference",
                conclusion="declared_not_loaded",
                confidence=CONFIDENCE_HIGH,
                severity="P3",
                title=f"声明但从未加载的字体族：{usage.family}",
                impact="浏览器会回退到后续字体，声明不生效，视觉一致性依赖本机字体。",
                suggestion="加载该字体（@font-face/next/font）或从字体栈中移除。",
                fixability=FIXABILITY_REPORT,
                manual_decision_required=manual,
                limitation=limitation,
                rule_id="font-audit-v1",
                evidence=[
                    _line_evidence(usage.file_path, usage.line),
                ],
                details={"family": usage.family, "external_stylesheet_present": manual},
            )
        )
    return items


def _is_system_family(key: str) -> bool:
    return key in _SYSTEM_FAMILIES


def _is_generic_family(key: str) -> bool:
    return key in _GENERIC_FAMILIES


def _line_evidence(file_path: str, line: int) -> QualityEvidence:
    return QualityEvidence(
        method="静态声明位置",
        detail=f"{file_path}:{line}",
        file_path=file_path,
        line_start=line,
        line_end=line,
    )


def _item_id(prefix: str, *parts: str) -> str:
    slug = "-".join(_slug(str(part)) for part in parts if part)
    return f"{prefix}-{slug}"[:160]


def _slug(value: str) -> str:
    slug = re.sub(r"[^a-zA-Z0-9]+", "-", value).strip("-").lower()
    return slug or "x"


def _dedupe_items(items: list[QualityItem]) -> list[QualityItem]:
    seen: set[str] = set()
    result: list[QualityItem] = []
    for item in items:
        if item.item_id in seen:
            continue
        seen.add(item.item_id)
        result.append(item)
    return result
