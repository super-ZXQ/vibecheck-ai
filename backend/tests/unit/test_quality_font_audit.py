"""Deterministic offline font-license audit tests (no database required)."""

from __future__ import annotations

import base64
import struct
from pathlib import Path

from app.quality.analyzers.font_audit import (
    STATE_UNVERIFIED,
    STATE_VERIFIED,
    analyze_font_licenses,
)
from app.quality.models import (
    REASON_INPUT_MISSING,
    STATUS_COMPLETED,
    STATUS_NOT_APPLICABLE,
)
from app.quality.repository_index import RepositoryIndex

GOLDEN_REPO = Path(__file__).resolve().parents[3]


def _write(root: Path, files: dict[str, str | bytes]) -> RepositoryIndex:
    for rel, content in files.items():
        target = root / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, bytes):
            target.write_bytes(content)
        else:
            target.write_text(content, encoding="utf-8")
    return RepositoryIndex(root)


def _name_table(entries: list[tuple[int, str]]) -> bytes:
    count = len(entries)
    records = b""
    storage = b""
    string_offset = 6 + 12 * count
    for name_id, text in entries:
        raw = text.encode("utf-16-be")
        records += struct.pack(">HHHHHH", 3, 1, 0x0409, name_id, len(raw), len(storage))
        storage += raw
    return struct.pack(">HHH", 0, count, string_offset) + records + storage


def _sfnt(name_table: bytes) -> bytes:
    header = struct.pack(">IHHHH", 0x00010000, 1, 0, 0, 0)
    table_offset = 12 + 16
    record = b"name" + struct.pack(">III", 0, table_offset, len(name_table))
    return header + record + name_table


def _ttf(license_text: str = "", license_url: str = "") -> bytes:
    entries: list[tuple[int, str]] = []
    if license_text:
        entries.append((13, license_text))
    if license_url:
        entries.append((14, license_url))
    return _sfnt(_name_table(entries)) if entries else _sfnt(_name_table([(1, "Test")]))


def _font_face_css(url: str = "/fonts/Test.ttf") -> str:
    return (
        "@font-face {\n"
        "  font-family: 'TestFont';\n"
        f"  src: url('{url}') format('truetype');\n"
        "}\n"
        "body { font-family: 'TestFont', sans-serif; }\n"
    )


def test_sibling_ofl_verifies_asset_and_reports_unreferenced(tmp_path):
    index = _write(
        tmp_path,
        {
            "frontend/app/globals.css": _font_face_css(),
            "public/fonts/Test.ttf": _ttf(),
            "public/fonts/OFL.txt": "SIL Open Font License 1.1",
            "public/fonts/Unused.ttf": _ttf(),
            "public/fonts/Unused-OFL.txt": "SIL Open Font License 1.1",
        },
    )
    block = analyze_font_licenses(index)
    data = block.to_dict()
    assert data["status"] == STATUS_COMPLETED
    counts = data["conclusion"]["counts"]
    assert counts["distributed_font_assets"] == 2
    assert counts["fonts_verified"] == 2
    assert counts["fonts_unverified"] == 0
    assert counts["unreferenced_assets"] == 1

    unreferenced = [
        item
        for item in data["items"]
        if item["category"] == "unreferenced_font_asset"
    ]
    assert len(unreferenced) == 1
    assert unreferenced[0]["details"]["bytes"] > 0
    assert "字节" in unreferenced[0]["title"]


def test_missing_license_is_unverified_with_manual_decision_and_evidence(tmp_path):
    index = _write(
        tmp_path,
        {
            "frontend/app/globals.css": _font_face_css(),
            "public/fonts/Test.ttf": _ttf(),
        },
    )
    data = analyze_font_licenses(index).to_dict()
    assert data["conclusion"]["counts"]["fonts_unverified"] == 1
    assert data["conclusion"]["counts"]["license_risk_items"] >= 1

    unverified = [
        item
        for item in data["items"]
        if item["category"] == "font_license_unverified"
    ]
    assert len(unverified) == 1
    item = unverified[0]
    assert item["manual_decision_required"] is True
    assert "不确定" in item["limitation"]
    assert item["details"]["missing_evidence"]
    assert item["details"]["license_state"] == STATE_UNVERIFIED


def test_binary_name_table_license_verifies_without_sibling_file(tmp_path):
    index = _write(
        tmp_path,
        {
            "frontend/app/globals.css": _font_face_css(),
            "public/fonts/Test.ttf": _ttf("SIL Open Font License 1.1"),
        },
    )
    data = analyze_font_licenses(index).to_dict()
    assert data["conclusion"]["counts"]["fonts_verified"] == 1
    assert data["conclusion"]["counts"]["license_risk_items"] == 0
    font = data["details"]["fonts"][0]
    assert font["license_state"] == STATE_VERIFIED
    assert font["license"] == "OFL-1.1"
    assert font["evidence_channels"][-1]["channel"] == "font_binary_name_table"


def test_woff2_is_explicitly_unverified_and_documented(tmp_path):
    index = _write(
        tmp_path,
        {
            "frontend/app/globals.css": _font_face_css("/fonts/Test.woff2"),
            "public/fonts/Test.woff2": b"wOF2" + b"\x00" * 40,
        },
    )
    data = analyze_font_licenses(index).to_dict()
    assert data["conclusion"]["counts"]["fonts_unverified"] == 1
    unverified = next(
        item
        for item in data["items"]
        if item["category"] == "font_license_unverified"
    )
    assert any("WOFF2" in row for row in unverified["details"]["missing_evidence"])
    limitations = data["details"]["limitations"]
    assert any("WOFF2" in row for row in limitations)


def test_system_font_stack_is_not_distributed_with_zero_findings(tmp_path):
    index = _write(
        tmp_path,
        {
            "frontend/app/globals.css": (
                "body { font-family: system-ui, -apple-system, sans-serif; }\n"
            ),
        },
    )
    data = analyze_font_licenses(index).to_dict()
    counts = data["conclusion"]["counts"]
    assert counts["fonts_not_distributed"] >= 1
    assert counts["distributed_font_assets"] == 0
    assert counts["license_risk_items"] == 0
    assert data["items"] == []
    assert "在已覆盖输入范围内未发现问题" in data["conclusion"]["headline"]


def test_dead_family_reference_and_external_import(tmp_path):
    index = _write(
        tmp_path,
        {
            "frontend/app/globals.css": (
                "@import url('https://fonts.googleapis.com/css2?family=Inter');\n"
                "body { font-family: 'Inter', sans-serif; }\n"
                "h1 { font-family: 'Missing', sans-serif; }\n"
            ),
        },
    )
    data = analyze_font_licenses(index).to_dict()
    dead = [item for item in data["items"] if item["category"] == "dead_font_reference"]
    assert len(dead) == 1
    assert "Missing" in dead[0]["title"]
    external = [item for item in data["items"] if item["category"] == "external_font_source"]
    assert len(external) == 1
    assert external[0]["manual_decision_required"] is True


def test_inline_data_uri_counts_as_distributed(tmp_path):
    payload = base64.b64encode(_ttf("SIL Open Font License 1.1")).decode("ascii")
    index = _write(
        tmp_path,
        {
            "frontend/app/globals.css": (
                "@font-face {\n"
                "  font-family: 'InlineFont';\n"
                f"  src: url('data:font/ttf;base64,{payload}') format('truetype');\n"
                "}\n"
            ),
        },
    )
    data = analyze_font_licenses(index).to_dict()
    counts = data["conclusion"]["counts"]
    assert counts["inline_fonts"] == 1
    assert counts["distributed_font_assets"] == 1
    assert counts["fonts_verified"] == 1


def test_next_font_local_and_google(tmp_path):
    index = _write(
        tmp_path,
        {
            "frontend/app/layout.tsx": (
                "import localFont from 'next/font/local'\n"
                "import { Inter } from 'next/font/google'\n"
                "const local = localFont({ src: '/fonts/Test.ttf' })\n"
                "const inter = Inter({ subsets: ['latin'] })\n"
            ),
            "public/fonts/Test.ttf": _ttf("SIL Open Font License 1.1"),
        },
    )
    data = analyze_font_licenses(index).to_dict()
    counts = data["conclusion"]["counts"]
    assert counts["fonts_verified"] == 1
    assert counts["external_font_sources"] == 1
    assert counts["dead_references"] == 0


def test_npm_font_package_is_unverified_due_to_ignored_node_modules(tmp_path):
    index = _write(
        tmp_path,
        {
            "frontend/package.json": (
                '{"dependencies": {"@fontsource/inter": "5.0.0"}}'
            ),
        },
    )
    data = analyze_font_licenses(index).to_dict()
    assert data["conclusion"]["counts"]["npm_font_packages"] == 1
    npm_items = [
        item for item in data["items"] if item["category"] == "npm_font_package"
    ]
    assert len(npm_items) == 1
    assert npm_items[0]["manual_decision_required"] is True
    assert any("node_modules" in row for row in data["details"]["limitations"])


def test_build_output_font_without_source_is_unverified(tmp_path):
    index = _write(
        tmp_path,
        {
            "frontend/app/globals.css": _font_face_css(),
            ".next/static/media/Test.ttf": _ttf(),
        },
    )
    data = analyze_font_licenses(index).to_dict()
    counts = data["conclusion"]["counts"]
    assert counts["build_output_fonts"] == 1
    assert counts["fonts_unverified"] >= 1


def test_empty_repo_is_not_applicable(tmp_path):
    data = analyze_font_licenses(RepositoryIndex(tmp_path)).to_dict()
    assert data["status"] == STATUS_NOT_APPLICABLE
    assert data["reason_code"] == REASON_INPUT_MISSING


def test_golden_repo_has_no_distributed_fonts_or_license_risk():
    data = analyze_font_licenses(RepositoryIndex(GOLDEN_REPO)).to_dict()
    counts = data["conclusion"]["counts"]
    assert counts["distributed_font_assets"] == 0
    assert counts["license_risk_items"] == 0
    assert counts["risk_p0"] == 0
    assert counts["risk_p1"] == 0
    assert data["status"] == STATUS_COMPLETED

    items = data["items"]
    categories = {item["category"] for item in items}
    assert categories <= {"dead_font_reference"}
    assert all(item["severity"] == "P3" for item in items)


def test_distributed_system_family_is_not_double_counted(tmp_path):
    index = _write(
        tmp_path,
        {
            "src/app.css": (
                "@font-face { font-family: 'Arial'; "
                "src: url('/fonts/Arial.ttf') format('truetype'); }\n"
                "body { font-family: Arial; }\n"
            ),
            "public/fonts/Arial.ttf": _ttf(),
            "public/fonts/OFL.txt": "SIL OPEN FONT LICENSE Version 1.1\n",
        },
    )
    block = analyze_font_licenses(index)
    counts = block.to_dict()["conclusion"]["counts"]
    assert counts["distributed_font_assets"] >= 1
    assert counts["fonts_not_distributed"] == 0
