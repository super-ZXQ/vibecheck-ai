"""Structured quality report schema.

The quality report is persisted separately from scan results. Its conclusions
never feed the security score or verdict; it is an informational product
surface with explicit per-block degradation states.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from app.core.security.desensitize import mask_snippet, mask_untrusted_text

QUALITY_SCHEMA_VERSION = 1

DIMENSION_FRONTEND_DEAD_CODE = "frontend_dead_code"
DIMENSION_FONT_LICENSE = "font_license_compliance"
DIMENSION_BACKEND_ROUTES = "backend_route_audit"
DIMENSION_BACKEND_COMMENTS = "backend_comment_quality"

DIMENSIONS = (
    DIMENSION_FRONTEND_DEAD_CODE,
    DIMENSION_FONT_LICENSE,
    DIMENSION_BACKEND_ROUTES,
    DIMENSION_BACKEND_COMMENTS,
)

DIMENSION_LABELS = {
    DIMENSION_FRONTEND_DEAD_CODE: "前端死代码",
    DIMENSION_FONT_LICENSE: "字体合规",
    DIMENSION_BACKEND_ROUTES: "后端路由审计",
    DIMENSION_BACKEND_COMMENTS: "中文注释规范",
}

STATUS_COMPLETED = "completed"
STATUS_PARTIAL = "partial"
STATUS_NOT_COMPLETED = "not_completed"
STATUS_NOT_APPLICABLE = "not_applicable"

BLOCK_STATUSES = (
    STATUS_COMPLETED,
    STATUS_PARTIAL,
    STATUS_NOT_COMPLETED,
    STATUS_NOT_APPLICABLE,
)

REASON_ANALYZER_PENDING = "ANALYZER_PENDING"
REASON_ANALYZER_UNAVAILABLE = "ANALYZER_UNAVAILABLE"
REASON_ANALYZER_TIMEOUT = "ANALYZER_TIMEOUT"
REASON_CANCELLED = "CANCELLED"
REASON_ANALYZER_ERROR = "ANALYZER_ERROR"
REASON_INPUT_MISSING = "INPUT_MISSING"
REASON_PARTIAL_ENUMERATION = "PARTIAL_ENUMERATION"
REASON_UNSUPPORTED_FRAMEWORK = "UNSUPPORTED_FRAMEWORK"
REASON_NO_BACKEND = "NO_BACKEND"
REASON_RUNTIME_UNVERIFIED = "RUNTIME_UNVERIFIED"
REASON_LLM_DISABLED = "LLM_DISABLED"
REASON_RESULT_TRUNCATED = "RESULT_TRUNCATED"

CONFIDENCE_HIGH = "high"
CONFIDENCE_MEDIUM = "medium"
CONFIDENCE_LOW = "low"

FIXABILITY_AUTO = "auto_fix"
FIXABILITY_DIFF = "diff_only"
FIXABILITY_REPORT = "report_only"

_SNIPPET_LIMIT = 200


def _safe_path(value: str) -> str:
    """Mask explicit-format secrets embedded in a repository-relative path."""
    return mask_untrusted_text(value[:1000])


def _safe_text(value: str, limit: int = _SNIPPET_LIMIT) -> str:
    """Mask secrets in free text and bound its size before persistence."""
    return mask_snippet(value[:limit])


def sanitize_json(value: Any) -> Any:
    """Recursively sanitize a report fragment before persistence."""
    if isinstance(value, str):
        return _safe_text(value, limit=500)
    if isinstance(value, list):
        return [sanitize_json(item) for item in value]
    if isinstance(value, tuple):
        return [sanitize_json(item) for item in value]
    if isinstance(value, dict):
        result: dict[str, Any] = {}
        for key, item in value.items():
            if key in {"file_path", "path", "registration_file"} and isinstance(item, str):
                result[key] = _safe_path(item)
            else:
                result[key] = sanitize_json(item)
        return result
    return value


@dataclass(slots=True)
class QualityEvidence:
    """One evidence row tied to a find or to the block-level evidence table."""

    method: str
    detail: str = ""
    file_path: str | None = None
    line_start: int | None = None
    line_end: int | None = None
    snippet: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "method": _safe_text(self.method, limit=80),
            "detail": _safe_text(self.detail, limit=300),
            "file_path": _safe_path(self.file_path) if self.file_path else None,
            "line_start": self.line_start,
            "line_end": self.line_end,
            "snippet": _safe_text(self.snippet) if self.snippet else "",
        }


@dataclass(slots=True)
class QualityItem:
    """A reportable quality finding.

    ``manual_decision_required`` items are never projected into the fixable
    list, even when a suggested diff exists.
    """

    item_id: str
    dimension: str
    category: str
    conclusion: str
    confidence: str
    title: str
    severity: str = "P3"
    impact: str = ""
    suggestion: str = ""
    fixability: str = FIXABILITY_REPORT
    manual_decision_required: bool = False
    limitation: str = ""
    rule_id: str = ""
    evidence: list[QualityEvidence] = field(default_factory=list)
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "item_id": self.item_id,
            "dimension": self.dimension,
            "category": self.category,
            "conclusion": self.conclusion,
            "confidence": self.confidence,
            "severity": self.severity,
            "title": _safe_text(self.title, limit=200),
            "impact": _safe_text(self.impact, limit=300),
            "suggestion": _safe_text(self.suggestion, limit=300),
            "fixability": self.fixability,
            "manual_decision_required": self.manual_decision_required,
            "limitation": _safe_text(self.limitation, limit=300),
            "rule_id": self.rule_id,
            "evidence": [row.to_dict() for row in self.evidence],
            "details": sanitize_json(self.details),
        }


@dataclass(slots=True)
class QualityBlock:
    """Per-dimension report block with explicit status and degradation reason."""

    dimension: str
    status: str
    conclusion: dict[str, Any] = field(default_factory=dict)
    reason_code: str | None = None
    reason_message: str = ""
    evidence: list[QualityEvidence] = field(default_factory=list)
    items: list[QualityItem] = field(default_factory=list)
    verification: dict[str, Any] = field(default_factory=dict)
    coverage: dict[str, Any] = field(default_factory=dict)
    details: dict[str, Any] = field(default_factory=dict)
    truncated: bool = False
    truncation_reason: str = ""

    @property
    def block_id(self) -> str:
        return self.dimension

    @property
    def label(self) -> str:
        return DIMENSION_LABELS[self.dimension]

    def fixable_items(self) -> list[QualityItem]:
        return [
            item
            for item in self.items
            if item.fixability in {FIXABILITY_AUTO, FIXABILITY_DIFF}
            and not item.manual_decision_required
        ]

    def manual_items(self) -> list[QualityItem]:
        return [item for item in self.items if item.manual_decision_required]

    def to_dict(self) -> dict[str, Any]:
        fixable = self.fixable_items()
        manual = self.manual_items()
        return {
            "dimension": self.dimension,
            "label": self.label,
            "status": self.status,
            "reason_code": self.reason_code,
            "reason_message": _safe_text(self.reason_message, limit=300),
            "conclusion": sanitize_json(self.conclusion),
            "evidence": [row.to_dict() for row in self.evidence],
            "items": [item.to_dict() for item in self.items],
            "fixable_item_ids": [item.item_id for item in fixable],
            "manual_confirm_item_ids": [item.item_id for item in manual],
            "verification": sanitize_json(self.verification),
            "coverage": sanitize_json(self.coverage),
            "details": sanitize_json(self.details),
            "truncated": self.truncated,
            "truncation_reason": _safe_text(self.truncation_reason, limit=200),
        }


@dataclass(slots=True)
class QualityReport:
    """Top-level persisted quality report."""

    task_id: str
    generated_at: str
    scanner_version: str
    blocks: dict[str, QualityBlock]
    limitations: list[str] = field(default_factory=list)
    schema_version: int = QUALITY_SCHEMA_VERSION

    def _ordered_blocks(self) -> list[QualityBlock]:
        return [self.blocks[d] for d in DIMENSIONS]

    def summary(self) -> dict[str, Any]:
        all_items = [item for block in self._ordered_blocks() for item in block.items]
        fixable = [
            item
            for block in self._ordered_blocks()
            for item in block.fixable_items()
        ]
        manual = [item for item in all_items if item.manual_decision_required]
        return {
            "total_items": len(all_items),
            "manual_decision_items": len(manual),
            "fixable_items": len(fixable),
            "auto_fixable_items": len(
                [item for item in fixable if item.fixability == FIXABILITY_AUTO]
            ),
            "blocks_completed": len(
                [b for b in self._ordered_blocks() if b.status == STATUS_COMPLETED]
            ),
            "blocks_not_completed": len(
                [
                    b
                    for b in self._ordered_blocks()
                    if b.status == STATUS_NOT_COMPLETED
                ]
            ),
        }

    def overall_status(self) -> str:
        statuses = {block.status for block in self._ordered_blocks()}
        if statuses <= {STATUS_COMPLETED, STATUS_NOT_APPLICABLE}:
            return STATUS_COMPLETED
        if statuses <= {STATUS_PARTIAL, STATUS_COMPLETED, STATUS_NOT_APPLICABLE}:
            return STATUS_PARTIAL
        return STATUS_PARTIAL

    def to_dict(self) -> dict[str, Any]:
        block_dicts = {
            block.dimension: block.to_dict() for block in self._ordered_blocks()
        }
        summary = self.summary()
        return {
            "schema_version": self.schema_version,
            "task_id": self.task_id,
            "generated_at": self.generated_at,
            "scanner_version": _safe_text(self.scanner_version, limit=40),
            "overall_status": self.overall_status(),
            "summary": summary,
            "blocks": block_dicts,
            "limitations": [_safe_text(item, limit=300) for item in self.limitations],
        }
