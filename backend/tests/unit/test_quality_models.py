"""Quality report schema invariants (no database required)."""

from __future__ import annotations

from app.quality.models import (
    DIMENSION_BACKEND_COMMENTS,
    DIMENSION_BACKEND_ROUTES,
    DIMENSION_FONT_LICENSE,
    DIMENSION_FRONTEND_DEAD_CODE,
    FIXABILITY_AUTO,
    FIXABILITY_REPORT,
    REASON_ANALYZER_PENDING,
    STATUS_COMPLETED,
    STATUS_NOT_COMPLETED,
    STATUS_PARTIAL,
    QualityBlock,
    QualityEvidence,
    QualityItem,
    QualityReport,
)


def _item(**overrides) -> QualityItem:
    base = dict(
        item_id="item-1",
        dimension=DIMENSION_BACKEND_ROUTES,
        category="unused_route_candidate",
        conclusion="unused_candidate",
        confidence="medium",
        title="仓库内未发现调用方：GET /items",
        severity="P3",
        fixability=FIXABILITY_REPORT,
        manual_decision_required=True,
    )
    base.update(overrides)
    return QualityItem(**base)


def test_manual_items_never_enter_fixable_list():
    block = QualityBlock(
        dimension=DIMENSION_BACKEND_ROUTES,
        status=STATUS_COMPLETED,
        items=[
            _item(),
            _item(
                item_id="item-2",
                manual_decision_required=False,
                fixability=FIXABILITY_AUTO,
            ),
        ],
    )
    data = block.to_dict()
    assert data["fixable_item_ids"] == ["item-2"]
    assert data["manual_confirm_item_ids"] == ["item-1"]


def test_degraded_block_requires_reason_code():
    block = QualityBlock(
        dimension=DIMENSION_FONT_LICENSE,
        status=STATUS_NOT_COMPLETED,
        reason_code=REASON_ANALYZER_PENDING,
        reason_message="字体合规分析将在后续版本接入；本轮未执行。",
    )
    data = block.to_dict()
    assert data["status"] == STATUS_NOT_COMPLETED
    assert data["reason_code"] == REASON_ANALYZER_PENDING
    assert data["reason_message"]


def test_dict_serialization_masks_secrets_in_text_and_evidence():
    item = _item(
        title='password = "s3cur3P@ssw0rd123!"',
        suggestion='password = "s3cur3P@ssw0rd123!"',
        evidence=[
            QualityEvidence(
                method="grep",
                detail="password/secret assignment",
                file_path="config/settings.py",
                snippet='DB_PASSWORD="s3cur3P@ssw0rd123!"',
            )
        ],
    )
    data = item.to_dict()
    serialized = str(data)
    assert "s3cur3P@ssw0rd123!" not in serialized
    assert "<REDACTED>" in serialized


def test_report_summary_and_overall_status_are_explicit():
    report = QualityReport(
        task_id="t1",
        generated_at="2026-01-01T00:00:00+00:00",
        scanner_version="v1",
        blocks={
            DIMENSION_BACKEND_ROUTES: QualityBlock(
                dimension=DIMENSION_BACKEND_ROUTES,
                status=STATUS_COMPLETED,
                items=[_item()],
            ),
            DIMENSION_FONT_LICENSE: QualityBlock(
                dimension=DIMENSION_FONT_LICENSE,
                status=STATUS_NOT_COMPLETED,
                reason_code=REASON_ANALYZER_PENDING,
                reason_message="pending",
            ),
            DIMENSION_FRONTEND_DEAD_CODE: QualityBlock(
                dimension=DIMENSION_FRONTEND_DEAD_CODE,
                status=STATUS_NOT_COMPLETED,
                reason_code=REASON_ANALYZER_PENDING,
                reason_message="pending",
            ),
            DIMENSION_BACKEND_COMMENTS: QualityBlock(
                dimension=DIMENSION_BACKEND_COMMENTS,
                status=STATUS_NOT_COMPLETED,
                reason_code=REASON_ANALYZER_PENDING,
                reason_message="pending",
            ),
        },
    )
    data = report.to_dict()

    assert data["summary"]["total_items"] == 1
    assert data["summary"]["manual_decision_items"] == 1
    assert data["summary"]["fixable_items"] == 0
    assert data["summary"]["blocks_not_completed"] == 3
    assert data["overall_status"] == STATUS_PARTIAL
    assert data["blocks"][DIMENSION_FONT_LICENSE]["reason_code"]
