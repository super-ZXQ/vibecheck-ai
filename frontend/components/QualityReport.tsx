"use client";

import type {
  QualityBlock,
  QualityItem,
  QualityReport as QualityReportData,
} from "@/lib/types";
import {
  formatQualityCounts,
  qualityStatusMeta,
  splitQualityItems,
} from "@/lib/quality-report.mjs";

const BLOCK_ORDER = [
  "frontend_dead_code",
  "font_license_compliance",
  "backend_route_audit",
  "backend_comment_quality",
];

const FIXABILITY_LABELS: Record<string, string> = {
  auto_fix: "可自动修复",
  diff_only: "仅生成差异建议",
  report_only: "仅报告",
};

const SEVERITY_CLASSES: Record<string, string> = {
  P0: "severity-critical",
  P1: "severity-high",
  P2: "severity-medium",
  P3: "severity-low",
};

interface QualityReportProps {
  report: QualityReportData;
}

export function QualityReport({ report }: QualityReportProps) {
  const blocks = BLOCK_ORDER.map((key) => report.blocks[key]).filter(
    (block): block is QualityBlock => Boolean(block),
  );

  return (
    <div>
      <div className="dimension-summary" aria-label="质量检查摘要">
        <div className="dimension-card">
          <span>条目</span>
          <strong>{report.summary.total_items}</strong>
        </div>
        <div className="dimension-card">
          <span>需人工确认</span>
          <strong>{report.summary.manual_decision_items}</strong>
        </div>
        <div className="dimension-card">
          <span>可修复</span>
          <strong>{report.summary.fixable_items}</strong>
        </div>
        <div className="dimension-card">
          <span>未完成维度</span>
          <strong>{report.summary.blocks_not_completed}</strong>
        </div>
      </div>

      <p className="dimension-score-notice">
        质量检查结论仅用于工程改进参考，不参与安全评分与结论判定。
      </p>

      {blocks.map((block) => (
        <QualityBlockCard key={block.dimension} block={block} />
      ))}

      {(report.limitations ?? []).length > 0 && (
        <div className="card">
          <h3>覆盖范围与限制</h3>
          <ul>
            {(report.limitations ?? []).map((line, index) => (
              <li key={index}>{line}</li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}

function QualityBlockCard({ block }: { block: QualityBlock }) {
  const counts = block.conclusion?.counts ?? {};
  // Backend id lists are authoritative: report_only items that belong to
  // neither group must not be presented as fixable.
  const { fixable, manual, other } = splitQualityItems(block);
  const statusMeta = qualityStatusMeta(block.status);
  const { scalars, nested } = formatQualityCounts(counts);
  const needsReason = block.status !== "completed";

  return (
    <div className="card">
      <div
        style={{
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          gap: "12px",
          flexWrap: "wrap",
        }}
      >
        <h3 style={{ margin: 0 }}>{block.label}</h3>
        <span className={`severity-badge ${statusMeta.className}`}>
          {statusMeta.label}
        </span>
      </div>

      {needsReason && (
        <p className="dimension-score-notice">
          {block.reason_code ? `原因代码：${block.reason_code}。` : ""}
          {block.reason_message || "该维度未完成，结果不完整。"}
        </p>
      )}

      {block.truncated && (
        <p className="dimension-score-notice">
          结果已截断：{block.truncation_reason || "超出报告容量上限。"}
        </p>
      )}

      <p>{block.conclusion?.headline || "未生成结论。"}</p>

      {(scalars.length > 0 || nested.length > 0) && (
        <div style={{ color: "var(--text-secondary)", fontSize: "0.9em" }}>
          {scalars.length > 0 && (
            <p style={{ margin: 0 }}>
              {scalars.map(([key, value]) => `${key}: ${value}`).join(" · ")}
            </p>
          )}
          {nested.map(([key, entries]) => (
            <details key={key} style={{ marginTop: "6px" }}>
              <summary style={{ cursor: "pointer" }}>
                {key} 明细（{entries.length}）
              </summary>
              <ul style={{ margin: "6px 0 0 18px" }}>
                {entries.map(([name, value]) => (
                  <li key={name} style={{ overflowWrap: "anywhere" }}>
                    {name}: {value}
                  </li>
                ))}
              </ul>
            </details>
          ))}
        </div>
      )}

      {block.items.length === 0 ? (
        <div className="empty-state">{emptyMessage(block)}</div>
      ) : (
        <>
          {fixable.length > 0 && (
            <QualityItemList title="可修复项" group="fixable" items={fixable} />
          )}
          {manual.length > 0 && (
            <QualityItemList title="需人工确认项" group="manual" items={manual} />
          )}
          {other.length > 0 && (
            <QualityItemList title="其他发现（仅报告）" group="other" items={other} />
          )}
        </>
      )}
    </div>
  );
}

function emptyMessage(block: QualityBlock): string {
  if (block.status === "completed") {
    return "在已覆盖输入范围内未发现问题。";
  }
  if (block.status === "not_applicable") {
    return `该维度不适用：${block.reason_message || "未提供原因。"}`;
  }
  return `该维度未完成/结果不完整：${block.reason_message || "未提供原因。"}`;
}

function QualityItemList({
  title,
  items,
  group,
}: {
  title: string;
  items: QualityItem[];
  group: "fixable" | "manual" | "other";
}) {
  return (
    <div style={{ marginTop: "12px" }} data-quality-group={group}>
      <h4 style={{ marginBottom: "8px" }}>
        {title}（{items.length}）
      </h4>
      <ul style={{ listStyle: "none", padding: 0, margin: 0 }}>
        {items.map((item) => (
          <li
            key={item.item_id}
            style={{
              borderTop: "1px solid rgba(127, 127, 127, 0.2)",
              padding: "10px 0",
            }}
          >
            <div
              style={{
                display: "flex",
                alignItems: "center",
                gap: "8px",
                flexWrap: "wrap",
              }}
            >
              <span
                className={`severity-badge ${
                  SEVERITY_CLASSES[item.severity] ?? "severity-low"
                }`}
              >
                {item.severity}
              </span>
              <strong>{item.title}</strong>
              <span style={{ opacity: 0.7, fontSize: "0.85em" }}>
                {FIXABILITY_LABELS[item.fixability] ?? item.fixability}
              </span>
            </div>

            {item.impact && (
              <p style={{ margin: "6px 0 0" }}>影响：{item.impact}</p>
            )}
            {item.suggestion && (
              <p style={{ margin: "6px 0 0" }}>建议：{item.suggestion}</p>
            )}
            {item.limitation && (
              <p style={{ margin: "6px 0 0", opacity: 0.75 }}>
                限制：{item.limitation}
              </p>
            )}

            {(item.evidence ?? []).length > 0 && (
              <details style={{ marginTop: "8px" }}>
                <summary style={{ cursor: "pointer" }}>证据</summary>
                <ul style={{ marginTop: "6px" }}>
                  {(item.evidence ?? []).map((evidence, index) => (
                    <li
                      key={`${item.item_id}-${index}`}
                      style={{ overflowWrap: "anywhere" }}
                    >
                      {evidence.file_path
                        ? `${evidence.file_path}${evidence.line_start ? `:${evidence.line_start}` : ""}`
                        : evidence.detail}
                      {evidence.snippet ? ` — ${evidence.snippet}` : ""}
                    </li>
                  ))}
                </ul>
              </details>
            )}
          </li>
        ))}
      </ul>
    </div>
  );
}
