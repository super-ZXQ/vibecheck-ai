"use client";

import type {
  QualityBlock,
  QualityBlockStatus,
  QualityItem,
  QualityReport as QualityReportData,
} from "@/lib/types";

const BLOCK_ORDER = [
  "frontend_dead_code",
  "font_license_compliance",
  "backend_route_audit",
  "backend_comment_quality",
];

const STATUS_LABELS: Record<QualityBlockStatus, string> = {
  completed: "已完成",
  partial: "部分完成",
  not_completed: "未完成",
  not_applicable: "不适用",
};

const STATUS_CLASSES: Record<QualityBlockStatus, string> = {
  completed: "severity-info",
  partial: "severity-medium",
  not_completed: "severity-high",
  not_applicable: "severity-low",
};

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

      {report.limitations.length > 0 && (
        <div className="card">
          <h3>覆盖范围与限制</h3>
          <ul>
            {report.limitations.map((line) => (
              <li key={line}>{line}</li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}

function QualityBlockCard({ block }: { block: QualityBlock }) {
  const counts = block.conclusion?.counts ?? {};
  const fixable = block.items.filter((item) => !item.manual_decision_required);
  const manual = block.items.filter((item) => item.manual_decision_required);
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
        <span className={`severity-badge ${STATUS_CLASSES[block.status]}`}>
          {STATUS_LABELS[block.status]}
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

      {Object.keys(counts).length > 0 && (
        <p style={{ opacity: 0.75, fontSize: "0.9em" }}>
          {Object.entries(counts)
            .map(([key, value]) => `${key}: ${value}`)
            .join(" · ")}
        </p>
      )}

      {block.items.length === 0 ? (
        <div className="empty-state">{emptyMessage(block)}</div>
      ) : (
        <>
          {fixable.length > 0 && (
            <QualityItemList title="可修复项" items={fixable} />
          )}
          {manual.length > 0 && (
            <QualityItemList title="需人工确认项" items={manual} />
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

function QualityItemList({ title, items }: { title: string; items: QualityItem[] }) {
  return (
    <div style={{ marginTop: "12px" }}>
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

            {item.evidence.length > 0 && (
              <details style={{ marginTop: "8px" }}>
                <summary style={{ cursor: "pointer" }}>证据</summary>
                <ul style={{ marginTop: "6px" }}>
                  {item.evidence.map((evidence, index) => (
                    <li key={`${item.item_id}-${index}`}>
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
