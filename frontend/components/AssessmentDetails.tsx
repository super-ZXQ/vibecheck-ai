/**
 * AssessmentDetails — security assessment breakdown.
 *
 * Displays:
 * - Score breakdown table (per-rule deductions)
 * - Score caps (blocking reasons that cap the score)
 * - Blocking reasons list
 * - Coverage info
 *
 * All data is already desensitized by the backend.
 */

import type { AssessmentResult } from "@/lib/types";

interface AssessmentDetailsProps {
  assessment: AssessmentResult;
}

const SEVERITY_CLASSES: Record<string, string> = {
  critical: "severity-critical",
  high: "severity-high",
  medium: "severity-medium",
  low: "severity-low",
  info: "severity-info",
};

const SEVERITY_LABELS: Record<string, string> = {
  critical: "严重",
  high: "高",
  medium: "中",
  low: "低",
  info: "信息",
};

export function AssessmentDetails({ assessment }: AssessmentDetailsProps) {
  return (
    <div>
      {/* --- Score overview --- */}
      <div className="card">
        <div className="score-display">
          <div>
            <div className="stage-label">最终评分</div>
            <div className="score-number">{assessment.score}</div>
          </div>
          <div>
            <div className="stage-label">扣分前评分</div>
            <div style={{ fontSize: "1.5rem", fontWeight: 600 }}>
              {assessment.score_before_caps}
            </div>
          </div>
        </div>
        <div style={{ marginTop: "0.5rem", fontSize: "0.85rem", color: "#64748b" }}>
          策略版本: {assessment.policy_version}
        </div>
      </div>

      {/* --- Blocking reasons --- */}
      {assessment.blocking_reasons.length > 0 && (
        <div style={{ marginTop: "1rem" }}>
          <h3 style={{ fontSize: "1.1rem", marginBottom: "0.75rem", color: "#991b1b" }}>
            阻断原因 ({assessment.blocking_reasons.length})
          </h3>
          <div className="card">
            {assessment.blocking_reasons.map((r, i) => (
              <div
                key={i}
                style={{
                  marginBottom: "0.75rem",
                  paddingBottom: "0.75rem",
                  borderBottom:
                    i < assessment.blocking_reasons.length - 1
                      ? "1px solid #f1f5f9"
                      : "none",
                }}
              >
                <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                  <span
                    className={`severity-badge ${
                      SEVERITY_CLASSES[r.severity] ?? "severity-info"
                    }`}
                  >
                    {SEVERITY_LABELS[r.severity] ?? r.severity}
                  </span>
                  <strong>{r.rule_name}</strong>
                </div>
                <div style={{ fontSize: "0.85rem", color: "#64748b", marginTop: "0.25rem" }}>
                  {r.file_path}:{r.line_start} — {r.description}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* --- Score breakdown (collapsible) --- */}
      {assessment.score_breakdown.length > 0 && (
        <details className="collapsible-details">
          <summary>
            <span className="chevron" aria-hidden="true">▶</span>
            评分明细
            <span className="filter-count">（{assessment.score_breakdown.length} 项）</span>
          </summary>
          <div className="details-body">
            <table className="findings-table">
              <thead>
                <tr>
                  <th>规则</th>
                  <th>严重程度</th>
                  <th>发现数</th>
                  <th>扣分</th>
                  <th>最大扣分</th>
                </tr>
              </thead>
              <tbody>
                {assessment.score_breakdown.map((e, i) => (
                  <tr key={i}>
                    <td>{e.rule_name}</td>
                    <td>
                      <span
                        className={`severity-badge ${
                          SEVERITY_CLASSES[e.severity] ?? "severity-info"
                        }`}
                      >
                        {SEVERITY_LABELS[e.severity] ?? e.severity}
                      </span>
                    </td>
                    <td>{e.finding_count}</td>
                    <td>{e.deduction}</td>
                    <td>{e.max_deduction}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </details>
      )}

      {/* --- Score caps (collapsible) --- */}
      {assessment.score_caps.length > 0 && (
        <details className="collapsible-details">
          <summary>
            <span className="chevron" aria-hidden="true">▶</span>
            评分上限
            <span className="filter-count">（{assessment.score_caps.length} 项）</span>
          </summary>
          <div className="details-body">
            <table className="findings-table">
              <thead>
                <tr>
                  <th>原因代码</th>
                  <th>上限值</th>
                  <th>说明</th>
                </tr>
              </thead>
              <tbody>
                {assessment.score_caps.map((c, i) => (
                  <tr key={i}>
                    <td><code>{c.reason_code}</code></td>
                    <td>{c.cap_value}</td>
                    <td>{c.description}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </details>
      )}

      {/* --- Coverage --- */}
      <div style={{ marginTop: "1rem" }}>
        <h3 style={{ fontSize: "1.1rem", marginBottom: "0.75rem" }}>
          覆盖率
        </h3>
        <div className="card">
          <div style={{ display: "flex", gap: "24px", flexWrap: "wrap" }}>
            <div>
              <div className="stage-label">状态</div>
              <div style={{ fontWeight: 600 }}>
                {assessment.coverage.status === "complete" ? "完整" : "部分"}
              </div>
            </div>
            <div>
              <div className="stage-label">总发现问题</div>
              <div style={{ fontWeight: 600 }}>{assessment.coverage.total_findings}</div>
            </div>
            <div>
              <div className="stage-label">已评分问题</div>
              <div style={{ fontWeight: 600 }}>{assessment.coverage.scored_findings}</div>
            </div>
            <div>
              <div className="stage-label">扫描文件数</div>
              <div style={{ fontWeight: 600 }}>{assessment.coverage.total_files_scanned}</div>
            </div>
            <div>
              <div className="stage-label">跳过文件数</div>
              <div style={{ fontWeight: 600 }}>{assessment.coverage.total_skipped_files}</div>
            </div>
          </div>

          {assessment.coverage.reasons.length > 0 && (
            <div style={{ marginTop: "0.75rem", fontSize: "0.85rem" }}>
              {assessment.coverage.reasons.map((r, i) => (
                <div key={i} style={{ color: "#854d0e" }}>• {r}</div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
