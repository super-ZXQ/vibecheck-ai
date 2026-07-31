/**
 * ScoreSummary — displays the overall security score and verdict.
 *
 * Data comes from TaskStatusResponse (security_score, security_verdict)
 * which is already desensitized by the backend.
 */

import type { TaskStatusResponse } from "@/lib/types";

interface ScoreSummaryProps {
  taskStatus: TaskStatusResponse;
}

const VERDICT_LABELS: Record<string, string> = {
  pass: "通过",
  warning: "警告",
  blocked: "不推荐上线",
};

const VERDICT_CLASSES: Record<string, string> = {
  pass: "verdict-pass",
  warning: "verdict-warning",
  blocked: "verdict-blocked",
};

export function ScoreSummary({ taskStatus }: ScoreSummaryProps) {
  const score = taskStatus.security_score;
  const verdict = taskStatus.security_verdict;

  // If no score/verdict, don't render
  if (score === null || verdict === null) {
    return null;
  }

  const verdictLabel = VERDICT_LABELS[verdict] ?? verdict;
  const verdictClass = VERDICT_CLASSES[verdict] ?? "verdict-warning";

  return (
    <div className="card">
      <div className="score-display">
        <div>
          <div className="stage-label">安全评分</div>
          <div className="score-number">{score}</div>
        </div>
        <div className={`score-verdict ${verdictClass}`}>
          {verdictLabel}
        </div>
      </div>

      {taskStatus.scan_summary && (
        <div
          style={{
            marginTop: "1rem",
            fontSize: "0.85rem",
            color: "#64748b",
          }}
        >
          <span>
            发现问题: {taskStatus.scan_summary.total_findings} 项
            （阻断: {taskStatus.scan_summary.blocking_findings} 项）
          </span>
          {taskStatus.scan_summary.findings_truncated && (
            <span style={{ marginLeft: "0.5rem", color: "#9a3412" }}>
              （结果已截断）
            </span>
          )}
        </div>
      )}
    </div>
  );
}
