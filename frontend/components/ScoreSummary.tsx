/**
 * ScoreSummary — displays the overall security score as an SVG ring
 * plus the verdict badge.
 *
 * Score color thresholds mirror the backend verdict policy:
 *   >= 75 pass (green) / 50-74 warning (amber) / < 50 blocked (red).
 * Data comes from TaskStatusResponse (already desensitized).
 */

"use client";

import { useCountUp } from "@/hooks/use-count-up";
import { lookup } from "@/lib/lookup";
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

const RING_COLORS: Record<string, string> = {
  pass: "#10b981",
  warning: "#f59e0b",
  blocked: "#ef4444",
};

const RING_LIGHT_COLORS: Record<string, string> = {
  pass: "#34d399",
  warning: "#fbbf24",
  blocked: "#f87171",
};

const RING_RADIUS = 48;
const RING_CIRCUMFERENCE = 2 * Math.PI * RING_RADIUS;

export function ScoreSummary({ taskStatus }: ScoreSummaryProps) {
  const score = taskStatus.security_score;
  const verdict = taskStatus.security_verdict;

  // Hooks must run unconditionally, before any early return.
  const clamped = score === null ? 0 : Math.max(0, Math.min(100, score));
  const displayedScore = useCountUp(clamped, 900);

  // If no score/verdict, don't render
  if (score === null || verdict === null) {
    return null;
  }

  const verdictLabel = lookup(VERDICT_LABELS, verdict, verdict);
  const verdictClass = lookup(VERDICT_CLASSES, verdict, "verdict-warning");
  const ringColor = lookup(RING_COLORS, verdict, RING_COLORS.warning);
  const ringLight = lookup(RING_LIGHT_COLORS, verdict, RING_LIGHT_COLORS.warning);
  const dashOffset = RING_CIRCUMFERENCE * (1 - clamped / 100);
  const gradientId = `ring-grad-${verdict}`;

  return (
    <div className="card">
      <div className="score-display">
        <div className="score-ring-wrap">
          <svg
            className="score-ring-svg"
            width="122"
            height="122"
            viewBox="0 0 122 122"
            role="img"
            aria-label={`安全评分 ${clamped} 分`}
          >
            <defs>
              <linearGradient id={gradientId} x1="0" y1="0" x2="1" y2="1">
                <stop offset="0%" stopColor={ringColor} />
                <stop offset="100%" stopColor={ringLight} />
              </linearGradient>
            </defs>
            <circle
              className="score-ring-track"
              cx="61"
              cy="61"
              r={RING_RADIUS}
              strokeWidth="10"
            />
            <circle
              className="score-ring-value"
              cx="61"
              cy="61"
              r={RING_RADIUS}
              strokeWidth="10"
              stroke={`url(#${gradientId})`}
              strokeDasharray={RING_CIRCUMFERENCE}
              strokeDashoffset={dashOffset}
            />
          </svg>
          <div className="score-ring-text">
            <span className="score-number" style={{ color: ringColor }}>
              {displayedScore}
            </span>
          </div>
        </div>
        <div>
          <div className="stage-label">安全评分</div>
          <div>
            <span className={`score-verdict ${verdictClass}`}>
              {verdictLabel}
            </span>
            {score < 50 && (
              <span className="score-blocked-tag">不推荐上线</span>
            )}
          </div>
          {taskStatus.scan_summary && (
            <div className="score-meta">
              发现问题: {taskStatus.scan_summary.total_findings} 项（阻断:{" "}
              {taskStatus.scan_summary.blocking_findings} 项）
              {taskStatus.scan_summary.findings_truncated && "（结果已截断）"}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
