/**
 * CheckProgress — displays task progress during polling.
 *
 * Shows a step indicator (download → extract → scan → assess → repair →
 * analyze), a gradient progress bar, and file/size info when available.
 * All data comes from the backend TaskStatusResponse which is already
 * desensitized.
 */

"use client";

import { useCountUp } from "@/hooks/use-count-up";
import { lookup } from "@/lib/lookup";
import type { TaskStatusResponse } from "@/lib/types";

interface CheckProgressProps {
  taskStatus: TaskStatusResponse;
}

// Human-readable stage labels
const STAGE_LABELS: Record<string, string> = {
  queued: "排队中",
  downloading: "下载仓库",
  extracting: "解压文件",
  scanning: "扫描敏感信息",
  assessing: "安全评估",
  repairing: "生成修复计划",
  finished: "完成",
};

// Ordered pipeline steps shown in the step indicator.
const PIPELINE_STEPS: { key: string; label: string }[] = [
  { key: "downloading", label: "下载" },
  { key: "extracting", label: "解压" },
  { key: "scanning", label: "扫描" },
  { key: "assessing", label: "评估" },
  { key: "repairing", label: "修复" },
  { key: "finished", label: "分析" },
];

function stageIndex(stage: string): number {
  if (stage === "queued") return 0;
  const idx = PIPELINE_STEPS.findIndex((s) => s.key === stage);
  return idx === -1 ? 0 : idx;
}

export function CheckProgress({ taskStatus }: CheckProgressProps) {
  const stageLabel = lookup(STAGE_LABELS, taskStatus.stage, taskStatus.stage);
  const progress = Math.max(0, Math.min(100, taskStatus.progress));
  const currentIdx = stageIndex(taskStatus.stage);
  const displayProgress = useCountUp(progress);

  return (
    <div className="card">
      <ol className="steps">
        {PIPELINE_STEPS.map((step, idx) => {
          const stateClass =
            idx < currentIdx || taskStatus.stage === "finished"
              ? "step-done"
              : idx === currentIdx
                ? "step-current"
                : "";
          return (
            <li key={step.key} className={`step ${stateClass}`}>
              <span className="step-icon">
                {idx < currentIdx || taskStatus.stage === "finished"
                  ? "✓"
                  : idx + 1}
              </span>
              <span className="step-label">{step.label}</span>
            </li>
          );
        })}
      </ol>

      <div className="stage-label">当前阶段</div>
      <div className="progress-stage-name">{stageLabel}</div>

      <div className="progress-bar-container">
        <div
          className="progress-bar-fill"
          style={{ width: `${progress}%` }}
        />
      </div>

      <div className="progress-meta">{displayProgress}%</div>

      {taskStatus.file_count !== null && (
        <div className="progress-meta">文件数量: {taskStatus.file_count}</div>
      )}

      {taskStatus.total_size !== null && (
        <div className="progress-meta">
          总大小: {formatSize(taskStatus.total_size)}
        </div>
      )}
    </div>
  );
}

function formatSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}
