/**
 * CheckProgress — displays task progress during polling.
 *
 * Shows the current stage, a progress bar, and file/size info when available.
 * All data comes from the backend TaskStatusResponse which is already
 * desensitized.
 */

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

export function CheckProgress({ taskStatus }: CheckProgressProps) {
  const stageLabel = STAGE_LABELS[taskStatus.stage] ?? taskStatus.stage;
  const progress = Math.max(0, Math.min(100, taskStatus.progress));

  return (
    <div className="card">
      <div className="stage-label">当前阶段</div>
      <div style={{ fontSize: "1.1rem", fontWeight: 600, marginBottom: "0.5rem" }}>
        {stageLabel}
      </div>

      <div className="progress-bar-container">
        <div
          className="progress-bar-fill"
          style={{ width: `${progress}%` }}
        />
      </div>

      <div style={{ fontSize: "0.85rem", color: "#64748b" }}>
        {progress}%
      </div>

      {taskStatus.file_count !== null && (
        <div style={{ fontSize: "0.85rem", color: "#64748b", marginTop: "0.5rem" }}>
          文件数量: {taskStatus.file_count}
        </div>
      )}

      {taskStatus.total_size !== null && (
        <div style={{ fontSize: "0.85rem", color: "#64748b" }}>
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
