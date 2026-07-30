/**
 * RepairPlan — deterministic repair plan display with agent prompt copy.
 *
 * Security constraints:
 * - Agent prompt is copied ONLY on user click (never auto-copied).
 * - Copy failure shows a fixed message (no internal details).
 * - Agent prompt is never sent to any external service.
 * - No localStorage, sessionStorage, or IndexedDB usage.
 *
 * All data is already desensitized by the backend repair policy.
 */

"use client";

import { useState } from "react";

import type { RepairPlan as RepairPlanType } from "@/lib/types";

interface RepairPlanProps {
  plan: RepairPlanType;
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

export function RepairPlan({ plan }: RepairPlanProps) {
  const { summary, repair_groups, verification_steps, agent_prompt, plan_status } = plan;

  return (
    <div>
      {/* --- Plan summary --- */}
      <div className="card">
        <div style={{ display: "flex", gap: "24px", flexWrap: "wrap" }}>
          <div>
            <div className="stage-label">计划状态</div>
            <div style={{ fontWeight: 600 }}>
              {plan_status === "complete" ? "完整" : "部分"}
            </div>
          </div>
          <div>
            <div className="stage-label">修复组总数</div>
            <div style={{ fontWeight: 600 }}>{summary.total_repair_groups}</div>
          </div>
          <div>
            <div className="stage-label">阻断修复组</div>
            <div style={{ fontWeight: 600, color: summary.blocking_repair_groups > 0 ? "#991b1b" : undefined }}>
              {summary.blocking_repair_groups}
            </div>
          </div>
        </div>

        {summary.coverage_warning && (
          <div className="error-box" style={{ marginTop: "0.75rem" }}>
            覆盖率警告：部分扫描结果不完整，修复计划可能不全面。
          </div>
        )}

        {summary.manual_review_required && (
          <div className="error-box" style={{ marginTop: "0.75rem" }}>
            需要人工审查：部分问题需要手动确认。
          </div>
        )}

        {summary.groups_truncated && (
          <div style={{ marginTop: "0.5rem", fontSize: "0.85rem", color: "#854d0e" }}>
            修复组列表已截断，仅显示部分修复组。
          </div>
        )}
      </div>

      {/* --- Repair groups --- */}
      <div style={{ marginTop: "1rem" }}>
        <h3 style={{ fontSize: "1.1rem", marginBottom: "0.75rem" }}>
          修复组 ({repair_groups.length})
        </h3>

        {repair_groups.length === 0 ? (
          <div className="empty-state">无需修复的问题。</div>
        ) : (
          repair_groups.map((group, i) => (
            <div
              key={group.group_id || i}
              className={`repair-group ${group.blocking ? "repair-group-blocking" : ""}`}
            >
              <div className="repair-group-title">
                {group.blocking && (
                  <span className="severity-badge severity-critical" style={{ marginRight: "8px" }}>
                    阻断
                  </span>
                )}
                <span
                  className={`severity-badge ${
                    SEVERITY_CLASSES[group.highest_severity] ?? "severity-info"
                  }`}
                  style={{ marginRight: "8px" }}
                >
                  {SEVERITY_LABELS[group.highest_severity] ?? group.highest_severity}
                </span>
                {group.title}
              </div>

              <div className="repair-group-description">
                {group.description}
              </div>

              {/* Steps */}
              {group.steps.length > 0 && (
                <div>
                  <div className="stage-label">修复步骤</div>
                  <ol className="repair-steps">
                    {group.steps.map((step, si) => (
                      <li key={si}>{step}</li>
                    ))}
                  </ol>
                </div>
              )}

              {/* Commands */}
              {group.commands.length > 0 && (
                <div style={{ marginTop: "0.5rem" }}>
                  <div className="stage-label">建议命令</div>
                  <div style={{ fontFamily: "monospace", fontSize: "0.85rem", marginTop: "0.25rem" }}>
                    {group.commands.map((cmd, ci) => (
                      <div key={ci} style={{ padding: "2px 0" }}>
                        <code>{cmd}</code>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Safety notes */}
              {group.safety_notes.length > 0 && (
                <div style={{ marginTop: "0.5rem" }}>
                  <div className="stage-label">安全提示</div>
                  <ul className="repair-steps">
                    {group.safety_notes.map((note, ni) => (
                      <li key={ni} style={{ color: "#854d0e" }}>{note}</li>
                    ))}
                  </ul>
                </div>
              )}

              {/* Related files */}
              {group.related_files.length > 0 && (
                <div style={{ marginTop: "0.5rem" }}>
                  <div className="stage-label">
                    相关文件 ({group.returned_related_files}
                    {group.total_related_files > group.returned_related_files
                      ? ` / ${group.total_related_files}`
                      : ""})
                  </div>
                  <div style={{ fontSize: "0.8rem", marginTop: "0.25rem" }}>
                    {group.related_files.map((f, fi) => (
                      <div key={fi}>
                        <code>{f}</code>
                      </div>
                    ))}
                    {group.related_files_truncated && (
                      <div style={{ color: "#854d0e", marginTop: "0.25rem" }}>
                        （文件列表已截断）
                      </div>
                    )}
                  </div>
                </div>
              )}
            </div>
          ))
        )}
      </div>

      {/* --- Verification steps --- */}
      {verification_steps.length > 0 && (
        <div style={{ marginTop: "1rem" }}>
          <h3 style={{ fontSize: "1.1rem", marginBottom: "0.75rem" }}>
            验证步骤
          </h3>
          <ol className="repair-steps">
            {verification_steps.map((step, i) => (
              <li key={i}>{step}</li>
            ))}
          </ol>
        </div>
      )}

      {/* --- Agent prompt --- */}
      {agent_prompt && (
        <AgentPromptSection prompt={agent_prompt} />
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Agent prompt section with copy button
// ---------------------------------------------------------------------------

function AgentPromptSection({ prompt }: { prompt: string }) {
  const [copyState, setCopyState] = useState<"idle" | "success" | "error">("idle");

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(prompt);
      setCopyState("success");
    } catch {
      setCopyState("error");
    }

    // Reset after 3 seconds
    setTimeout(() => {
      setCopyState("idle");
    }, 3000);
  };

  return (
    <div style={{ marginTop: "1rem" }}>
      <h3 style={{ fontSize: "1.1rem", marginBottom: "0.75rem" }}>
        Agent 指令
      </h3>
      <div className="agent-prompt-container">
        <div style={{ marginBottom: "0.5rem" }}>
          <button
            className="btn btn-secondary"
            style={{ padding: "6px 16px", fontSize: "0.85rem" }}
            onClick={handleCopy}
          >
            复制指令
          </button>
          {copyState === "success" && (
            <span className="copy-feedback copy-success">已复制到剪贴板</span>
          )}
          {copyState === "error" && (
            <span className="copy-feedback copy-error">
              复制失败，请手动选择文本复制
            </span>
          )}
        </div>
        <pre className="agent-prompt-text">{prompt}</pre>
      </div>
      <div style={{ fontSize: "0.8rem", color: "#94a3b8", marginTop: "0.5rem" }}>
        指令仅复制到剪贴板，不会自动执行或发送到任何外部服务。
      </div>
    </div>
  );
}
