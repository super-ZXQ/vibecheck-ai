/**
 * LLM analysis tab: AI-generated explanations and fix instructions
 * for non-blocking findings. Items may come from the LLM or from
 * local fallback templates (source field).
 */

import { lookup } from "@/lib/lookup";
import type { LLMAnalysisItem, LLMAnalysisResult } from "@/lib/types";

interface LLMAnalysisProps {
  result: LLMAnalysisResult;
  /** Total findings from the scan summary, used to show analysis coverage. */
  totalFindings?: number;
}

const SOURCE_LABELS: Record<string, string> = {
  llm: "LLM 分析",
  fallback: "回退模板",
  none: "未分析",
};

function sourceLabel(source: string): string {
  return lookup(SOURCE_LABELS, source, source);
}

function LLMItemCard({ item }: { item: LLMAnalysisItem }) {
  const location = item.line_start !== null
    ? `${item.file_path}:${item.line_start}`
    : item.file_path;

  return (
    <div className="card llm-item-card">
      <div className="llm-item-header">
        <span className={`severity-badge severity-${item.severity}`}>
          {item.severity}
        </span>
        <span className="llm-item-title">{item.rule_name}</span>
        <span className={`llm-source-badge llm-source-${item.source}`}>
          {sourceLabel(item.source)}
        </span>
      </div>
      <div className="llm-item-location">{location}</div>
      <div className="llm-item-section">
        <div className="llm-item-section-title">AI 解释</div>
        <p className="llm-item-text">{item.explanation}</p>
      </div>
      <div className="llm-item-section">
        <div className="llm-item-section-title">修复指导</div>
        <p className="llm-item-text llm-item-instruction">{item.instruction}</p>
      </div>
    </div>
  );
}

export default function LLMAnalysis({ result, totalFindings }: LLMAnalysisProps) {
  const coverageNote =
    totalFindings !== undefined && totalFindings > result.total_analyzed
      ? `（未覆盖 ${totalFindings - result.total_analyzed} 项：AI 分析仅覆盖扫描发现的高优先级项目）`
      : null;

  return (
    <div>
      <div className="llm-stats">
        <span className="llm-stat">
          已分析 <strong>{result.total_analyzed}</strong>{" "}
          {totalFindings !== undefined
            ? `/ 共 ${totalFindings} 项发现`
            : "项"}
        </span>
        <span className="llm-stat">
          LLM 分析 <strong>{result.total_llm}</strong> 项
        </span>
        <span className="llm-stat">
          回退模板 <strong>{result.total_fallback}</strong> 项
        </span>
        <span className={`llm-source-badge llm-source-${result.source}`}>
          数据来源：{sourceLabel(result.source)}
        </span>
      </div>
      {coverageNote && (
        <div className="llm-coverage-note">{coverageNote}</div>
      )}
      {result.items.length === 0 ? (
        <div className="empty-state">没有需要 AI 分析的非阻断发现</div>
      ) : (
        <div className="llm-item-list">
          {result.items.map((item, index) => (
            <LLMItemCard
              key={`${item.rule_id}-${item.file_path}-${index}`}
              item={item}
            />
          ))}
        </div>
      )}
    </div>
  );
}
