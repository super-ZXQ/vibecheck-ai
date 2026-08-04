/**
 * ResultTabs — tab navigation for scan results, assessment, repair plan,
 * and LLM analysis.
 *
 * Each tab independently tracks its status:
 * - available → show content component
 * - unavailable → show "legacy/unavailable" message (e.g., 409)
 * - error → show safe error message
 *
 * A single tab's error does NOT crash the entire results page.
 */

"use client";

import { useState } from "react";

import { AssessmentDetails } from "@/components/AssessmentDetails";
import LLMAnalysis from "@/components/LLMAnalysis";
import { RepairPlan as RepairPlanView } from "@/components/RepairPlan";
import { ScanResults } from "@/components/ScanResults";
import type {
  AssessmentResult,
  LLMAnalysisResult,
  RepairPlan,
  ScanResult,
} from "@/lib/types";
import type { ResultTabStatus } from "@/hooks/use-check-task";

type TabKey = "scan" | "assessment" | "repair" | "llm";

interface ResultTabsProps {
  scanResult: ScanResult | null;
  scanResultStatus: ResultTabStatus;
  assessment: AssessmentResult | null;
  assessmentStatus: ResultTabStatus;
  repairPlan: RepairPlan | null;
  repairPlanStatus: ResultTabStatus;
  llmAnalysis: LLMAnalysisResult | null;
  llmAnalysisStatus: ResultTabStatus;
  /** Optional render override for the repair plan tab. */
  renderRepairPlan?: (plan: RepairPlan) => React.ReactNode;
}

const TAB_LABELS: Record<TabKey, string> = {
  scan: "扫描结果",
  assessment: "安全评估",
  repair: "修复计划",
  llm: "AI 分析",
};

const TAB_ICONS: Record<TabKey, React.ReactNode> = {
  scan: (
    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" aria-hidden="true">
      <circle cx="11" cy="11" r="7" stroke="currentColor" strokeWidth="2" />
      <path
        d="M20 20l-3.5-3.5M11 8v3l2 1.5"
        stroke="currentColor"
        strokeWidth="2"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  ),
  assessment: (
    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" aria-hidden="true">
      <path
        d="M12 3l7 4v5c0 4.5-3 8.5-7 9.5-4-1-7-5-7-9.5V7l7-4z"
        stroke="currentColor"
        strokeWidth="2"
        strokeLinejoin="round"
      />
      <path
        d="M9.2 12.4l2 2 3.6-3.8"
        stroke="currentColor"
        strokeWidth="2"
        strokeLinecap="round"
        strokeLinejoin="round"
        fill="none"
      />
    </svg>
  ),
  repair: (
    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" aria-hidden="true">
      <path
        d="M14.7 6.3a4 4 0 00-5.4 5.4L4 17v3h3l5.3-5.3a4 4 0 005.4-5.4l-3 3-2-2 3-3z"
        stroke="currentColor"
        strokeWidth="2"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  ),
  llm: (
    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" aria-hidden="true">
      <path
        d="M12 3l1.9 4.7L18.5 9l-4.6 1.3L12 15l-1.9-4.7L5.5 9l4.6-1.3L12 3z"
        stroke="currentColor"
        strokeWidth="1.8"
        strokeLinejoin="round"
      />
      <path
        d="M18.5 14l.8 2 2 .8-2 .8-.8 2-.8-2-2-.8 2-.8.8-2z"
        stroke="currentColor"
        strokeWidth="1.8"
        strokeLinejoin="round"
      />
      <path
        d="M5.5 14l.7 1.8 1.8.7-1.8.7L5.5 19l-.7-1.8-1.8-.7 1.8-.7.7-1.8z"
        stroke="currentColor"
        strokeWidth="1.8"
        strokeLinejoin="round"
      />
    </svg>
  ),
};

export function ResultTabs({
  scanResult,
  scanResultStatus,
  assessment,
  assessmentStatus,
  repairPlan,
  repairPlanStatus,
  llmAnalysis,
  llmAnalysisStatus,
  renderRepairPlan,
}: ResultTabsProps) {
  const [activeTab, setActiveTab] = useState<TabKey>("scan");

  return (
    <div>
      {/* Tab bar */}
      <div className="tabs">
        {(Object.keys(TAB_LABELS) as TabKey[]).map((key) => (
          <button
            key={key}
            className={`tab ${activeTab === key ? "tab-active" : ""}`}
            onClick={() => setActiveTab(key)}
          >
            <span className="tab-icon">{TAB_ICONS[key]}</span>
            {TAB_LABELS[key]}
            {getStatusBadge(key)}
          </button>
        ))}
      </div>

      {/* Tab content */}
      <div className="tab-content" key={activeTab}>
        {activeTab === "scan" && (
          <TabContent
            status={scanResultStatus}
            data={scanResult}
            renderContent={(data) => (
              <ScanResults scanResult={data} llmAnalysis={llmAnalysis} />
            )}
          />
        )}

        {activeTab === "assessment" && (
          <TabContent
            status={assessmentStatus}
            data={assessment}
            renderContent={(data) => <AssessmentDetails assessment={data} />}
          />
        )}

        {activeTab === "repair" && (
          <TabContent
            status={repairPlanStatus}
            data={repairPlan}
            renderContent={(data) =>
              renderRepairPlan ? renderRepairPlan(data) : <RepairPlanView plan={data} />
            }
          />
        )}

        {activeTab === "llm" && (
          <TabContent
            status={llmAnalysisStatus}
            data={llmAnalysis}
            renderContent={(data) => (
              <LLMAnalysis
                result={data}
                totalFindings={scanResult?.summary.total_findings}
              />
            )}
          />
        )}
      </div>
    </div>
  );

  function getStatusBadge(key: TabKey): string {
    const status =
      key === "scan"
        ? scanResultStatus
        : key === "assessment"
          ? assessmentStatus
          : key === "repair"
            ? repairPlanStatus
            : llmAnalysisStatus;
    if (status === "available") return " ✓";
    if (status === "unavailable") return " −";
    return " !";
  }
}

// ---------------------------------------------------------------------------
// Tab content wrapper — handles status-based rendering
// ---------------------------------------------------------------------------

interface TabContentProps<T> {
  status: ResultTabStatus;
  data: T | null;
  renderContent: (data: T) => React.ReactNode;
}

function TabContent<T>({ status, data, renderContent }: TabContentProps<T>) {
  if (status === "error") {
    return (
      <div className="error-box">
        该结果加载失败，请刷新页面重试。
      </div>
    );
  }

  if (status === "unavailable") {
    return (
      <div className="empty-state">
        该结果不可用（可能是旧版任务未生成此结果）。
      </div>
    );
  }

  // status === "available"
  if (data === null) {
    return (
      <div className="error-box">
        该结果加载失败，请刷新页面重试。
      </div>
    );
  }

  return <>{renderContent(data)}</>;
}
