/**
 * ResultTabs — tab navigation for scan results, assessment, repair plan,
 * LLM analysis, and quality checks.
 *
 * Each tab independently tracks its status:
 * - available → show content component
 * - unavailable → show "legacy/unavailable" message (e.g., 409)
 * - error → show safe error message
 *
 * A single tab's error does NOT crash the entire results page.
 * Panels are mounted lazily and kept mounted once visited, so per-tab
 * state (expanded evidence, filters) survives tab switches.
 */

"use client";

import { useRef, useState } from "react";

import { AssessmentDetails } from "@/components/AssessmentDetails";
import LLMAnalysis from "@/components/LLMAnalysis";
import { QualityReport as QualityReportView } from "@/components/QualityReport";
import { RepairPlan as RepairPlanView } from "@/components/RepairPlan";
import { ScanResults } from "@/components/ScanResults";
import type {
  AssessmentResult,
  LLMAnalysisResult,
  QualityReport,
  RepairPlan,
  ScanResult,
} from "@/lib/types";
import type { ResultTabStatus } from "@/hooks/use-check-task";

const TAB_KEYS = ["scan", "assessment", "repair", "llm", "quality"] as const;

type TabKey = (typeof TAB_KEYS)[number];

interface ResultTabsProps {
  scanResult: ScanResult | null;
  scanResultStatus: ResultTabStatus;
  assessment: AssessmentResult | null;
  assessmentStatus: ResultTabStatus;
  repairPlan: RepairPlan | null;
  repairPlanStatus: ResultTabStatus;
  llmAnalysis: LLMAnalysisResult | null;
  llmAnalysisStatus: ResultTabStatus;
  qualityReport: QualityReport | null;
  qualityReportStatus: ResultTabStatus;
  /** Optional render override for the repair plan tab. */
  renderRepairPlan?: (plan: RepairPlan) => React.ReactNode;
}

const STATUS_ARIA: Record<ResultTabStatus, string> = {
  available: "结果可用",
  unavailable: "结果不可用",
  error: "结果加载失败",
};

const TAB_LABELS: Record<TabKey, string> = {
  scan: "扫描结果",
  assessment: "安全评估",
  repair: "修复计划",
  llm: "AI 分析",
  quality: "质量检查",
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
  quality: (
    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" aria-hidden="true">
      <path
        d="M9 4h6a2 2 0 012 2v13a1 1 0 01-1.5.9L12 18l-3.5 1.9A1 1 0 017 19V6a2 2 0 012-2z"
        stroke="currentColor"
        strokeWidth="2"
        strokeLinejoin="round"
      />
      <path
        d="M9.5 9.5h5M9.5 13h3.5"
        stroke="currentColor"
        strokeWidth="2"
        strokeLinecap="round"
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
  qualityReport,
  qualityReportStatus,
  renderRepairPlan,
}: ResultTabsProps) {
  const [activeTab, setActiveTab] = useState<TabKey>("scan");
  // Lazy keep-alive: render a panel only after its tab is first opened,
  // then leave it mounted while hidden so per-tab state is preserved.
  const [visitedTabs, setVisitedTabs] = useState<ReadonlySet<TabKey>>(
    () => new Set<TabKey>(["scan"]),
  );
  const tabRefs = useRef<Array<HTMLButtonElement | null>>([]);

  return (
    <div>
      {/* Tab bar */}
      <div className="tabs" role="tablist" aria-label="检测结果">
        {TAB_KEYS.map((key, index) => {
          const selected = activeTab === key;
          return (
            <button
              key={key}
              ref={(node) => {
                tabRefs.current[index] = node;
              }}
              type="button"
              role="tab"
              id={tabId(key)}
              aria-selected={selected}
              aria-controls={panelId(key)}
              aria-label={`${TAB_LABELS[key]}，${STATUS_ARIA[statusFor(key)]}`}
              tabIndex={selected ? 0 : -1}
              className={`tab ${selected ? "tab-active" : ""}`}
              onClick={() => selectTab(key)}
              onKeyDown={(event) => handleTabKeyDown(event, index)}
            >
              <span className="tab-icon">{TAB_ICONS[key]}</span>
              {TAB_LABELS[key]}
              <span aria-hidden="true">{getStatusBadge(key)}</span>
            </button>
          );
        })}
      </div>

      {/* Tab content */}
      {TAB_KEYS.map((key) => (
        <div
          key={key}
          className="tab-content"
          role="tabpanel"
          id={panelId(key)}
          aria-labelledby={tabId(key)}
          tabIndex={0}
          hidden={activeTab !== key}
        >
          {visitedTabs.has(key) ? renderTab(key) : null}
        </div>
      ))}
    </div>
  );

  function selectTab(key: TabKey) {
    setActiveTab(key);
    setVisitedTabs((previous) => {
      if (previous.has(key)) return previous;
      const next = new Set(previous);
      next.add(key);
      return next;
    });
  }

  function handleTabKeyDown(
    event: React.KeyboardEvent<HTMLButtonElement>,
    index: number,
  ) {
    let nextIndex: number | null = null;
    if (event.key === "ArrowRight") {
      nextIndex = (index + 1) % TAB_KEYS.length;
    } else if (event.key === "ArrowLeft") {
      nextIndex = (index - 1 + TAB_KEYS.length) % TAB_KEYS.length;
    } else if (event.key === "Home") {
      nextIndex = 0;
    } else if (event.key === "End") {
      nextIndex = TAB_KEYS.length - 1;
    }
    if (nextIndex === null) return;
    event.preventDefault();
    const nextKey = TAB_KEYS[nextIndex];
    selectTab(nextKey);
    tabRefs.current[nextIndex]?.focus();
  }

  function renderTab(key: TabKey): React.ReactNode {
    if (key === "scan") {
      return (
        <TabContent
          status={scanResultStatus}
          data={scanResult}
          renderContent={(data) => (
            <ScanResults scanResult={data} llmAnalysis={llmAnalysis} />
          )}
        />
      );
    }
    if (key === "assessment") {
      return (
        <TabContent
          status={assessmentStatus}
          data={assessment}
          renderContent={(data) => <AssessmentDetails assessment={data} />}
        />
      );
    }
    if (key === "repair") {
      return (
        <TabContent
          status={repairPlanStatus}
          data={repairPlan}
          renderContent={(data) =>
            renderRepairPlan ? renderRepairPlan(data) : <RepairPlanView plan={data} />
          }
        />
      );
    }
    if (key === "llm") {
      return (
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
      );
    }
    return (
      <TabContent
        status={qualityReportStatus}
        data={qualityReport}
        renderContent={(data) => <QualityReportView report={data} />}
      />
    );
  }

  function statusFor(key: TabKey): ResultTabStatus {
    if (key === "scan") return scanResultStatus;
    if (key === "assessment") return assessmentStatus;
    if (key === "repair") return repairPlanStatus;
    if (key === "llm") return llmAnalysisStatus;
    return qualityReportStatus;
  }

  function getStatusBadge(key: TabKey): string {
    const status = statusFor(key);
    if (status === "available") return " ✓";
    if (status === "unavailable") return " −";
    return " !";
  }
}

function tabId(key: TabKey): string {
  return `result-tab-${key}`;
}

function panelId(key: TabKey): string {
  return `result-panel-${key}`;
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
