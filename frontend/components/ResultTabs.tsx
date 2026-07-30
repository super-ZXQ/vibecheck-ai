/**
 * ResultTabs — tab navigation for scan results, assessment, and repair plan.
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
import { ScanResults } from "@/components/ScanResults";
import type {
  AssessmentResult,
  RepairPlan,
  ScanResult,
} from "@/lib/types";
import type { ResultTabStatus } from "@/hooks/use-check-task";

type TabKey = "scan" | "assessment" | "repair";

interface ResultTabsProps {
  scanResult: ScanResult | null;
  scanResultStatus: ResultTabStatus;
  assessment: AssessmentResult | null;
  assessmentStatus: ResultTabStatus;
  repairPlan: RepairPlan | null;
  repairPlanStatus: ResultTabStatus;
  /** Optional render override for the repair plan tab (added in Phase 5). */
  renderRepairPlan?: (plan: RepairPlan) => React.ReactNode;
}

const TAB_LABELS: Record<TabKey, string> = {
  scan: "扫描结果",
  assessment: "安全评估",
  repair: "修复计划",
};

export function ResultTabs({
  scanResult,
  scanResultStatus,
  assessment,
  assessmentStatus,
  repairPlan,
  repairPlanStatus,
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
            {TAB_LABELS[key]}
            {getStatusBadge(key)}
          </button>
        ))}
      </div>

      {/* Tab content */}
      <div>
        {activeTab === "scan" && (
          <TabContent
            status={scanResultStatus}
            data={scanResult}
            renderContent={(data) => <ScanResults scanResult={data} />}
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
            renderContent={
              renderRepairPlan
                ? (data) => renderRepairPlan(data)
                : (data) => <RepairPlanPlaceholder plan={data} />
            }
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
          : repairPlanStatus;
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

// ---------------------------------------------------------------------------
// Repair plan placeholder (replaced by RepairPlan component in Phase 5)
// ---------------------------------------------------------------------------

function RepairPlanPlaceholder({ plan }: { plan: RepairPlan }) {
  return (
    <div className="card">
      <p style={{ fontWeight: 600, marginBottom: "0.5rem" }}>
        修复计划已加载
      </p>
      <p style={{ fontSize: "0.85rem", color: "#64748b" }}>
        计划状态: {plan.plan_status === "complete" ? "完整" : "部分"}
      </p>
      <p style={{ fontSize: "0.85rem", color: "#64748b" }}>
        修复组数量: {plan.summary.total_repair_groups}
        （阻断: {plan.summary.blocking_repair_groups}）
      </p>
    </div>
  );
}
