/**
 * Export the full check report as a JSON file download.
 *
 * Runs entirely client-side; no data leaves the browser.
 */

import type {
  AssessmentResult,
  LLMAnalysisResult,
  RepairPlan,
  ScanResult,
} from "./types";

export function exportReport(
  taskId: string,
  scanResult: ScanResult | null,
  assessment: AssessmentResult | null,
  repairPlan: RepairPlan | null,
  llmAnalysis: LLMAnalysisResult | null,
): void {
  const report = {
    exported_at: new Date().toISOString(),
    task_id: taskId,
    scan_result: scanResult,
    assessment: assessment,
    repair_plan: repairPlan,
    llm_analysis: llmAnalysis,
  };
  const blob = new Blob([JSON.stringify(report, null, 2)], {
    type: "application/json",
  });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `vibecheck-report-${taskId.slice(0, 8)}.json`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}
