/**
 * Shared severity badge styling/labels. Single source of truth so
 * ScanResults / AssessmentDetails / RepairPlan do not duplicate maps.
 */

export const SEVERITY_CLASSES: Record<string, string> = {
  critical: "severity-critical",
  high: "severity-high",
  medium: "severity-medium",
  low: "severity-low",
  info: "severity-info",
};

export const SEVERITY_LABELS: Record<string, string> = {
  critical: "严重",
  high: "高",
  medium: "中",
  low: "低",
  info: "信息",
};
