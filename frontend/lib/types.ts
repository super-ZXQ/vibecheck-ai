/**
 * TypeScript type definitions for all VibeCheck API responses.
 *
 * Every type mirrors the Pydantic model or serialized dict structure
 * returned by the backend. No type is duplicated across files.
 */

// ---------------------------------------------------------------------------
// POST /api/check
// ---------------------------------------------------------------------------

export interface CheckRequest {
  repo_url: string;
}

export interface CheckResponse {
  task_id: string;
  status: string;
  check_url: string;
}

// ---------------------------------------------------------------------------
// GET /api/check/{task_id}
// ---------------------------------------------------------------------------

export interface ScanSummary {
  total_findings: number;
  blocking_findings: number;
  total_notices: number;
  total_skipped_files: number;
  total_scan_errors: number;
  total_files_scanned: number;
  total_lines_scanned: number;
  returned_findings: number;
  findings_truncated: boolean;
  returned_notices: number;
  notices_truncated: boolean;
  returned_skipped_files: number;
  skipped_files_truncated: boolean;
  returned_scan_errors: number;
  scan_errors_truncated: boolean;
  dimension_counts?: {
    sensitive_data_security?: number;
    incomplete_content?: number;
    deployability_production?: number;
    basic_security?: number;
    documentation_consistency?: number;
  };
}

export interface TaskStatusResponse {
  task_id: string;
  status: string; // "pending" | "running" | "completed" | "failed"
  stage: string; // "queued" | "downloading" | "extracting" | "scanning" | "assessing" | "repairing" | "finished"
  progress: number;
  owner: string | null;
  repo_name: string | null;
  error_code: string | null;
  error_message: string | null;
  report_url: string | null;
  file_count: number | null;
  total_size: number | null;
  top_level_dir: string | null;
  scan_summary: ScanSummary | null;
  security_score: number | null;
  security_verdict: string | null;
  assessment_url: string | null;
  repair_plan_available: boolean | null;
  repair_plan_url: string | null;
  llm_analysis_available: boolean | null;
  llm_analysis_url: string | null;
}

// ---------------------------------------------------------------------------
// GET /api/check/{task_id}/result
// ---------------------------------------------------------------------------

export interface Finding {
  rule_id: string;
  rule_name: string;
  severity: string; // "critical" | "high" | "medium" | "low" | "info"
  confidence: string; // "high" | "medium" | "low"
  file_path: string;
  line_start: number | null;
  line_end: number | null;
  column_start: number | null;
  column_end: number | null;
  snippet_masked: string;
  is_blocking: boolean;
  finding_type: string;
  description: string;
  category: string;
  secret_type: string;
  message: string;
  repair_template_key: string;
  dimension?:
    | "sensitive_data_security"
    | "incomplete_content"
    | "deployability_production"
    | "basic_security"
    | "documentation_consistency";
}

export interface ScanNotice {
  rule_id: string;
  message: string;
  file_path: string;
}

export interface SkippedFile {
  file_path: string;
  reason: string;
}

export interface ScanError {
  file_path: string;
  error_type: string;
  error_message: string;
}

export interface ScanResult {
  schema_version: number;
  findings: Finding[];
  notices: ScanNotice[];
  skipped_files: SkippedFile[];
  scan_errors: ScanError[];
  summary: ScanSummary;
}

// ---------------------------------------------------------------------------
// GET /api/check/{task_id}/assessment
// ---------------------------------------------------------------------------

export interface ScoreBreakdownEntry {
  rule_id: string;
  rule_name: string;
  severity: string;
  finding_count: number;
  deduction: number;
  max_deduction: number;
}

export interface ScoreCapEntry {
  reason_code: string;
  cap_value: number;
  description: string;
}

export interface BlockingReason {
  rule_id: string;
  rule_name: string;
  severity: string;
  file_path: string;
  line_start: number;
  description: string;
}

export interface Coverage {
  status: string; // "complete" | "partial"
  reasons: string[];
  total_findings: number;
  scored_findings: number;
  findings_truncated: boolean;
  total_blocking_findings: number;
  returned_blocking_reasons: number;
  blocking_reasons_truncated: boolean;
  total_scan_errors: number;
  total_files_scanned: number;
  total_skipped_files: number;
}

export interface AssessmentResult {
  schema_version: number;
  policy_version: string;
  assessment_scope: string;
  task_id: string;
  score: number;
  score_before_caps: number;
  verdict: string; // "pass" | "warning" | "blocked"
  score_breakdown: ScoreBreakdownEntry[];
  score_caps: ScoreCapEntry[];
  blocking_reasons: BlockingReason[];
  coverage: Coverage;
}

// ---------------------------------------------------------------------------
// GET /api/check/{task_id}/repair-plan
// ---------------------------------------------------------------------------

export interface RepairSummary {
  total_repair_groups: number;
  blocking_repair_groups: number;
  manual_review_required: boolean;
  coverage_warning: boolean;
  groups_truncated: boolean;
}

export interface RepairGroup {
  group_id: string;
  action_code: string;
  priority: number;
  blocking: boolean;
  highest_severity: string;
  highest_confidence: string;
  title: string;
  description: string;
  related_rule_ids: string[];
  related_files: string[];
  total_related_files: number;
  returned_related_files: number;
  related_files_truncated: boolean;
  finding_count: number;
  steps: string[];
  commands: string[];
  safety_notes: string[];
  verification_steps: string[];
}

export interface RepairPlan {
  schema_version: number;
  policy_version: string;
  repair_scope: string;
  task_id: string;
  plan_status: string; // "complete" | "partial"
  summary: RepairSummary;
  repair_groups: RepairGroup[];
  verification_steps: string[];
  agent_prompt: string;
  source_scan_updated_at: string;
  source_assessment_updated_at: string;
  source_assessment_policy_version: string;
  created_at: string;
  updated_at: string;
}

// ---------------------------------------------------------------------------
// GET /api/check/{task_id}/llm-analysis
// ---------------------------------------------------------------------------

export interface LLMAnalysisItem {
  rule_id: string;
  rule_name: string;
  severity: string;
  file_path: string;
  line_start: number | null;
  explanation: string;
  instruction: string;
  source: string; // "llm" | "fallback" | "none"
}

export interface LLMAnalysisResult {
  schema_version: number;
  scope: string;
  total_analyzed: number;
  total_llm: number;
  total_fallback: number;
  source: string;
  items: LLMAnalysisItem[];
}

// ---------------------------------------------------------------------------
// Error response (all error endpoints)
// ---------------------------------------------------------------------------

export interface ApiErrorBody {
  detail: {
    error_code: string;
  };
}
