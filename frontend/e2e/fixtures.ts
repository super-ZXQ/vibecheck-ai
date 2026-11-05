/**
 * Mock data and helpers for E2E tests.
 *
 * All API calls in tests are mocked via page.route — no real backend
 * or GitHub network is required.
 */

import type { Page, Route } from "@playwright/test";

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

export const TEST_TASK_ID = "550e8400-e29b-41d4-a716-446655440000";
export const API_BASE = "http://localhost:8000";

// ---------------------------------------------------------------------------
// Mock task status responses
// ---------------------------------------------------------------------------

export const mockPendingStatus = {
  task_id: TEST_TASK_ID,
  status: "pending",
  stage: "queued",
  progress: 0,
  error_code: null,
  error_message: null,
  report_url: null,
  file_count: null,
  total_size: null,
  top_level_dir: null,
  scan_summary: null,
  security_score: null,
  security_verdict: null,
  assessment_url: null,
  repair_plan_available: null,
  repair_plan_url: null,
};

export const mockRunningStatus = {
  ...mockPendingStatus,
  status: "running",
  stage: "scanning",
  progress: 50,
};

export const mockCompletedStatus = {
  ...mockPendingStatus,
  status: "completed",
  stage: "finished",
  progress: 100,
  scan_summary: {
    total_findings: 2,
    blocking_findings: 1,
    total_notices: 1,
    total_skipped_files: 1,
    total_scan_errors: 0,
    total_files_scanned: 10,
    total_lines_scanned: 500,
    returned_findings: 2,
    findings_truncated: false,
    returned_notices: 1,
    notices_truncated: false,
    returned_skipped_files: 1,
    skipped_files_truncated: false,
    returned_scan_errors: 0,
    scan_errors_truncated: false,
  },
  security_score: 45,
  security_verdict: "blocked",
  assessment_url: `/api/check/${TEST_TASK_ID}/assessment`,
  repair_plan_available: true,
  repair_plan_url: `/api/check/${TEST_TASK_ID}/repair-plan`,
};

export const mockFailedStatus = {
  ...mockPendingStatus,
  status: "failed",
  stage: "scanning",
  progress: 50,
  error_code: "REPOSITORY_NOT_FOUND",
  error_message: "仓库不存在或无法访问，请确认地址正确。",
};

// ---------------------------------------------------------------------------
// Mock scan result
// ---------------------------------------------------------------------------

function makeFindings(count: number) {
  return Array.from({ length: count }, (_, i) => ({
    rule_id: `R00${i % 7 + 1}`,
    rule_name: `Test Rule ${i + 1}`,
    severity: i % 4 === 0 ? "critical" : i % 4 === 1 ? "high" : i % 4 === 2 ? "medium" : "low",
    confidence: "high",
    file_path: `src/file_${i}.py`,
    line_start: i * 10 + 1,
    line_end: i * 10 + 1,
    column_start: 1,
    column_end: 20,
    snippet_masked: "password = ***",
    is_blocking: i % 5 === 0,
    finding_type: "secret",
    description: "Hardcoded password detected",
    category: "password",
    secret_type: "password",
    message: "Potential hardcoded password",
    repair_template_key: "REPLACE_WITH_ENV_VAR",
    dimension: "sensitive_data_security" as const,
  }));
}

export const mockScanResult = {
  schema_version: 2,
  findings: makeFindings(30),
  notices: [
    { rule_id: "R008", message: "Env file detected", file_path: ".env.example" },
  ],
  skipped_files: [
    { file_path: "node_modules/react/index.js", reason: "Ignored directory" },
  ],
  scan_errors: [],
  summary: {
    total_findings: 30,
    blocking_findings: 6,
    total_notices: 1,
    total_skipped_files: 1,
    total_scan_errors: 0,
    total_files_scanned: 10,
    total_lines_scanned: 500,
    returned_findings: 30,
    findings_truncated: false,
    returned_notices: 1,
    notices_truncated: false,
    returned_skipped_files: 1,
    skipped_files_truncated: false,
    returned_scan_errors: 0,
    scan_errors_truncated: false,
    dimension_counts: {
      sensitive_data_security: 30,
      incomplete_content: 0,
      deployability_production: 0,
      basic_security: 0,
      documentation_consistency: 0,
    },
  },
};

export const mockMultidimensionalScanResult = {
  ...mockScanResult,
  findings: [
    ...mockScanResult.findings.slice(0, 26),
    ...Array.from({ length: 6 }, (_, i) => ({
      ...mockScanResult.findings[i],
      rule_id: `I00${i % 5 + 1}_INCOMPLETE`,
      rule_name: `Incomplete Rule ${i + 1}`,
      file_path: `src/incomplete_${i}.ts`,
      is_blocking: false,
      dimension: "incomplete_content" as const,
      description: "An unfinished construct remains in production source code.",
      message: "Complete the implementation before shipping.",
    })),
  ],
  summary: {
    ...mockScanResult.summary,
    total_findings: 32,
    blocking_findings: 6,
    returned_findings: 32,
    dimension_counts: {
      sensitive_data_security: 26,
      incomplete_content: 6,
      deployability_production: 0,
      basic_security: 0,
      documentation_consistency: 0,
    },
  },
};

export const mockThreeDimensionalScanResult = {
  ...mockMultidimensionalScanResult,
  findings: [
    ...mockMultidimensionalScanResult.findings,
    ...Array.from({ length: 27 }, (_, i) => ({
      ...mockScanResult.findings[i],
      rule_id: `D${String(i + 1).padStart(3, "0")}_DEPLOYABILITY`,
      rule_name: `Deployability Rule ${i + 1}`,
      file_path: i === 0 ? "<repository>" : `deploy/config_${i}.txt`,
      is_blocking: false,
      dimension: "deployability_production" as const,
      description: "A production deployment prerequisite is missing.",
      message: "Add the missing production configuration before deployment.",
    })),
  ],
  summary: {
    ...mockMultidimensionalScanResult.summary,
    total_findings: 59,
    returned_findings: 59,
    dimension_counts: {
      sensitive_data_security: 26,
      incomplete_content: 6,
      deployability_production: 27,
      basic_security: 0,
      documentation_consistency: 0,
    },
  },
};

export const mockFourDimensionalScanResult = {
  ...mockThreeDimensionalScanResult,
  findings: [
    ...mockThreeDimensionalScanResult.findings,
    ...Array.from({ length: 27 }, (_, i) => ({
      ...mockScanResult.findings[i],
      rule_id: `B${String(i % 5 + 1).padStart(3, "0")}_BASIC_SECURITY`,
      rule_name: `Basic Security Rule ${i + 1}`,
      file_path: i === 0 ? "<repository>" : `src/security_${i}.ts`,
      is_blocking: false,
      dimension: "basic_security" as const,
      description: "A high-confidence basic security weakness was detected.",
      message: "Apply the fixed security recommendation before deployment.",
    })),
  ],
  summary: {
    ...mockThreeDimensionalScanResult.summary,
    total_findings: 86,
    returned_findings: 86,
    dimension_counts: {
      sensitive_data_security: 26,
      incomplete_content: 6,
      deployability_production: 27,
      basic_security: 27,
      documentation_consistency: 0,
    },
  },
};

export const mockFiveDimensionalScanResult = {
  ...mockFourDimensionalScanResult,
  findings: [
    ...mockFourDimensionalScanResult.findings,
    ...Array.from({ length: 27 }, (_, i) => ({
      ...mockScanResult.findings[i],
      rule_id: `C${String(i % 4 + 1).padStart(3, "0")}_DOCUMENTATION`,
      rule_name: `Documentation Rule ${i + 1}`,
      file_path: i === 0 ? "<repository>" : "README.md",
      line_start: i === 0 ? null : i + 10,
      line_end: i === 0 ? null : i + 10,
      is_blocking: false,
      dimension: "documentation_consistency" as const,
      description: "A documented repository fact does not match the project.",
      message: "Update the documentation or restore the referenced project element.",
    })),
  ],
  summary: {
    ...mockFourDimensionalScanResult.summary,
    total_findings: 113,
    returned_findings: 113,
    dimension_counts: {
      sensitive_data_security: 26,
      incomplete_content: 6,
      deployability_production: 27,
      basic_security: 27,
      documentation_consistency: 27,
    },
  },
};

// ---------------------------------------------------------------------------
// Mock assessment
// ---------------------------------------------------------------------------

export const mockAssessment = {
  schema_version: 1,
  policy_version: "p0-6-v1",
  assessment_scope: "sensitive_data_security",
  task_id: TEST_TASK_ID,
  score: 45,
  score_before_caps: 55,
  verdict: "blocked",
  score_breakdown: [
    {
      rule_id: "R001",
      rule_name: "GitHub Token",
      severity: "critical",
      finding_count: 3,
      deduction: 20,
      max_deduction: 30,
    },
  ],
  score_caps: [
    {
      reason_code: "PRIVATE_KEY_FOUND",
      cap_value: 49,
      description: "Private key detected, score capped at 49",
    },
  ],
  blocking_reasons: [
    {
      rule_id: "R005",
      rule_name: "Private Key",
      severity: "critical",
      file_path: "config/key.pem",
      line_start: 1,
      description: "Private key detected",
    },
  ],
  coverage: {
    status: "complete",
    reasons: [],
    total_findings: 30,
    scored_findings: 30,
    findings_truncated: false,
    total_blocking_findings: 6,
    returned_blocking_reasons: 1,
    blocking_reasons_truncated: false,
    total_scan_errors: 0,
    total_files_scanned: 10,
    total_skipped_files: 1,
  },
};

// ---------------------------------------------------------------------------
// Mock repair plan
// ---------------------------------------------------------------------------

export const mockRepairPlan = {
  schema_version: 1,
  policy_version: "p0-7-v1",
  repair_scope: "sensitive_data_repair",
  task_id: TEST_TASK_ID,
  plan_status: "complete",
  summary: {
    total_repair_groups: 2,
    blocking_repair_groups: 1,
    manual_review_required: false,
    coverage_warning: false,
    groups_truncated: false,
  },
  repair_groups: [
    {
      group_id: "g1",
      action_code: "REPLACE_WITH_ENV_VAR",
      priority: 1,
      blocking: true,
      highest_severity: "critical",
      highest_confidence: "high",
      title: "Replace hardcoded secrets with environment variables",
      description: "Move all hardcoded passwords and tokens to environment variables.",
      related_rule_ids: ["R001", "R006"],
      related_files: ["src/config.py", "src/auth.py"],
      total_related_files: 2,
      returned_related_files: 2,
      related_files_truncated: false,
      finding_count: 5,
      steps: [
        "Create a .env file with the required variables",
        "Update the code to read from process.env or os.environ",
        "Remove the hardcoded values",
      ],
      commands: ["git diff --stat"],
      safety_notes: ["Never commit the .env file to version control"],
      verification_steps: ["Run the application to verify it starts correctly"],
    },
  ],
  verification_steps: ["Verify all secrets are removed from the codebase"],
  agent_prompt: "Please fix the following security issues:\n1. Replace hardcoded passwords with environment variables\n2. Remove private key files",
  source_scan_updated_at: "2025-01-01T00:00:00Z",
  source_assessment_updated_at: "2025-01-01T00:00:00Z",
  source_assessment_policy_version: "p0-6-v1",
  created_at: "2025-01-01T00:00:00Z",
  updated_at: "2025-01-01T00:00:00Z",
};

// ---------------------------------------------------------------------------
// Mock quality report
// ---------------------------------------------------------------------------

function qualityEvidence(
  filePath: string,
  detail: string,
  snippet = "",
): {
  method: string;
  detail: string;
  file_path: string | null;
  line_start: number | null;
  line_end: number | null;
  snippet: string;
} {
  return {
    method: "static_analysis",
    detail,
    file_path: filePath,
    line_start: 10,
    line_end: null,
    snippet,
  };
}

export const mockQualityReport = {
  schema_version: 1,
  task_id: TEST_TASK_ID,
  generated_at: "2025-01-01T00:00:00Z",
  scanner_version: "quality-v1",
  overall_status: "partial",
  summary: {
    total_items: 4,
    manual_decision_items: 1,
    fixable_items: 1,
    auto_fixable_items: 1,
    blocks_completed: 1,
    blocks_not_completed: 1,
  },
  blocks: {
    frontend_dead_code: {
      dimension: "frontend_dead_code",
      label: "前端死代码",
      status: "completed",
      reason_code: null,
      reason_message: "",
      conclusion: {
        headline: "发现 1 个可自动修复项、1 个仅报告项。",
        counts: { total_items: 2, by_severity: { P2: 1, P3: 1 } },
      },
      evidence: [qualityEvidence("frontend/lib", "扫描了 42 个前端模块")],
      items: [
        {
          item_id: "dead-export-1",
          dimension: "frontend_dead_code",
          category: "unused_export",
          conclusion: "导出未被任何模块引用。",
          confidence: "high",
          severity: "P2",
          title: "未引用的导出 helper",
          impact: "增加维护成本与打包体积。",
          suggestion: "删除该导出函数。",
          fixability: "auto_fix",
          manual_decision_required: false,
          limitation: "动态 import 无法完全排除。",
          rule_id: "FE001",
          evidence: [
            qualityEvidence(
              "src/components/ExtremelyLongUnbrokenIdentifierNameThatCannotBreakOnNarrowScreens.tsx",
              "全仓引用检索结果为 0。",
              "export function orphanHelper() {}",
            ),
          ],
          details: {},
        },
        {
          item_id: "dead-report-1",
          dimension: "frontend_dead_code",
          category: "unused_css",
          conclusion: "CSS 类未在代码中出现。",
          confidence: "medium",
          severity: "P3",
          title: "CSS 类可能未使用",
          impact: "样式冗余。",
          suggestion: "人工确认模板字符串拼接后删除。",
          fixability: "report_only",
          manual_decision_required: false,
          limitation: "可能由运行时拼接使用。",
          rule_id: "FE002",
          evidence: [qualityEvidence("app/globals.css", "仅定义，未发现字面量引用。")],
          details: {},
        },
      ],
      fixable_item_ids: ["dead-export-1"],
      manual_confirm_item_ids: [] as string[],
      verification: {},
      coverage: {},
      details: {},
      truncated: false,
      truncation_reason: "",
    },
    font_license_compliance: {
      dimension: "font_license_compliance",
      label: "字体许可与冗余",
      status: "partial",
      reason_code: "FONT_ASSET_UNREADABLE",
      reason_message: "有一份字体文件无法读取元数据。",
      conclusion: {
        headline: "1 项需人工确认、1 项仅报告。",
        counts: { total_fonts: 2, by_source: { css: 1, asset: 1 } },
      },
      evidence: [qualityEvidence("", "枚举到 2 个字体来源。")],
      items: [
        {
          item_id: "font-manual-1",
          dimension: "font_license_compliance",
          category: "license_unverified",
          conclusion: "许可无法确认。",
          confidence: "low",
          severity: "P2",
          title: "Inter 字体许可需人工确认",
          impact: "存在法务风险。",
          suggestion: "确认 LICENSE 后再决定是否分发。",
          fixability: "report_only",
          manual_decision_required: true,
          limitation: "未找到 LICENSE 文件。",
          rule_id: "FONT001",
          evidence: [qualityEvidence("app/globals.css", "仅声明 font-family，未加载字体。")],
          details: { license: "unverified" },
        },
        {
          item_id: "font-report-1",
          dimension: "font_license_compliance",
          category: "declared_not_loaded",
          conclusion: "字体声明但未加载。",
          confidence: "high",
          severity: "P3",
          title: "声明但未加载的字体",
          impact: "视觉回退到系统字体。",
          suggestion: "删除声明或正式引入字体。",
          fixability: "report_only",
          manual_decision_required: false,
          limitation: "不涉及授权义务。",
          rule_id: "FONT002",
          evidence: [qualityEvidence("app/globals.css", "未找到 @font-face。")],
          details: {},
        },
      ],
      fixable_item_ids: [] as string[],
      manual_confirm_item_ids: ["font-manual-1"],
      verification: {},
      coverage: {},
      details: {},
      truncated: false,
      truncation_reason: "",
    },
    backend_route_audit: {
      dimension: "backend_route_audit",
      label: "后端路由审计",
      status: "not_completed",
      reason_code: "ANALYZER_TIMEOUT",
      reason_message: "路由分析超出时间预算。",
      conclusion: { headline: "", counts: {} as Record<string, number> },
      evidence: [],
      items: [],
      fixable_item_ids: [] as string[],
      manual_confirm_item_ids: [] as string[],
      verification: {},
      coverage: {},
      details: {},
      truncated: false,
      truncation_reason: "",
    },
    backend_comment_quality: {
      dimension: "backend_comment_quality",
      label: "中文注释规范",
      status: "not_applicable",
      reason_code: "NO_BACKEND",
      reason_message: "未发现后端源码目录。",
      conclusion: { headline: "", counts: {} as Record<string, number> },
      evidence: [],
      items: [],
      fixable_item_ids: [] as string[],
      manual_confirm_item_ids: [] as string[],
      verification: {},
      coverage: {},
      details: {},
      truncated: false,
      truncation_reason: "",
    },
  },
  limitations: ["仅覆盖已成功解析的文件。", "仅覆盖已成功解析的文件。"],
};

/** Empty quality report: all four dimensions completed with no findings. */
export const mockEmptyQualityReport = {
  ...mockQualityReport,
  overall_status: "completed",
  summary: {
    total_items: 0,
    manual_decision_items: 0,
    fixable_items: 0,
    auto_fixable_items: 0,
    blocks_completed: 4,
    blocks_not_completed: 0,
  },
  blocks: Object.fromEntries(
    Object.entries(mockQualityReport.blocks).map(([key, block]) => [
      key,
      {
        ...block,
        status: "completed",
        reason_code: null,
        reason_message: "",
        conclusion: { headline: "", counts: {} },
        evidence: [],
        items: [],
        fixable_item_ids: [],
        manual_confirm_item_ids: [],
      },
    ]),
  ),
  limitations: [],
};

// ---------------------------------------------------------------------------
// Route helpers
// ---------------------------------------------------------------------------

/** Mock POST /api/check → return task created */
export function mockSubmitSuccess(page: Page, taskId = TEST_TASK_ID) {
  return page.route(`${API_BASE}/api/check`, (route: Route) => {
    route.fulfill({
      status: 202,
      contentType: "application/json",
      body: JSON.stringify({
        task_id: taskId,
        status: "pending",
        check_url: `/api/check/${taskId}`,
      }),
    });
  });
}

/** Mock POST /api/check → return error with given status and error_code */
export function mockSubmitError(
  page: Page,
  httpStatus: number,
  errorCode: string,
  errorMessage?: string,
) {
  return page.route(`${API_BASE}/api/check`, (route: Route) => {
    route.fulfill({
      status: httpStatus,
      contentType: "application/json",
      body: JSON.stringify({
        detail: {
          error_code: errorCode,
          error_message: errorMessage ?? "Error message",
        },
      }),
    });
  });
}

/** Mock POST /api/check/upload → return task created */
export function mockUploadSuccess(page: Page, taskId = TEST_TASK_ID) {
  return page.route(`${API_BASE}/api/check/upload`, (route: Route) => {
    route.fulfill({
      status: 202,
      contentType: "application/json",
      body: JSON.stringify({
        task_id: taskId,
        status: "pending",
        check_url: `/api/check/${taskId}`,
      }),
    });
  });
}

/** Mock POST /api/check/upload → return error with given status and error_code */
export function mockUploadError(
  page: Page,
  httpStatus: number,
  errorCode: string,
  errorMessage?: string,
) {
  return page.route(`${API_BASE}/api/check/upload`, (route: Route) => {
    route.fulfill({
      status: httpStatus,
      contentType: "application/json",
      body: JSON.stringify({
        detail: {
          error_code: errorCode,
          error_message: errorMessage ?? "Error message",
        },
      }),
    });
  });
}

/** Mock GET /api/check/{task_id} → return given status response */
export function mockTaskStatus(page: Page, statusResponse: unknown) {
  return page.route(`${API_BASE}/api/check/${TEST_TASK_ID}`, (route: Route) => {
    route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify(statusResponse),
    });
  });
}

/** Mock GET /api/check/{task_id} → return given status, support sequence */
export function mockTaskStatusSequence(page: Page, responses: unknown[]) {
  let callIndex = 0;
  return page.route(`${API_BASE}/api/check/${TEST_TASK_ID}`, (route: Route) => {
    const response = responses[Math.min(callIndex, responses.length - 1)];
    callIndex++;
    route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify(response),
    });
  });
}

/** Mock all three result endpoints for completed task */
export function mockAllResults(page: Page, opts?: {
  scanResultStatus?: number;
  assessmentStatus?: number;
  repairPlanStatus?: number;
  qualityReportStatus?: number;
  scanResultBody?: unknown;
  assessmentBody?: unknown;
  repairPlanBody?: unknown;
  qualityReportBody?: unknown;
}) {
  const sr = opts?.scanResultStatus ?? 200;
  const ar = opts?.assessmentStatus ?? 200;
  const rr = opts?.repairPlanStatus ?? 200;
  const qr = opts?.qualityReportStatus ?? 200;

  page.route(`${API_BASE}/api/check/${TEST_TASK_ID}/result`, (route: Route) => {
    if (sr !== 200) {
      route.fulfill({
        status: sr,
        contentType: "application/json",
        body: JSON.stringify({
          detail: {
            error_code: "SCAN_RESULT_NOT_READY",
            error_message: "扫描结果尚未生成，请稍后重试。",
          },
        }),
      });
    } else {
      route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify(opts?.scanResultBody ?? mockScanResult),
      });
    }
  });

  page.route(`${API_BASE}/api/check/${TEST_TASK_ID}/assessment`, (route: Route) => {
    if (ar !== 200) {
      route.fulfill({
        status: ar,
        contentType: "application/json",
        body: JSON.stringify({
          detail: {
            error_code: "ASSESSMENT_NOT_AVAILABLE",
            error_message: "安全评估结果不可用，请重新提交检测。",
          },
        }),
      });
    } else {
      route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify(opts?.assessmentBody ?? mockAssessment),
      });
    }
  });

  page.route(`${API_BASE}/api/check/${TEST_TASK_ID}/repair-plan`, (route: Route) => {
    if (rr !== 200) {
      route.fulfill({
        status: rr,
        contentType: "application/json",
        body: JSON.stringify({
          detail: {
            error_code: "REPAIR_PLAN_NOT_AVAILABLE",
            error_message: "修复计划不可用，请重新提交检测以生成修复计划。",
          },
        }),
      });
    } else {
      route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify(opts?.repairPlanBody ?? mockRepairPlan),
      });
    }
  });

  page.route(`${API_BASE}/api/check/${TEST_TASK_ID}/quality-report`, (route: Route) => {
    if (qr !== 200) {
      route.fulfill({
        status: qr,
        contentType: "application/json",
        body: JSON.stringify({
          detail: {
            error_code:
              qr === 409 ? "QUALITY_REPORT_NOT_AVAILABLE" : "QUALITY_REPORT_FAILED",
            error_message:
              qr === 409
                ? "质量报告不可用，请重新提交检测。"
                : "质量报告生成失败。",
          },
        }),
      });
    } else {
      route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify(opts?.qualityReportBody ?? mockQualityReport),
      });
    }
  });
}

/** Mock GET /api/check/{task_id} → network error (fetch throws) */
export function mockTaskStatusNetworkError(page: Page) {
  return page.route(`${API_BASE}/api/check/${TEST_TASK_ID}`, (route: Route) => {
    route.abort("failed");
  });
}
