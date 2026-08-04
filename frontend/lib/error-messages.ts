/**
 * Complete error code → Chinese message mapping.
 *
 * Based on the public codes returned by the backend API routes.
 * Unknown error codes fall back to a fixed generic message.
 * No raw exception text, stack traces, temp paths, or credential patterns
 * are ever displayed.
 */

import { lookup } from "./lookup";

const ERROR_MESSAGES: Record<string, string> = {
  // Task lookup
  TASK_NOT_FOUND: "任务不存在。",
  INVALID_TASK_ID: "任务ID格式无效。",

  // URL validation
  INVALID_REPO_URL: "仓库地址格式无效，请输入合法的 GitHub 公开仓库地址。",

  // Download errors
  REPOSITORY_NOT_FOUND: "仓库不存在或无法访问，请确认地址正确。",
  PRIVATE_REPOSITORY: "仓库不存在或为私有仓库，无法下载。",
  GITHUB_RATE_LIMITED: "GitHub API 速率限制，请稍后重试。",
  DOWNLOAD_TOO_LARGE: "仓库压缩包超过大小限制，无法下载。",
  DOWNLOAD_FAILED: "下载失败，请稍后重试。",

  // Extraction errors
  UNSAFE_ARCHIVE: "压缩包包含不安全内容，已拒绝解压。",
  EXTRACTION_LIMIT_EXCEEDED: "解压内容超过限制（文件数量或总大小），已中止。",

  // Cleanup errors
  CLEANUP_FAILED: "临时文件清理失败，但不影响检测结果。",

  // Queue errors
  QUEUE_FULL: "检测队列已满，请稍后重试。",

  // Scan errors (P0-5)
  SCAN_INTERNAL_ERROR: "扫描过程中发生内部错误，请稍后重试。",
  SCAN_RESULT_PERSIST_FAILED: "扫描结果保存失败，请稍后重试。",
  SCAN_RESULT_NOT_READY: "扫描结果尚未生成，请稍后重试。",
  SCAN_RESULT_TOO_LARGE: "扫描结果数据量过大，无法保存。",
  SCAN_RESULT_MISSING: "扫描结果缺失，请重新提交检测。",

  // Assessment errors (P0-6)
  ASSESSMENT_NOT_READY: "安全评估尚未完成，请稍后重试。",
  ASSESSMENT_NOT_AVAILABLE: "安全评估结果不可用，请重新提交检测。",
  ASSESSMENT_INTERNAL_ERROR: "安全评估过程中发生内部错误，请稍后重试。",
  ASSESSMENT_PERSIST_FAILED: "安全评估结果保存失败，请稍后重试。",
  ASSESSMENT_RESULT_TOO_LARGE: "安全评估结果数据量过大，无法保存。",

  // Repair plan errors (P0-7)
  REPAIR_PLAN_NOT_READY: "修复计划尚未生成，请稍后轮询。",
  REPAIR_PLAN_NOT_AVAILABLE: "修复计划不可用，请重新提交检测以生成修复计划。",
  REPAIR_PLAN_INTERNAL_ERROR: "修复计划生成过程中发生内部错误，请稍后重试。",
  REPAIR_PLAN_PERSIST_FAILED: "修复计划保存失败，请稍后重试。",
  REPAIR_PLAN_TOO_LARGE: "修复计划数据量过大，无法保存。",

  // Service lifecycle
  SERVICE_RESTARTED: "服务在任务执行期间重启，请重新提交检测。",

  // Catch-all
  INTERNAL_ERROR: "内部错误，请稍后重试。",
};

/** Fixed fallback for any error code not in the mapping. */
const UNKNOWN_ERROR_MESSAGE = "内部错误，请稍后重试。";

/** Network-level error message (fetch throws TypeError). */
export const NETWORK_ERROR_MESSAGE = "网络连接失败，请检查网络后重试。";

/** API base URL not configured message. */
export const CONFIG_ERROR_MESSAGE =
  "后端 API 地址未配置，请检查环境变量 NEXT_PUBLIC_API_BASE_URL。";

/**
 * Get the fixed Chinese message for a known error code.
 * Unknown codes return a generic safe message.
 */
export function getErrorMessage(errorCode: string | null | undefined): string {
  if (!errorCode) return UNKNOWN_ERROR_MESSAGE;
  return lookup(ERROR_MESSAGES, errorCode, UNKNOWN_ERROR_MESSAGE);
}
