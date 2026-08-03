"""Error codes for VibeCheck task processing.

All error codes are machine-readable strings. The corresponding
error_message stored in the database is always desensitized — it must
NOT contain tokens, full repo content, temp directory absolute paths,
or internal exception stacks.
"""

# --- URL validation ---
INVALID_REPO_URL = "INVALID_REPO_URL"

# --- Download errors ---
REPOSITORY_NOT_FOUND = "REPOSITORY_NOT_FOUND"
PRIVATE_REPOSITORY = "PRIVATE_REPOSITORY"
GITHUB_RATE_LIMITED = "GITHUB_RATE_LIMITED"
DOWNLOAD_TOO_LARGE = "DOWNLOAD_TOO_LARGE"
DOWNLOAD_FAILED = "DOWNLOAD_FAILED"

# --- Extraction errors ---
UNSAFE_ARCHIVE = "UNSAFE_ARCHIVE"
EXTRACTION_LIMIT_EXCEEDED = "EXTRACTION_LIMIT_EXCEEDED"

# --- Stage timeout errors (P2-3) ---
# Each stage has its own timeout error code so callers can identify
# which stage hung. All messages are desensitized.
EXTRACT_TIMEOUT = "EXTRACT_TIMEOUT"
SCAN_TIMEOUT = "SCAN_TIMEOUT"
ASSESSMENT_TIMEOUT = "ASSESSMENT_TIMEOUT"
REPAIR_PLAN_TIMEOUT = "REPAIR_PLAN_TIMEOUT"

# --- Cleanup errors ---
CLEANUP_FAILED = "CLEANUP_FAILED"

# --- Queue errors ---
QUEUE_FULL = "QUEUE_FULL"

# --- Scan errors (P0-5) ---
SCAN_INTERNAL_ERROR = "SCAN_INTERNAL_ERROR"
SCAN_RESULT_PERSIST_FAILED = "SCAN_RESULT_PERSIST_FAILED"
SCAN_RESULT_NOT_READY = "SCAN_RESULT_NOT_READY"
SCAN_RESULT_TOO_LARGE = "SCAN_RESULT_TOO_LARGE"
SCAN_RESULT_MISSING = "SCAN_RESULT_MISSING"

# --- Assessment errors (P0-6) ---
ASSESSMENT_NOT_READY = "ASSESSMENT_NOT_READY"
ASSESSMENT_NOT_AVAILABLE = "ASSESSMENT_NOT_AVAILABLE"
ASSESSMENT_INTERNAL_ERROR = "ASSESSMENT_INTERNAL_ERROR"
ASSESSMENT_PERSIST_FAILED = "ASSESSMENT_PERSIST_FAILED"
ASSESSMENT_RESULT_TOO_LARGE = "ASSESSMENT_RESULT_TOO_LARGE"

# --- Repair plan errors (P0-7) ---
REPAIR_PLAN_NOT_READY = "REPAIR_PLAN_NOT_READY"
REPAIR_PLAN_NOT_AVAILABLE = "REPAIR_PLAN_NOT_AVAILABLE"
REPAIR_PLAN_INTERNAL_ERROR = "REPAIR_PLAN_INTERNAL_ERROR"
REPAIR_PLAN_PERSIST_FAILED = "REPAIR_PLAN_PERSIST_FAILED"
REPAIR_PLAN_TOO_LARGE = "REPAIR_PLAN_TOO_LARGE"

# --- LLM analysis errors (P1-4) ---
# LLM analysis is non-blocking: failures fall back to templates.
# These codes are used for logging and internal tracking only.
LLM_ANALYSIS_NOT_READY = "LLM_ANALYSIS_NOT_READY"
LLM_ANALYSIS_NOT_AVAILABLE = "LLM_ANALYSIS_NOT_AVAILABLE"
LLM_ANALYSIS_INTERNAL_ERROR = "LLM_ANALYSIS_INTERNAL_ERROR"
LLM_ANALYSIS_PERSIST_FAILED = "LLM_ANALYSIS_PERSIST_FAILED"
LLM_ANALYSIS_TOO_LARGE = "LLM_ANALYSIS_TOO_LARGE"

# --- Service lifecycle ---
SERVICE_RESTARTED = "SERVICE_RESTARTED"

# --- Catch-all ---
INTERNAL_ERROR = "INTERNAL_ERROR"


# --- Desensitized error message templates ---

_ERROR_MESSAGES = {
    INVALID_REPO_URL: "仓库地址格式无效，请输入合法的 GitHub 公开仓库地址。",
    REPOSITORY_NOT_FOUND: "仓库不存在或无法访问，请确认地址正确。",
    PRIVATE_REPOSITORY: "仓库不存在或为私有仓库，无法下载。",
    GITHUB_RATE_LIMITED: "GitHub API 速率限制，请稍后重试。",
    DOWNLOAD_TOO_LARGE: "仓库压缩包超过大小限制，无法下载。",
    DOWNLOAD_FAILED: "下载失败，请稍后重试。",
    UNSAFE_ARCHIVE: "压缩包包含不安全内容，已拒绝解压。",
    EXTRACTION_LIMIT_EXCEEDED: "解压内容超过限制（文件数量或总大小），已中止。",
    EXTRACT_TIMEOUT: "解压阶段超时，已中止。",
    SCAN_TIMEOUT: "扫描阶段超时，已中止。",
    ASSESSMENT_TIMEOUT: "安全评估阶段超时，已中止。",
    REPAIR_PLAN_TIMEOUT: "修复计划生成阶段超时，已中止。",
    CLEANUP_FAILED: "临时文件清理失败，但不影响检测结果。",
    QUEUE_FULL: "检测队列已满，请稍后重试。",
    SCAN_INTERNAL_ERROR: "扫描过程中发生内部错误，请稍后重试。",
    SCAN_RESULT_PERSIST_FAILED: "扫描结果保存失败，请稍后重试。",
    SCAN_RESULT_NOT_READY: "扫描结果尚未生成，请稍后重试。",
    SCAN_RESULT_TOO_LARGE: "扫描结果数据量过大，无法保存。",
    SCAN_RESULT_MISSING: "扫描结果缺失，请重新提交检测。",
    ASSESSMENT_NOT_READY: "安全评估尚未完成，请稍后重试。",
    ASSESSMENT_NOT_AVAILABLE: "安全评估结果不可用，请重新提交检测。",
    ASSESSMENT_INTERNAL_ERROR: "安全评估过程中发生内部错误，请稍后重试。",
    ASSESSMENT_PERSIST_FAILED: "安全评估结果保存失败，请稍后重试。",
    ASSESSMENT_RESULT_TOO_LARGE: "安全评估结果数据量过大，无法保存。",
    REPAIR_PLAN_NOT_READY: "修复计划尚未生成，请稍后轮询。",
    REPAIR_PLAN_NOT_AVAILABLE: "修复计划不可用，请重新提交检测以生成修复计划。",
    REPAIR_PLAN_INTERNAL_ERROR: "修复计划生成过程中发生内部错误，请稍后重试。",
    REPAIR_PLAN_PERSIST_FAILED: "修复计划保存失败，请稍后重试。",
    REPAIR_PLAN_TOO_LARGE: "修复计划数据量过大，无法保存。",
    LLM_ANALYSIS_NOT_READY: "LLM 分析尚未完成，请稍后轮询。",
    LLM_ANALYSIS_NOT_AVAILABLE: "LLM 分析结果不可用，已使用回退模板。",
    LLM_ANALYSIS_INTERNAL_ERROR: "LLM 分析过程中发生内部错误，已使用回退模板。",
    LLM_ANALYSIS_PERSIST_FAILED: "LLM 分析结果保存失败，已使用回退模板。",
    LLM_ANALYSIS_TOO_LARGE: "LLM 分析结果数据量过大，已使用回退模板。",
    SERVICE_RESTARTED: "服务在任务执行期间重启，请重新提交检测。",
    INTERNAL_ERROR: "内部错误，请稍后重试。",
}


def get_error_message(error_code: str) -> str:
    """Return a desensitized, user-facing error message for the given code.

    If the code is unknown, returns a generic internal error message.
    Never includes sensitive information.
    """
    return _ERROR_MESSAGES.get(error_code, _ERROR_MESSAGES[INTERNAL_ERROR])


def sanitize_error_message(raw_message: str) -> str:
    """Sanitize a raw error message by removing potential sensitive content.

    Strips:
    - File paths (absolute paths starting with / or containing temp dirs)
    - Stack traces
    - Token patterns (ghp_, Bearer, etc.)
    - Raw exception type details

    Returns a safe, generic message.
    """
    import re

    # Remove absolute paths (Unix and Windows)
    sanitized = re.sub(
        r'[/\\]?[a-zA-Z0-9_\-./\\]+\.tar\.gz', '[file]', raw_message
    )
    sanitized = re.sub(r'/tmp/[^\s]+', '[temp_path]', sanitized)
    sanitized = re.sub(r'[A-Z]:\\[^\s]+', '[temp_path]', sanitized)

    # Remove token patterns
    sanitized = re.sub(r'ghp_[A-Za-z0-9]+', '[token]', sanitized)
    sanitized = re.sub(r'Bearer\s+[A-Za-z0-9._-]+', '[token]', sanitized)
    sanitized = re.sub(r'AKIA[A-Z0-9]+', '[key]', sanitized)

    # Remove stack trace lines
    sanitized = re.sub(
        r'Traceback \(most recent call last\):.*', '[stack_trace]',
        sanitized, flags=re.DOTALL
    )

    # If the message still looks like it contains sensitive info, return generic
    if len(sanitized) > 200:
        return get_error_message(INTERNAL_ERROR)

    return sanitized
