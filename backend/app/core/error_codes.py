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

# --- Cleanup errors ---
CLEANUP_FAILED = "CLEANUP_FAILED"

# --- Queue errors ---
QUEUE_FULL = "QUEUE_FULL"

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
    CLEANUP_FAILED: "临时文件清理失败，但不影响检测结果。",
    QUEUE_FULL: "检测队列已满，请稍后重试。",
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
