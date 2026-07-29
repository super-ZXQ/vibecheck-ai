"""Deterministic repair policy v1 — sensitive data security dimension.

This module is the SINGLE source of truth for all repair action codes,
action sequences, priority ordering, command allowlists, and fixed
safety texts used by the P0-7 repair plan engine.

IMMUTABILITY CONTRACT:
- Policy values are hardcoded constants. They must NEVER be read from
  environment variables, config files, or runtime parameters.
- All dict-like policy structures use MappingProxyType (immutable).
- All action definitions are frozen dataclasses.
- The same (policy_version, persisted ScanResult, persisted
  AssessmentResult) input MUST always produce identical plan_status,
  summary, repair_groups, verification_steps, and agent_prompt.
- Only created_at, updated_at, and task_id may differ between runs.

SCOPE:
- This policy ONLY handles the "sensitive_data_security" dimension.
- It does NOT perform LLM-based analysis, auto-modify target repos,
  or execute any commands.

COMMAND SAFETY:
- commands fields are strictly limited to a fixed allowlist.
- No command may print, echo, or output secret values.
- No command may rewrite Git history, force push, or delete branches.
"""

from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Any


# ---------------------------------------------------------------------------
# --- Policy identity ---
# ---------------------------------------------------------------------------

POLICY_VERSION = "p0-7-v1"
REPAIR_SCOPE = "sensitive_data_security"
REPAIR_SCHEMA_VERSION = 1


# ---------------------------------------------------------------------------
# --- Fixed action code enumeration ---
# ---------------------------------------------------------------------------

ACTION_REVOKE_OR_ROTATE_SECRET = "REVOKE_OR_ROTATE_SECRET"
ACTION_CREATE_REPLACEMENT_SECRET = "CREATE_REPLACEMENT_SECRET"
ACTION_MOVE_TO_ENVIRONMENT_VARIABLE = "MOVE_TO_ENVIRONMENT_VARIABLE"
ACTION_REMOVE_HARDCODED_SECRET = "REMOVE_HARDCODED_SECRET"
ACTION_UPDATE_GITIGNORE = "UPDATE_GITIGNORE"
ACTION_REVIEW_SECRET_USAGE = "REVIEW_SECRET_USAGE"
ACTION_CLEAN_GIT_HISTORY = "CLEAN_GIT_HISTORY"
ACTION_VERIFY_NO_SECRET_REMAINS = "VERIFY_NO_SECRET_REMAINS"
ACTION_RERUN_SECURITY_SCAN = "RERUN_SECURITY_SCAN"
ACTION_REVIEW_SCAN_COVERAGE = "REVIEW_SCAN_COVERAGE"
ACTION_RESOLVE_SCAN_ERROR = "RESOLVE_SCAN_ERROR"
ACTION_MANUAL_REVIEW_REQUIRED = "MANUAL_REVIEW_REQUIRED"

# Fixed, immutable tuple of ALL valid action codes.
# Runtime code MUST NOT dynamically add new action codes.
ACTION_CODES: tuple[str, ...] = (
    ACTION_REVOKE_OR_ROTATE_SECRET,
    ACTION_CREATE_REPLACEMENT_SECRET,
    ACTION_MOVE_TO_ENVIRONMENT_VARIABLE,
    ACTION_REMOVE_HARDCODED_SECRET,
    ACTION_UPDATE_GITIGNORE,
    ACTION_REVIEW_SECRET_USAGE,
    ACTION_CLEAN_GIT_HISTORY,
    ACTION_VERIFY_NO_SECRET_REMAINS,
    ACTION_RERUN_SECURITY_SCAN,
    ACTION_REVIEW_SCAN_COVERAGE,
    ACTION_RESOLVE_SCAN_ERROR,
    ACTION_MANUAL_REVIEW_REQUIRED,
)

# Frozen set for O(1) membership testing.
_ACTION_CODE_SET: frozenset[str] = frozenset(ACTION_CODES)


def is_valid_action_code(code: str) -> bool:
    """Check if a string is a valid, known action code."""
    return code in _ACTION_CODE_SET


# ---------------------------------------------------------------------------
# --- Action priority (lower = higher priority) ---
# ---------------------------------------------------------------------------

ACTION_PRIORITY: MappingProxyType = MappingProxyType({
    ACTION_REVOKE_OR_ROTATE_SECRET: 1,
    ACTION_CREATE_REPLACEMENT_SECRET: 2,
    ACTION_MOVE_TO_ENVIRONMENT_VARIABLE: 3,
    ACTION_REMOVE_HARDCODED_SECRET: 4,
    ACTION_UPDATE_GITIGNORE: 5,
    ACTION_REVIEW_SECRET_USAGE: 6,
    ACTION_CLEAN_GIT_HISTORY: 7,
    ACTION_VERIFY_NO_SECRET_REMAINS: 8,
    ACTION_RERUN_SECURITY_SCAN: 9,
    ACTION_REVIEW_SCAN_COVERAGE: 10,
    ACTION_RESOLVE_SCAN_ERROR: 11,
    ACTION_MANUAL_REVIEW_REQUIRED: 12,
})


# ---------------------------------------------------------------------------
# --- Severity and confidence ordering ---
# ---------------------------------------------------------------------------

SEVERITY_ORDER: MappingProxyType = MappingProxyType({
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
})

CONFIDENCE_ORDER: MappingProxyType = MappingProxyType({
    "high": 0,
    "medium": 1,
    "low": 2,
})


# ---------------------------------------------------------------------------
# --- Command allowlist ---
# ---------------------------------------------------------------------------

# P0-7 v1 ONLY allows these read-only Git inspection commands.
# All other actions have empty commands lists.
# No command may output secrets, force push, reset, clean, or delete.
_COMMAND_ALLOWLIST: frozenset[str] = frozenset({
    "git status --short",
    "git diff --stat",
    "git log --oneline -20",
})

# Actions that are allowed to have commands.
_ACTIONS_WITH_COMMANDS: frozenset[str] = frozenset({
    ACTION_REVIEW_SECRET_USAGE,
    ACTION_CLEAN_GIT_HISTORY,
    ACTION_VERIFY_NO_SECRET_REMAINS,
})


def get_allowed_commands(action_code: str) -> tuple[str, ...]:
    """Return the fixed command tuple for an action code.

    Only REVIEW_SECRET_USAGE, CLEAN_GIT_HISTORY, and
    VERIFY_NO_SECRET_REMAINS have commands, and only from the
    fixed allowlist. All other actions return an empty tuple.
    """
    if action_code == ACTION_REVIEW_SECRET_USAGE:
        return ("git status --short", "git diff --stat")
    if action_code == ACTION_CLEAN_GIT_HISTORY:
        return ("git log --oneline -20",)
    if action_code == ACTION_VERIFY_NO_SECRET_REMAINS:
        return ("git status --short",)
    return ()


def is_command_allowed(command: str) -> bool:
    """Check if a command string is in the fixed allowlist."""
    return command in _COMMAND_ALLOWLIST


# ---------------------------------------------------------------------------
# --- Frozen RepairAction dataclass ---
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class RepairAction:
    """Immutable repair action definition.

    Frozen dataclass prevents runtime modification of action values.
    Attempting to set attributes raises FrozenInstanceError.
    """
    action_code: str
    priority: int
    blocking: bool
    title: str
    description: str
    steps: tuple[str, ...]
    commands: tuple[str, ...]
    safety_notes: tuple[str, ...]
    verification_steps: tuple[str, ...]


# ---------------------------------------------------------------------------
# --- Fixed action definitions ---
# ---------------------------------------------------------------------------

_ACTION_REVOKE_OR_ROTATE = RepairAction(
    action_code=ACTION_REVOKE_OR_ROTATE_SECRET,
    priority=1,
    blocking=True,
    title="撤销或轮换受影响的凭据",
    description=(
        "立即撤销或轮换每一个受影响的旧凭据。"
        "逐一处理该组中每一个受影响的凭据或位置。"
    ),
    steps=(
        "登录对应平台的管理控制台。",
        "找到被泄露的凭据并立即撤销或禁用。",
        "确认旧凭据已失效，无法再被使用。",
    ),
    commands=(),
    safety_notes=(
        "此步骤必须在修改代码之前完成。",
        "不要在终端中打印或输出凭据值。",
        "不要使用 echo $TOKEN 或 printenv 等命令查看凭据。",
    ),
    verification_steps=(
        "确认旧凭据已从平台撤销。",
        "使用旧凭据尝试访问，应被拒绝。",
    ),
)

_ACTION_CREATE_REPLACEMENT = RepairAction(
    action_code=ACTION_CREATE_REPLACEMENT_SECRET,
    priority=2,
    blocking=True,
    title="创建替代凭据",
    description=(
        "业务仍需要凭据时，创建新的替代凭据。"
        "逐一处理该组中每一个受影响的凭据或位置。"
    ),
    steps=(
        "在对应平台创建新的凭据。",
        "记录新凭据的用途和权限范围。",
        "立即将新凭据存入安全的密钥管理服务。",
    ),
    commands=(),
    safety_notes=(
        "新凭据不得硬编码到源码或配置文件中。",
        "不要在终端中打印或输出新凭据值。",
        "新凭据只能通过环境变量或密钥管理服务注入。",
    ),
    verification_steps=(
        "确认新凭据已安全存储。",
        "确认新凭据未出现在任何源码文件中。",
    ),
)

_ACTION_MOVE_TO_ENV = RepairAction(
    action_code=ACTION_MOVE_TO_ENVIRONMENT_VARIABLE,
    priority=3,
    blocking=True,
    title="迁移到环境变量",
    description=(
        "新凭据只能通过环境变量或密钥管理服务注入。"
        "逐一处理该组中每一个受影响的凭据或位置。"
    ),
    steps=(
        "在运行环境中设置环境变量。",
        "修改代码从环境变量读取凭据。",
        "确保 .env 文件不被提交到版本控制。",
    ),
    commands=(),
    safety_notes=(
        "不要将环境变量值硬编码到代码中。",
        "不要在日志中记录环境变量的值。",
    ),
    verification_steps=(
        "确认代码从环境变量读取凭据。",
        "确认 .env 文件已在 .gitignore 中。",
    ),
)

_ACTION_REMOVE_HARDCODED = RepairAction(
    action_code=ACTION_REMOVE_HARDCODED_SECRET,
    priority=4,
    blocking=True,
    title="删除硬编码凭据",
    description=(
        "删除源码和配置文件中的硬编码值。"
        "逐一处理该组中每一个受影响的凭据或位置。"
    ),
    steps=(
        "找到所有硬编码凭据的位置。",
        "替换为从环境变量读取的代码。",
        "确认硬编码值已完全移除。",
    ),
    commands=(),
    safety_notes=(
        "不要在提交消息中包含凭据值。",
        "不要在注释中保留旧凭据值。",
    ),
    verification_steps=(
        "使用 git diff 确认硬编码值已移除。",
        "运行仓库现有文档或CI中规定的测试命令。",
    ),
)

_ACTION_UPDATE_GITIGNORE = RepairAction(
    action_code=ACTION_UPDATE_GITIGNORE,
    priority=5,
    blocking=True,
    title="更新 .gitignore",
    description=(
        "检查并在必要时更新 .gitignore。"
        "确保 .env、密钥文件等不会被提交。"
    ),
    steps=(
        "检查 .gitignore 是否包含 .env 和常见密钥文件模式。",
        "如有缺失，添加对应模式。",
        "确认已被跟踪的敏感文件已从版本控制中移除。",
    ),
    commands=(),
    safety_notes=(
        "不要在 .gitignore 中写入凭据值。",
    ),
    verification_steps=(
        "确认 .gitignore 包含 .env 模式。",
        "确认敏感文件不再被 Git 跟踪。",
    ),
)

_ACTION_REVIEW_USAGE = RepairAction(
    action_code=ACTION_REVIEW_SECRET_USAGE,
    priority=6,
    blocking=True,
    title="审查凭据使用位置",
    description=(
        "检查旧凭据被使用的位置。"
        "逐一处理该组中每一个受影响的凭据或位置。"
    ),
    steps=(
        "搜索代码中所有使用旧凭据的位置。",
        "确认每处使用都已更新为新凭据或环境变量。",
        "检查是否有其他服务或配置引用了旧凭据。",
    ),
    commands=("git status --short", "git diff --stat"),
    safety_notes=(
        "不要使用 git grep 输出包含凭据的匹配行。",
        "不要使用 grep 输出完整的匹配行。",
    ),
    verification_steps=(
        "确认所有使用位置已更新。",
        "运行仓库现有文档或CI中规定的测试命令。",
    ),
)

_ACTION_CLEAN_HISTORY = RepairAction(
    action_code=ACTION_CLEAN_GIT_HISTORY,
    priority=7,
    blocking=True,
    title="清理 Git 历史",
    description=(
        "该操作会重写远程Git历史，必须在确认团队协作影响和备份后手动执行。"
        "此步骤只提供人工指导，不生成或执行具体历史重写命令。"
    ),
    steps=(
        "确认所有凭据已撤销和替换。",
        "通知所有团队成员即将重写历史。",
        "创建仓库完整备份。",
        "使用官方工具按文档指引重写历史。",
        "通知所有团队成员重新克隆仓库。",
    ),
    commands=("git log --oneline -20",),
    safety_notes=(
        "该操作会重写远程Git历史，必须在确认团队协作影响和备份后手动执行。",
        "不得生成可直接执行的force push命令。",
        "不得生成git-filter-repo或BFG命令。",
        "不得生成git push --force或git push -f命令。",
        "不得生成git reset --hard命令。",
        "不得生成git clean -fd命令。",
    ),
    verification_steps=(
        "确认历史重写已完成。",
        "确认所有团队成员已重新克隆。",
    ),
)

_ACTION_VERIFY_NO_SECRET = RepairAction(
    action_code=ACTION_VERIFY_NO_SECRET_REMAINS,
    priority=8,
    blocking=True,
    title="验证无残留凭据",
    description=(
        "验证仓库中没有残留凭据。"
    ),
    steps=(
        "在当前工作区中搜索是否还有残留的凭据。",
        "在 Git 历史中搜索是否还有残留的凭据。",
        "确认所有凭据都已被撤销和替换。",
    ),
    commands=("git status --short",),
    safety_notes=(
        "不要使用输出完整匹配行的搜索命令。",
        "不要打印任何凭据值。",
    ),
    verification_steps=(
        "确认当前工作区无残留凭据。",
        "确认 Git 历史无残留凭据（如已执行历史清理）。",
    ),
)

_ACTION_RERUN_SCAN = RepairAction(
    action_code=ACTION_RERUN_SECURITY_SCAN,
    priority=9,
    blocking=True,
    title="重新运行安全扫描",
    description=(
        "重新向VibeCheck提交仓库进行复检。"
    ),
    steps=(
        "在完成上述所有修复步骤后，重新向VibeCheck提交仓库。",
        "确认新的扫描结果中没有之前发现的凭据问题。",
    ),
    commands=(),
    safety_notes=(
        "重新运行VibeCheck只作为文字步骤，不虚构不存在的CLI命令。",
    ),
    verification_steps=(
        "确认新的VibeCheck扫描结果中不再包含已修复的凭据问题。",
    ),
)

_ACTION_REVIEW_COVERAGE = RepairAction(
    action_code=ACTION_REVIEW_SCAN_COVERAGE,
    priority=10,
    blocking=False,
    title="审查扫描覆盖率",
    description=(
        "当前修复计划基于不完整扫描结果，完成列出的步骤后仍不能直接确认仓库安全。"
        "请审查扫描覆盖率并解决覆盖率不足的问题。"
    ),
    steps=(
        "检查扫描结果中是否有文件被跳过或扫描失败。",
        "确认扫描范围是否覆盖了所有相关文件。",
        "解决覆盖率不足的问题后重新提交扫描。",
    ),
    commands=(),
    safety_notes=(
        "当前修复计划基于不完整扫描结果，完成列出的步骤后仍不能直接确认仓库安全。",
    ),
    verification_steps=(
        "确认扫描覆盖率已达到完整状态。",
        "重新运行VibeCheck确认无遗漏问题。",
    ),
)

_ACTION_RESOLVE_ERROR = RepairAction(
    action_code=ACTION_RESOLVE_SCAN_ERROR,
    priority=11,
    blocking=False,
    title="解决扫描错误",
    description=(
        "扫描过程中存在错误，请解决后重新提交扫描。"
    ),
    steps=(
        "检查扫描结果中的 scan_errors 列表。",
        "解决导致扫描错误的文件或配置问题。",
        "重新提交仓库进行扫描。",
    ),
    commands=(),
    safety_notes=(
        "不要执行被检查仓库中的代码。",
    ),
    verification_steps=(
        "确认扫描错误已解决。",
        "重新运行VibeCheck确认无扫描错误。",
    ),
)

_ACTION_MANUAL_REVIEW = RepairAction(
    action_code=ACTION_MANUAL_REVIEW_REQUIRED,
    priority=12,
    blocking=False,
    title="需要人工审查",
    description=(
        "存在未知或缺失的修复模板，需要人工审查。"
        "当前修复计划基于不完整扫描结果，完成列出的步骤后仍不能直接确认仓库安全。"
    ),
    steps=(
        "人工审查相关的 Finding 和规则。",
        "根据凭据类型手动确定修复方案。",
        "完成修复后重新运行VibeCheck。",
    ),
    commands=(),
    safety_notes=(
        "不要假设修复方案，必须由有经验的人员审查。",
        "当前修复计划基于不完整扫描结果，完成列出的步骤后仍不能直接确认仓库安全。",
    ),
    verification_steps=(
        "确认人工审查已完成。",
        "重新运行VibeCheck确认问题已解决。",
    ),
)


# Frozen mapping: action_code → RepairAction
_ACTIONS_BY_CODE: MappingProxyType = MappingProxyType({
    ACTION_REVOKE_OR_ROTATE_SECRET: _ACTION_REVOKE_OR_ROTATE,
    ACTION_CREATE_REPLACEMENT_SECRET: _ACTION_CREATE_REPLACEMENT,
    ACTION_MOVE_TO_ENVIRONMENT_VARIABLE: _ACTION_MOVE_TO_ENV,
    ACTION_REMOVE_HARDCODED_SECRET: _ACTION_REMOVE_HARDCODED,
    ACTION_UPDATE_GITIGNORE: _ACTION_UPDATE_GITIGNORE,
    ACTION_REVIEW_SECRET_USAGE: _ACTION_REVIEW_USAGE,
    ACTION_CLEAN_GIT_HISTORY: _ACTION_CLEAN_HISTORY,
    ACTION_VERIFY_NO_SECRET_REMAINS: _ACTION_VERIFY_NO_SECRET,
    ACTION_RERUN_SECURITY_SCAN: _ACTION_RERUN_SCAN,
    ACTION_REVIEW_SCAN_COVERAGE: _ACTION_REVIEW_COVERAGE,
    ACTION_RESOLVE_SCAN_ERROR: _ACTION_RESOLVE_ERROR,
    ACTION_MANUAL_REVIEW_REQUIRED: _ACTION_MANUAL_REVIEW,
})


def get_action(action_code: str) -> RepairAction:
    """Get the frozen RepairAction for a given action code.

    Raises KeyError if the action code is not in the fixed mapping.
    """
    return _ACTIONS_BY_CODE[action_code]


# ---------------------------------------------------------------------------
# --- Blocking finding fixed repair sequence ---
# ---------------------------------------------------------------------------

# When is_blocking == true, this FIXED sequence is always generated
# regardless of repair_template_key. Steps 1-10 must not be skipped.
BLOCKING_ACTION_SEQUENCE: tuple[str, ...] = (
    ACTION_REVOKE_OR_ROTATE_SECRET,
    ACTION_CREATE_REPLACEMENT_SECRET,
    ACTION_MOVE_TO_ENVIRONMENT_VARIABLE,
    ACTION_REMOVE_HARDCODED_SECRET,
    ACTION_UPDATE_GITIGNORE,
    ACTION_REVIEW_SECRET_USAGE,
    ACTION_CLEAN_GIT_HISTORY,
    ACTION_VERIFY_NO_SECRET_REMAINS,
    ACTION_RERUN_SECURITY_SCAN,
)

# Global actions that appear only ONCE in the entire repair plan,
# regardless of how many findings trigger them.
GLOBAL_SINGLETON_ACTIONS: frozenset[str] = frozenset({
    ACTION_VERIFY_NO_SECRET_REMAINS,
    ACTION_RERUN_SECURITY_SCAN,
    ACTION_REVIEW_SCAN_COVERAGE,
    ACTION_RESOLVE_SCAN_ERROR,
    ACTION_MANUAL_REVIEW_REQUIRED,
})


# ---------------------------------------------------------------------------
# --- Non-blocking template mappings ---
# ---------------------------------------------------------------------------

# Each repair_template_key maps to a fixed tuple of action codes.
# Non-blocking findings use these mappings to generate repair groups.
# Blocking findings ALWAYS use BLOCKING_ACTION_SEQUENCE instead.

_TEMPLATE_MAPPINGS: MappingProxyType = MappingProxyType({
    "rotate_github_token": (
        ACTION_REVOKE_OR_ROTATE_SECRET,
        ACTION_CREATE_REPLACEMENT_SECRET,
        ACTION_MOVE_TO_ENVIRONMENT_VARIABLE,
        ACTION_REMOVE_HARDCODED_SECRET,
        ACTION_UPDATE_GITIGNORE,
        ACTION_REVIEW_SECRET_USAGE,
    ),
    "rotate_aws_credentials": (
        ACTION_REVOKE_OR_ROTATE_SECRET,
        ACTION_CREATE_REPLACEMENT_SECRET,
        ACTION_MOVE_TO_ENVIRONMENT_VARIABLE,
        ACTION_REMOVE_HARDCODED_SECRET,
        ACTION_UPDATE_GITIGNORE,
        ACTION_REVIEW_SECRET_USAGE,
    ),
    "rotate_google_api_key": (
        ACTION_REVOKE_OR_ROTATE_SECRET,
        ACTION_CREATE_REPLACEMENT_SECRET,
        ACTION_MOVE_TO_ENVIRONMENT_VARIABLE,
        ACTION_REMOVE_HARDCODED_SECRET,
        ACTION_UPDATE_GITIGNORE,
        ACTION_REVIEW_SECRET_USAGE,
    ),
    "rotate_private_key": (
        ACTION_REVOKE_OR_ROTATE_SECRET,
        ACTION_CREATE_REPLACEMENT_SECRET,
        ACTION_MOVE_TO_ENVIRONMENT_VARIABLE,
        ACTION_REMOVE_HARDCODED_SECRET,
        ACTION_UPDATE_GITIGNORE,
        ACTION_REVIEW_SECRET_USAGE,
    ),
    "use_env_var_password": (
        ACTION_MOVE_TO_ENVIRONMENT_VARIABLE,
        ACTION_REMOVE_HARDCODED_SECRET,
        ACTION_UPDATE_GITIGNORE,
        ACTION_REVIEW_SECRET_USAGE,
    ),
    "use_env_var_secret": (
        ACTION_MOVE_TO_ENVIRONMENT_VARIABLE,
        ACTION_REMOVE_HARDCODED_SECRET,
        ACTION_UPDATE_GITIGNORE,
        ACTION_REVIEW_SECRET_USAGE,
    ),
    "use_env_var_connection_string": (
        ACTION_MOVE_TO_ENVIRONMENT_VARIABLE,
        ACTION_REMOVE_HARDCODED_SECRET,
        ACTION_UPDATE_GITIGNORE,
        ACTION_REVIEW_SECRET_USAGE,
    ),
    "secure_env_file": (
        ACTION_MOVE_TO_ENVIRONMENT_VARIABLE,
        ACTION_UPDATE_GITIGNORE,
        ACTION_REVIEW_SECRET_USAGE,
    ),
    "use_env_var_production": (
        ACTION_MOVE_TO_ENVIRONMENT_VARIABLE,
        ACTION_REMOVE_HARDCODED_SECRET,
        ACTION_UPDATE_GITIGNORE,
        ACTION_REVIEW_SECRET_USAGE,
    ),
})

# All known repair_template_key values (frozen set for membership test).
KNOWN_TEMPLATE_KEYS: frozenset[str] = frozenset(_TEMPLATE_MAPPINGS.keys())


def get_template_actions(template_key: str) -> tuple[str, ...] | None:
    """Get the action code sequence for a repair_template_key.

    Returns None if the key is unknown or missing.
    The caller must handle None by setting plan_status=partial and
    adding a MANUAL_REVIEW_REQUIRED group.
    """
    return _TEMPLATE_MAPPINGS.get(template_key)


def is_known_template_key(key: str) -> bool:
    """Check if a repair_template_key is known."""
    return key in KNOWN_TEMPLATE_KEYS


# ---------------------------------------------------------------------------
# --- Rule ID to template key mapping (R001-R011) ---
# ---------------------------------------------------------------------------

# Maps rule_id prefix to the expected repair_template_key.
# This is used for testing that all R001-R011 rules have explicit mappings.
# Rule R010 (ENV_EXAMPLE_FILE) produces notices, not findings, so it
# has no repair_template_key — but it is listed here for completeness.
RULE_TEMPLATE_MAP: MappingProxyType = MappingProxyType({
    "R001_GITHUB_TOKEN": "rotate_github_token",
    "R002_AWS_ACCESS_KEY": "rotate_aws_credentials",
    "R003_AWS_SECRET_KEY": "rotate_aws_credentials",
    "R004_GOOGLE_API_KEY": "rotate_google_api_key",
    "R005_PRIVATE_KEY": "rotate_private_key",
    "R006_PASSWORD_ASSIGNMENT": "use_env_var_password",
    "R007_GENERIC_TOKEN_ASSIGNMENT": "use_env_var_secret",
    "R008_CONNECTION_STRING": "use_env_var_connection_string",
    "R009_ENV_FILE_PRESENT": "secure_env_file",
    "R010_ENV_EXAMPLE_FILE": "",
    "R011_PRODUCTION_ENV_WITH_SECRET": "use_env_var_production",
})


# ---------------------------------------------------------------------------
# --- Aggregation key ---
# ---------------------------------------------------------------------------

# Fixed aggregation key for grouping findings into repair groups.
# Findings with the same aggregation key are merged into one repair group.
AGGREGATION_KEY_FIELDS: tuple[str, ...] = (
    "action_code",
    "repair_template_key",
    "rule_id",
    "secret_type",
    "blocking",
)


def compute_aggregation_key(
    action_code: str,
    repair_template_key: str,
    rule_id: str,
    secret_type: str,
    blocking: bool,
) -> tuple[str, str, str, str, bool]:
    """Compute the fixed aggregation key for a finding.

    Findings with the same key are merged into one repair group.
    Different provider, rule_id, or secret_type are NOT merged.
    """
    return (
        action_code,
        repair_template_key,
        rule_id,
        secret_type,
        blocking,
    )


# ---------------------------------------------------------------------------
# --- Repair group sort key ---
# ---------------------------------------------------------------------------

def compute_group_sort_key(
    blocking: bool,
    priority: int,
    highest_severity: str,
    highest_confidence: str,
    action_code: str,
    repair_template_key: str,
    rule_id: str,
    secret_type: str,
    related_files_first: str,
) -> tuple:
    """Compute the deterministic sort key for a repair group.

    Sort order (highest priority first):
    1. blocking: true first (0 for true, 1 for false)
    2. priority: ascending
    3. highest_severity: critical, high, medium, low, info
    4. highest_confidence: high, medium, low
    5. action_code: alphabetical
    6. repair_template_key: alphabetical
    7. rule_id: alphabetical
    8. secret_type: alphabetical
    9. related_files first item: alphabetical

    All values are guaranteed to be comparable types (int or str).
    No float, no random, no hash, no time-based logic.
    """
    return (
        0 if blocking else 1,
        priority,
        SEVERITY_ORDER.get(highest_severity, 99),
        CONFIDENCE_ORDER.get(highest_confidence, 99),
        action_code,
        repair_template_key,
        rule_id,
        secret_type,
        related_files_first,
    )


# ---------------------------------------------------------------------------
# --- Partial plan declaration ---
# ---------------------------------------------------------------------------

PARTIAL_DECLARATION = (
    "当前修复计划基于不完整扫描结果，"
    "完成列出的步骤后仍不能直接确认仓库安全。"
)


# ---------------------------------------------------------------------------
# --- Agent prompt fixed requirements ---
# ---------------------------------------------------------------------------

AGENT_PROMPT_REQUIREMENTS: tuple[str, ...] = (
    "1. 在用户当前打开的仓库中操作。",
    "2. 只修改Finding相关文件。",
    "3. 不输出、记录、重复或猜测任何原始secret。",
    "4. 已脱敏文本不可当作真实凭据使用。",
    "5. blocking问题先由用户撤销或轮换旧凭据，再修改代码。",
    "6. 禁止自动force push和Git历史重写。",
    "7. 禁止修改无关业务逻辑。",
    "8. 使用仓库已有文档或CI中的测试命令验证。",
    "9. 输出变更摘要和剩余风险。",
    "10. 停止在commit、push或PR之前，等待用户确认。",
    "11. 修改后重新运行VibeCheck。",
)

# Agent prompt forbidden patterns — must NOT appear in the prompt.
AGENT_PROMPT_FORBIDDEN: tuple[str, ...] = (
    "repo_url",
    "owner",
    "repo_name",
    "snippet",
    "snippet_masked",
    "原始secret",
    "数据库路径",
    "临时路径",
)


# ---------------------------------------------------------------------------
# --- Supported assessment policy versions ---
# ---------------------------------------------------------------------------

# P0-7 repair engine supports assessments produced by these policy versions.
SUPPORTED_ASSESSMENT_POLICY_VERSIONS: frozenset[str] = frozenset({
    "p0-6-v1",
})


def is_supported_assessment_policy(version: str) -> bool:
    """Check if an assessment policy version is supported by P0-7."""
    return version in SUPPORTED_ASSESSMENT_POLICY_VERSIONS
