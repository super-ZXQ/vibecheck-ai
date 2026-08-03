"""Fallback templates for non-blocking findings — used when LLM is unavailable.

Every non-blocking rule has a fixed (explanation, instruction) pair.
When LLM is disabled or fails, these templates provide a safe default.

IMMUTABILITY:
- Templates are hardcoded constants. They must NEVER be read from
  environment variables or config files.
- The same rule_id MUST always produce the same template text.

SECURITY:
- Templates contain NO secrets, NO raw code, NO absolute paths.
- They are generic per-rule-type descriptions, not finding-specific.
"""

from __future__ import annotations

from types import MappingProxyType
from typing import NamedTuple


class FallbackTemplate(NamedTuple):
    """A fixed explanation and instruction for a non-blocking rule."""
    explanation: str
    instruction: str


# ---------------------------------------------------------------------------
# --- Non-blocking sensitive data rules (R006-R009, R011) ---
# R001-R005 are BLOCKING and use local repair templates, not LLM.
# R010 is a ScanNotice, not a Finding, so no template needed.
# ---------------------------------------------------------------------------

_FALLBACK_TEMPLATES: dict[str, FallbackTemplate] = {
    # --- Sensitive data (non-blocking) ---
    "R006_PASSWORD_ASSIGNMENT": FallbackTemplate(
        explanation=(
            "代码中将密码直接赋值给变量。硬编码密码可能被提交到版本库后泄露，"
            "即使后续删除也会留在 Git 历史中。"
        ),
        instruction=(
            "将密码移到环境变量或密钥管理服务中，代码中只引用变量名。"
            "检查 Git 历史，必要时轮换已泄露的密码。"
        ),
    ),
    "R007_GENERIC_TOKEN_ASSIGNMENT": FallbackTemplate(
        explanation=(
            "代码中将 API 密钥或 Token 直接赋值给变量。密钥硬编码在源码中"
            "有泄露风险，任何能访问代码库的人都能获取该凭据。"
        ),
        instruction=(
            "将密钥移到环境变量或专用密钥管理服务中。"
            "在 .gitignore 中添加相关文件，防止意外提交。"
            "如果密钥已被提交，立即轮换并清理 Git 历史。"
        ),
    ),
    "R008_CONNECTION_STRING": FallbackTemplate(
        explanation=(
            "连接字符串中包含用户名和密码等敏感信息。"
            "硬编码的数据库连接凭据会随代码一起进入版本库，造成安全风险。"
        ),
        instruction=(
            "将连接字符串拆分为环境变量（主机、端口、用户名、密码分别设置），"
            "在代码中动态拼接。确保密码不出现在源码或日志中。"
        ),
    ),
    "R009_ENV_FILE_PRESENT": FallbackTemplate(
        explanation=(
            "项目中存在 .env 文件。.env 文件通常包含环境变量和密钥，"
            "如果被提交到版本库会导致敏感信息泄露。"
        ),
        instruction=(
            "确认 .env 文件已添加到 .gitignore。"
            "如果 .env 已被提交，检查其中是否包含真实密钥并轮换。"
            "提供 .env.example 模板供团队成员参考。"
        ),
    ),
    "R011_PRODUCTION_ENV_WITH_SECRET": FallbackTemplate(
        explanation=(
            "生产环境配置文件中包含硬编码的敏感值。"
            "生产环境文件中的密码、密钥等如果泄露会造成严重安全事故。"
        ),
        instruction=(
            "将生产环境敏感值移到环境变量或密钥管理服务中。"
            "确保生产环境配置文件不包含明文密码或密钥。"
            "检查 Git 历史并轮换已泄露的凭据。"
        ),
    ),

    # --- Incomplete content ---
    "I001_TODO_COMMENT": FallbackTemplate(
        explanation=(
            "代码中包含 TODO/FIXME/HACK 等未完成标记。"
            "这些标记表示有尚未完成的工作，可能影响功能完整性。"
        ),
        instruction=(
            "检查 TODO 标记的内容，评估是否需要立即处理。"
            "如果标记的是已知技术债务，建议在任务跟踪系统中记录。"
            "上线前清理所有阻塞性的 TODO。"
        ),
    ),
    "I002_UNIMPLEMENTED_CODE": FallbackTemplate(
        explanation=(
            "代码中存在显式标记的未实现逻辑（如 NotImplementedError、"
            "raise NotImplementedError）。这会导致运行时崩溃。"
        ),
        instruction=(
            "实现该函数或方法的具体逻辑。"
            "如果暂时无法实现，返回合理的默认值或抛出有意义的业务异常。"
            "上线前必须确保所有代码路径都有可用实现。"
        ),
    ),
    "I003_PLACEHOLDER_RETURN": FallbackTemplate(
        explanation=(
            "函数返回了占位值（如 return None、return True、return \"\"）。"
            "这通常表示逻辑尚未完成，返回值可能不符合调用方预期。"
        ),
        instruction=(
            "检查函数的预期返回值类型和语义，替换占位值为正确实现。"
            "添加单元测试验证返回值的正确性。"
        ),
    ),
    "I004_DEBUG_BREAKPOINT": FallbackTemplate(
        explanation=(
            "代码中包含调试断点（如 breakpoint()、pdb.set_trace()）。"
            "断点会导致程序在生产环境中意外暂停。"
        ),
        instruction=(
            "删除所有调试断点语句。"
            "配置代码检查工具（如 flake8、ruff）自动检测并阻止提交断点代码。"
        ),
    ),
    "I005_EXCESSIVE_DEBUG_OUTPUT": FallbackTemplate(
        explanation=(
            "代码中包含过多的调试输出语句（如大量 print 语句）。"
            "调试输出会影响性能，并可能在日志中泄露敏感信息。"
        ),
        instruction=(
            "将 print 语句替换为正式的日志框架（如 logging）。"
            "设置合理的日志级别，生产环境使用 WARNING 或以上。"
            "确保日志中不输出敏感信息。"
        ),
    ),

    # --- Deployability ---
    "D001_PRODUCTION_START": FallbackTemplate(
        explanation=(
            "项目缺少可复现的生产启动方式。没有明确的生产启动命令，"
            "部署过程可能依赖手动操作，容易出错。"
        ),
        instruction=(
            "在 README 或部署文档中明确记录生产启动命令。"
            "使用 Docker Compose 或类似的声明式配置确保部署一致性。"
            "启动命令应包含环境变量设置和依赖检查。"
        ),
    ),
    "D002_ENVIRONMENT_DOCUMENTATION": FallbackTemplate(
        explanation=(
            "项目使用了环境变量但缺少环境配置文档。"
            "团队成员和新部署环境无法知道需要设置哪些环境变量。"
        ),
        instruction=(
            "创建 .env.example 文件列出所有需要的环境变量（用占位值）。"
            "在 README 中说明每个环境变量的用途和默认值。"
        ),
    ),
    "D003_DEPENDENCY_LOCK": FallbackTemplate(
        explanation=(
            "项目缺少依赖锁定文件。没有锁定文件，不同环境安装的依赖版本"
            "可能不一致，导致不可复现的构建问题。"
        ),
        instruction=(
            "提交依赖锁定文件（如 package-lock.json、yarn.lock、"
            "requirements.txt 带版本号、poetry.lock）。"
            "确保 CI/CD 和部署使用锁定文件安装依赖。"
        ),
    ),
    "D004_DEPLOYMENT_DOCUMENTATION": FallbackTemplate(
        explanation=(
            "README 中缺少生产部署说明。没有部署文档，新环境搭建"
            "和问题排查会变得困难。"
        ),
        instruction=(
            "在 README 中添加部署章节，包括：生产环境前置条件、"
            "部署步骤、启动命令、健康检查方式。"
        ),
    ),
    "D005_DOCKER_MISSING": FallbackTemplate(
        explanation=(
            "项目缺少容器化配置（Dockerfile 或 Docker Compose）。"
            "没有容器化配置，部署环境的一致性难以保证。"
        ),
        instruction=(
            "添加 Dockerfile 定义构建和运行环境。"
            "推荐使用 Docker Compose 编排多容器服务。"
            "基础镜像应使用明确版本标签，避免使用 latest。"
        ),
    ),
    "D006_DOCKER_MISSING_FROM": FallbackTemplate(
        explanation=(
            "Dockerfile 中缺少有效的 FROM 指令。"
            "没有 FROM 指令的 Dockerfile 无法构建镜像。"
        ),
        instruction=(
            "在 Dockerfile 第一行添加有效的 FROM 指令。"
            "使用官方基础镜像并指定明确版本标签。"
        ),
    ),
    "D007_DOCKER_MUTABLE_BASE": FallbackTemplate(
        explanation=(
            "Docker 基础镜像使用了 latest 或未指定版本标签。"
            "可变标签会导致每次构建拉取不同版本的镜像，破坏可复现性。"
        ),
        instruction=(
            "将基础镜像标签从 latest 改为具体版本号。"
            "推荐使用镜像摘要（digest）确保不可变。"
        ),
    ),
    "D008_DOCKER_ROOT_USER": FallbackTemplate(
        explanation=(
            "Docker 容器以 root 用户运行或未指定运行用户。"
            "以 root 运行容器会增加安全风险。"
        ),
        instruction=(
            "在 Dockerfile 中创建非 root 用户并切换。"
            "使用 USER 指令指定运行用户。"
            "确保应用文件权限正确设置。"
        ),
    ),
    "D009_DOCKER_MISSING_START": FallbackTemplate(
        explanation=(
            "Docker 配置中缺少明确的启动命令。"
            "没有启动命令，容器无法自动启动应用。"
        ),
        instruction=(
            "在 Dockerfile 中使用 CMD 或 ENTRYPOINT 指定启动命令。"
            "在 Docker Compose 中确认 command 配置正确。"
        ),
    ),
    "D010_INVALID_DEPLOYMENT_CONFIG": FallbackTemplate(
        explanation=(
            "部署配置文件存在语法或结构问题。"
            "无效的部署配置会导致构建或启动失败。"
        ),
        instruction=(
            "检查 Dockerfile 或 Docker Compose 文件的语法。"
            "使用 docker compose config 验证配置。"
            "确保所有引用的路径和镜像都存在。"
        ),
    ),

    # --- Basic security ---
    "B001_API_AUTHENTICATION": FallbackTemplate(
        explanation=(
            "检测到 API 路由缺少身份认证控制。"
            "未受保护的 API 端点可能被未授权访问。"
        ),
        instruction=(
            "为非公开 API 路由添加身份认证中间件。"
            "使用 JWT、API Key 或 OAuth 等认证机制。"
            "在文档中标注故意公开的端点。"
        ),
    ),
    "B002_INPUT_VALIDATION": FallbackTemplate(
        explanation=(
            "API 项目中读取请求输入时缺少输入验证。"
            "未验证的输入可能导致注入攻击或数据处理错误。"
        ),
        instruction=(
            "使用框架的 schema 验证工具（如 Pydantic、Zod）"
            "验证请求体、查询参数和路径参数。"
            "对输入进行类型检查、长度限制和格式验证。"
        ),
    ),
    "B003_RATE_LIMITING": FallbackTemplate(
        explanation=(
            "API 路由缺少速率限制控制。"
            "没有速率限制的 API 容易遭受暴力攻击和滥用。"
        ),
        instruction=(
            "在应用层或网关层添加速率限制。"
            "使用令牌桶或滑动窗口算法控制请求频率。"
            "在响应头中返回限流信息。"
        ),
    ),
    "B004_PERMISSIVE_CORS": FallbackTemplate(
        explanation=(
            "检测到宽松的 CORS 配置（允许所有来源）。"
            "通配符 CORS 配置允许任意网站跨域访问 API。"
        ),
        instruction=(
            "将通配符来源替换为可信的生产域名列表。"
            "仅允许可信域名访问敏感 API。"
        ),
    ),
    "B005_SQL_INJECTION": FallbackTemplate(
        explanation=(
            "SQL 语句中动态拼接了请求来源的输入。"
            "这是 SQL 注入漏洞的高风险模式。"
        ),
        instruction=(
            "使用参数化查询或安全的查询构建器。"
            "确保请求参数不直接出现在 SQL 文本中。"
            "对所有数据库输入使用参数绑定。"
        ),
    ),

    # --- Documentation consistency ---
    "C001_README_COMPLETENESS": FallbackTemplate(
        explanation=(
            "项目缺少足够完整的 README 文件。"
            "README 是项目入口文档，不完整会影响理解和使用。"
        ),
        instruction=(
            "创建或完善根目录 README 文件。"
            "包含项目简介、安装步骤、使用方法、配置说明等核心内容。"
            "建议至少 100 字以上的有效说明文字。"
        ),
    ),
    "C002_TECH_STACK_MISMATCH": FallbackTemplate(
        explanation=(
            "README 中声明的技术栈与实际依赖不一致。"
            "文档与代码不匹配会误导开发者。"
        ),
        instruction=(
            "在 README 中添加文档中声明的技术对应的依赖包。"
            "或者修正 README 中的技术栈描述，使其与实际一致。"
        ),
    ),
    "C003_START_COMMAND_MISMATCH": FallbackTemplate(
        explanation=(
            "README 中记录的启动命令引用了不存在的脚本或路径。"
            "无效的启动命令会导致新用户无法运行项目。"
        ),
        instruction=(
            "修正 README 中的启动命令，使其匹配实际项目结构。"
            "或添加文档中引用的脚本文件和入口。"
        ),
    ),
    "C004_PROJECT_STRUCTURE_MISMATCH": FallbackTemplate(
        explanation=(
            "README 中展示的项目结构路径在仓库中不存在。"
            "过时的目录结构文档会造成混淆。"
        ),
        instruction=(
            "更新 README 中的项目结构说明，反映当前实际目录。"
            "或恢复文档中引用的目录和文件。"
        ),
    ),
}

# Immutable public view
FALLBACK_TEMPLATES: MappingProxyType[str, FallbackTemplate] = MappingProxyType(
    _FALLBACK_TEMPLATES
)


def get_fallback_template(rule_id: str) -> FallbackTemplate | None:
    """Return the fallback template for a rule_id, or None if unknown.

    Unknown rule_ids return None — callers should handle this by
    using a generic default template.
    """
    return _FALLBACK_TEMPLATES.get(rule_id)


# Generic fallback when rule_id is not in the template map.
GENERIC_FALLBACK = FallbackTemplate(
    explanation="检测到一项需要关注的问题，建议人工检查相关代码。",
    instruction="请检查相关代码并按照最佳实践进行修复。",
)
