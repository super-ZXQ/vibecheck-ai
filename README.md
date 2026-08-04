# VibeCheck

项目上线体检工具 — 面向 Vibe Coding 与 AI 编程初学者。

用户提交公开 GitHub 仓库地址，系统读取代码与文档，从五个维度检查项目是否适合正式上线，输出评分、风险清单与可复制的修复指令。

## 功能特性

- **五个扫描维度**：敏感信息安全、未完成内容、可部署性与生产配置、基础安全、文档一致性。
- **安全评分**：0–100 分制，含评分明细、评分上限与加权扣分说明；未完成内容、可部署性、基础安全、文档一致性暂不计入安全评分。
- **检测流程可视化**：下载 → 解压 → 扫描 → 评估 → 修复 → 分析，六步进度指示 + 实时百分比与文件/大小统计。
- **发现问题清单**：按严重程度分级，支持按维度筛选、按严重性筛选、关键词搜索与分页。
- **安全评估**：默认折叠的评分明细与评分上限，逐条可展开查看依据。
- **修复计划**：按维度分组的可复制修复指令，支持一键复制整段 Agent Prompt，并提供「不会自动执行」免责声明。
- **LLM 分析**：基于非阻断式分析生成修复建议，结果不可用时自动回退到模板。
- **检测历史**：浏览器本地持久化的检测记录卡片化展示，失败任务标注「检测失败」。
- **结果导出**：将检测结果导出为 JSON 报告文件（含扫描、评估、修复计划与 AI 分析）。
- **本地上传通道**：支持上传 `.zip` / `.tar.gz` 压缩包或本地文件夹替代 GitHub 下载（压缩包 ≤ 50 MB，解压总量 ≤ 200 MB，单文件 ≤ 25 MB，文件数 ≤ 2000）。
- **浅色玻璃拟态界面**：无外部 CSS/JS/字体依赖，纯 CSS 渐变、玻璃拟态与内联 SVG。

## 技术栈

| 层 | 技术 |
| --- | --- |
| 前端 | Next.js (App Router) + React + TypeScript |
| 前端测试 | Playwright (e2e) + Node 内置测试运行器 (单元) |
| 后端 | FastAPI + SQLAlchemy + Pydantic |
| 后端测试 | pytest |
| 存储 | SQLite |
| 运行 | Docker Compose（开发 / 生产双模式） |

## 快速开始

```bash
# 1. 复制环境变量配置
cp .env.example .env

# 2. 一键启动前后端
docker compose up --build

# 3. 访问
# 前端: http://localhost:3000
# 后端 API: http://localhost:8000/api/health
```

## Docker 部署

### 开发模式

```bash
docker compose up --build
```

开发模式挂载源代码并启用热重载，适合本地开发调试。

### 生产模式

生产模式使用独立的只读、非 root 多阶段镜像，不挂载源代码，也不会启动
Next.js 开发服务器。

```bash
# 1. 复制并检查公开地址、CORS 与 Host 白名单
cp production.env.example production.env

# 2. 构建并启动生产栈
docker compose \
  --env-file production.env \
  -f docker-compose.production.yml \
  up --build -d

# 3. 验证就绪状态
curl http://localhost:8000/api/ready
curl http://localhost:3000/health
```

`NEXT_PUBLIC_API_BASE_URL` 会在前端镜像构建时固化，部署地址变化后必须重新
构建前端镜像。面向非本机访问时，应在服务前放置 TLS 反向代理，并把
`CORS_ALLOWED_ORIGINS` 改成实际 HTTPS Origin，并将公网 Host 追加到
`TRUSTED_HOSTS`。不得删除 `127.0.0.1`，否则后端会在启动时拒绝配置，容器
健康检查也无法通过。

后端使用内存中的 `/tmp` 保存下载的压缩包和解压目录；两者与运行开销可能
同时占用临时空间。`BACKEND_TMPFS_SIZE` 不得低于最大压缩包（50 MB）与最大
解压大小（200 MB）之和，并应保留额外余量，默认值为 `320m`。生产配置
缺失、使用默认数据库路径或对远程来源使用 HTTP 时，后端会拒绝启动。

单个仓库文件的解压上限默认为 25 MB，可通过 `MAX_SINGLE_FILE_SIZE` 下调或
上调，但硬上限为 50 MB。超过独立 1 MB 扫描上限的文件只会安全解压并记录为
跳过，不会读入规则扫描；压缩包 50 MB 与解压总量 200 MB 的限制保持不变。

本地上传的压缩包与文件夹同样写入 `/tmp` 临时目录，`BACKEND_TMPFS_SIZE`
的计算已包含上传上限（压缩包 50 MB + 解压总量 200 MB）；上传任务在完成或
失败后立即清理临时目录。

生产响应会发送 HSTS 头，但浏览器只会在服务经过 HTTPS 反向代理访问时执行
HSTS；本机 HTTP 验收仅用于确认响应头存在，不能替代真实 TLS 部署验证。

## API 文档

### 提交检测

`POST /api/check`

```json
{ "repo_url": "https://github.com/owner/repo" }
```

响应：`{ "task_id": "...", "status": "queued", "check_url": "/check/{task_id}" }`

非法 URL 返回 `400 INVALID_REPO_URL`；队列已满返回 `429 QUEUE_FULL`。

### 本地上传

`POST /api/check/upload`（multipart/form-data）

- `mode=archive`：单个 `file` 字段，支持 `.zip` / `.tar.gz` / `.tgz`，内容按魔数识别。
- `mode=folder`：多个 `file` 字段，文件名携带相对路径（`webkitRelativePath`），后端按该路径重建目录结构。

限制：压缩包 ≤ 50 MB、解压总量 ≤ 200 MB、单文件 ≤ 25 MB（可经
`MAX_SINGLE_FILE_SIZE` 下调/上调，硬上限 50 MB）、文件数 ≤ 2000。

响应：`{ "task_id": "...", "status": "pending", "check_url": "/check/{task_id}" }`

超限返回 `413 UPLOAD_TOO_LARGE`；格式非法或包含不安全内容（路径穿越、符号链接）返回 `400 INVALID_UPLOAD`；队列已满返回 `429 QUEUE_FULL`。上传任务与 GitHub 检测共用同一处理队列，任务目录随任务结束一并清理。

### 轮询任务状态

`GET /api/check/{task_id}`

返回 `status`（`queued` / `running` / `completed` / `failed`）、`stage`、
`progress`、`file_count`、`total_size`、`score`、`scan_summary` 等。
`status = failed` 时返回 `error_code` 与脱敏后的 `error_message`。

### 拉取各阶段结果

| 端点 | 内容 |
| --- | --- |
| `GET /api/check/{task_id}/result` | 扫描结果（findings 与五维度计数） |
| `GET /api/check/{task_id}/assessment` | 安全评估（评分、评分明细、评分上限） |
| `GET /api/check/{task_id}/repair-plan` | 修复计划（分组修复指令 + Agent Prompt） |
| `GET /api/check/{task_id}/llm-analysis` | LLM 分析（非阻断，409 表示不可用并回退模板） |

### 健康检查

| 端点 | 用途 |
| --- | --- |
| `GET /api/health` | 存活探针 |
| `GET /api/ready` | 就绪探针（生产 compose 健康检查使用） |

所有错误均返回脱敏后的 `error_code`（如 `GITHUB_RATE_LIMITED`、
`DOWNLOAD_TOO_LARGE`、`SCAN_TIMEOUT`、`REPAIR_PLAN_NOT_READY`）与对应的
用户可读中文消息，不含 token、绝对路径、堆栈或原始异常内容。

## 项目结构

```
vibecheck/
├── frontend/               # Next.js 前端
│   ├── app/
│   │   ├── page.tsx             # 首页（提交表单 / 示例仓库 / 历史记录）
│   │   ├── check/[task_id]/     # 检测结果页（轮询 + 结果展示）
│   │   ├── globals.css          # 视觉体系（玻璃拟态设计令牌）
│   │   └── layout.tsx           # 背景装饰层 / 顶部导航 / 页脚
│   ├── components/              # CheckProgress / ScoreSummary / ResultTabs /
│   │                             # ScanResults / AssessmentDetails /
│   │                             # RepairPlan / LLMAnalysis 等
│   ├── hooks/                   # use-count-up 等
│   ├── lib/                     # API 客户端 / 类型 / 导出 / 历史记录
│   ├── e2e/                     # Playwright 端到端测试
│   └── Dockerfile(.production)
├── backend/                 # FastAPI 后端
│   ├── app/
│   │   ├── main.py              # FastAPI 入口
│   │   ├── api/                 # 路由（check / status / 各阶段结果 / 健康）
│   │   ├── core/
│   │   │   ├── config.py        # 配置与安全限制
│   │   │   ├── error_codes.py   # 脱敏错误码与文案
│   │   │   ├── github.py        # GitHub URL 校验与安全下载
│   │   │   └── safe_extract.py  # 安全解压（防穿越/拒链接/限大小）
│   │   ├── models/ services/    # 数据模型与任务流水线
│   │   └── ...
│   ├── tests/                   # pytest 安全与回归测试
│   └── Dockerfile(.production)
├── docker-compose.yml           # 开发模式
├── docker-compose.production.yml # 生产加固模式
├── .env.example / production.env.example
└── README.md
```

## 开发指南

```bash
# 前端：安装依赖
cd frontend
npm install

# 前端：单元测试（Node 内置测试运行器）
npm run test:unit

# 前端：端到端测试（先构建，再用生产服务器启动）
npm run build
npx playwright test

# 后端：运行测试
cd backend
pip install -r requirements.txt
pytest -v
```

提交前请确保：`npm run build` 通过、单元测试全绿、Playwright 端到端全绿、
后端 `pytest` 全绿。改动不得破坏 e2e 依赖的类名与 `data-testid`，也不得
修改后端核心逻辑、API、schema 或 CI。

## 安全设计

- 敏感信息仅在 VibeCheck 服务端隔离临时目录内处理，不发送第三方 LLM，不保存完整原文，任务结束后删除临时文件。
- 所有密钥检测测试使用无权限合成测试字符串，不使用任何真实有效密钥。
- 安全下载仅接受 github.com 标准地址，跳转白名单仅 github.com 与 codeload.github.com。
- 解压时拒绝路径穿越、符号链接、硬链接、设备文件、FIFO、Socket 及异常路径。
- 前端通过 CSP 限制脚本、样式、字体与图片来源；API 响应绝不写入 localStorage / sessionStorage / IndexedDB，错误消息一律脱敏。

## License

MIT
