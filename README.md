# VibeCheck

项目上线体检工具 — 面向 Vibe Coding 与 AI 编程初学者。

用户提交公开 GitHub 仓库地址，系统读取代码与文档，从五个维度检查项目是否适合正式上线，输出评分、风险清单与可复制的修复指令。

## 快速启动

```bash
# 1. 复制环境变量配置
cp .env.example .env

# 2. 一键启动前后端
docker compose up --build

# 3. 访问
# 前端: http://localhost:3000
# 后端 API: http://localhost:8000/api/health
```

## 项目结构

```
vibecheck/
├── frontend/          # Next.js 前端
├── backend/           # FastAPI 后端
│   ├── app/
│   │   ├── main.py          # FastAPI 入口
│   │   ├── core/
│   │   │   ├── config.py    # 配置与安全限制
│   │   │   ├── github.py    # GitHub URL 校验与安全下载
│   │   │   └── safe_extract.py  # 安全解压（防穿越/拒链接/限大小）
│   │   └── ...
│   └── tests/               # 安全测试
├── docker-compose.yml
└── .env.example
```

## 安全设计

- 敏感信息仅在 VibeCheck 服务端隔离临时目录内处理，不发送第三方 LLM，不保存完整原文，任务结束后删除临时文件。
- 所有密钥检测测试使用无权限合成测试字符串，不使用任何真实有效密钥。
- 安全下载仅接受 github.com 标准地址，跳转白名单仅 github.com 与 codeload.github.com。
- 解压时拒绝路径穿越、符号链接、硬链接、设备文件、FIFO、Socket 及异常路径。

## 开发

```bash
# 运行后端测试
cd backend
pip install -r requirements.txt
pytest -v
```

## 生产模式

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

生产响应会发送 HSTS 头，但浏览器只会在服务经过 HTTPS 反向代理访问时执行
HSTS；本机 HTTP 验收仅用于确认响应头存在，不能替代真实 TLS 部署验证。
