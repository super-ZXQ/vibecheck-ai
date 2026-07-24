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
