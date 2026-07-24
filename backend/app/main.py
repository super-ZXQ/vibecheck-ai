"""FastAPI application entry point.

P0 scaffold: health check + API routing placeholder.
Full check/report endpoints will be added in subsequent P0 tasks.
"""

from fastapi import FastAPI

app = FastAPI(
    title="VibeCheck",
    description="项目上线体检工具 — 面向 Vibe Coding 与 AI 编程初学者",
    version="0.1.0",
)


@app.get("/api/health")
async def health_check():
    return {"status": "ok", "version": "0.1.0"}
