"""Locust load scenarios for VibeCheck (local base URL only).

IMPORTANT:
- Point --host at a LOCAL VibeCheck instance.
- Do NOT use this script to hammer public GitHub APIs.
- For CI/experiments prefer synthetic/mocked backends (see tests/ and docs/).

Usage:
  locust -f load/locustfile.py --host http://127.0.0.1:8000
"""

from __future__ import annotations

import random

from locust import HttpUser, between, task

# Synthetic GitHub-shaped URLs. Local mock/stub backends should accept these
# without calling github.com. Real GitHub must not be load-tested here.
FAKE_REPOS = [
    f"https://github.com/loadtest/synth-{i}" for i in range(1, 21)
]


class VibeCheckUser(HttpUser):
    wait_time = between(0.05, 0.3)

    @task(3)
    def submit_check(self) -> None:
        repo = random.choice(FAKE_REPOS)
        with self.client.post(
            "/api/check",
            json={"repo_url": repo},
            catch_response=True,
            name="POST /api/check",
        ) as resp:
            if resp.status_code == 429:
                resp.success()  # expected under load
            elif resp.status_code in (200, 202):
                resp.success()
            else:
                resp.failure(f"unexpected {resp.status_code}")

    @task(2)
    def health(self) -> None:
        self.client.get("/api/health", name="GET /api/health")

    @task(1)
    def ready(self) -> None:
        self.client.get("/api/ready", name="GET /api/ready")

    @task(1)
    def metrics(self) -> None:
        self.client.get("/metrics", name="GET /metrics")

    @task(1)
    def poll_recent(self) -> None:
        # Polling without a known id exercises 404 path safely.
        self.client.get(
            "/api/check/00000000-0000-0000-0000-000000000000",
            name="GET /api/check/{id}",
        )
