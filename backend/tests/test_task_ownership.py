"""Task ownership: X-Submitter-Key scoping of admission, reads and cancel.

Finding #8: a task id was the only credential, so any visitor who learned one
could read another visitor's report and cancel their job — and because active
tasks coalesced per repository, a second visitor was *handed* the first one's
task id by design.

Ownership model under test:
- A submitter key is recorded only when the client sends one.
- Active-task coalescing is scoped to that key.
- Owned tasks answer 404 to every other key, including no key at all.
- Keyless tasks keep the old public behaviour (documented opt-out).
"""

import pytest
from fastapi.testclient import TestClient

from app.core.task_access import hash_submitter_key
from app.services import task_manager

A_KEY = "aaaaaaaabbbbbbbbccccccccdddddddd"
B_KEY = "11112222333344445555666677778888"

# (path suffix, status a properly authenticated read answers for a pending task)
TASK_ENDPOINTS = [
    ("", 200),
    ("/result", 409),
    ("/assessment", 409),
    ("/repair-plan", 409),
    ("/llm-analysis", 409),
]


def _row(task_id: str):
    import asyncio

    from app.db.models import TaskRow
    from app.db.session import get_session_factory

    async def _get():
        factory = get_session_factory()
        async with factory() as session:
            row = await session.get(TaskRow, task_id)
            return (
                None
                if row is None
                else (row.status, row.submitter_key, row.deduplication_key,
                      row.cancelled_at)
            )

    return asyncio.run(_get())


def _set_dedup_key(task_id: str, key: str) -> None:
    """Stamp a task with an arbitrary (e.g. legacy-shaped) coalesce key."""
    import asyncio

    from sqlalchemy import update

    from app.db.models import TaskRow
    from app.db.session import get_session_factory

    async def _apply():
        factory = get_session_factory()
        async with factory() as session:
            await session.execute(
                update(TaskRow).where(TaskRow.id == task_id).values(
                    deduplication_key=key
                )
            )
            await session.commit()

    asyncio.run(_apply())


def _legacy_key(repo_url: str) -> str:
    from app.core.scanner_version import SCANNER_VERSION
    from app.db.repositories.tasks import normalize_repo_url

    return f"{normalize_repo_url(repo_url)}|active|{SCANNER_VERSION}"


class TestSubmitterKeyOnCreate:
    def _submit(self, client, headers=None, repo="https://github.com/u/own"):
        from unittest.mock import patch

        with patch("app.api.check.trigger_queue_processing"):
            return client.post(
                "/api/check", json={"repo_url": repo}, headers=headers or {}
            )

    def test_key_recorded_as_digest(self, test_db):
        from app.main import app

        with TestClient(app) as client:
            resp = self._submit(
                client, {"X-Submitter-Key": A_KEY}
            )
            assert resp.status_code == 202
            task_id = resp.json()["task_id"]
        _status, stored_key, dedup_key, _ = _row(task_id)
        assert stored_key == hash_submitter_key(A_KEY)
        assert len(stored_key) == 64
        assert A_KEY not in stored_key
        assert A_KEY not in (dedup_key or "")

    def test_hash_is_stable_and_key_specific(self):
        first = hash_submitter_key(A_KEY)
        assert first == hash_submitter_key(A_KEY)
        assert first != hash_submitter_key(B_KEY)
        assert len(first) == 64
        assert set(first) <= set("0123456789abcdef")

    def test_missing_key_leaves_task_unowned(self, test_db):
        from app.main import app

        with TestClient(app) as client:
            resp = self._submit(client)
            assert resp.status_code == 202
            task_id = resp.json()["task_id"]
        assert _row(task_id)[1] is None

    def test_response_never_echoes_the_key(self, test_db):
        from app.main import app

        with TestClient(app) as client:
            resp = self._submit(client, {"X-Submitter-Key": A_KEY})
        assert A_KEY not in resp.text

    def test_malformed_key_is_rejected_not_ignored(self, test_db):
        from app.main import app

        with TestClient(app) as client:
            for bad in ("too-short", "has spaces and!! symbols here"):
                resp = self._submit(client, {"X-Submitter-Key": bad})
                assert resp.status_code == 400
                assert resp.json()["detail"]["error_code"] == "INVALID_SUBMITTER_KEY"


class TestAdmissionScoping:
    def test_same_key_coalesces(self, test_db):
        first, created_a = task_manager.admit_repo_task(
            "https://github.com/u/same", "u", "same", submitter_key=A_KEY
        )
        second, created_b = task_manager.admit_repo_task(
            "https://github.com/u/same", "u", "same", submitter_key=A_KEY
        )
        assert created_a is True and created_b is False
        assert second.id == first.id

    def test_different_keys_get_their_own_task(self, test_db):
        first, _ = task_manager.admit_repo_task(
            "https://github.com/u/two", "u", "two", submitter_key=A_KEY
        )
        second, created = task_manager.admit_repo_task(
            "https://github.com/u/two", "u", "two", submitter_key=B_KEY
        )
        assert created is True
        assert second.id != first.id
        # Distinct coalesce keys are what keeps the partial unique index clear.
        assert _row(first.id)[2] != _row(second.id)[2]

    def test_keyless_submitters_still_share(self, test_db):
        first, _ = task_manager.admit_repo_task(
            "https://github.com/u/public", "u", "public"
        )
        second, created = task_manager.admit_repo_task(
            "https://github.com/u/public", "u", "public"
        )
        assert created is False and second.id == first.id

    def test_owned_task_is_not_adopted_by_keyless_submit(self, test_db):
        first, _ = task_manager.admit_repo_task(
            "https://github.com/u/adopt", "u", "adopt", submitter_key=A_KEY
        )
        second, created = task_manager.admit_repo_task(
            "https://github.com/u/adopt", "u", "adopt"
        )
        assert created is True and second.id != first.id

    def test_keyed_submit_does_not_adopt_keyless_task(self, test_db):
        first, _ = task_manager.admit_repo_task(
            "https://github.com/u/adopt2", "u", "adopt2"
        )
        second, created = task_manager.admit_repo_task(
            "https://github.com/u/adopt2", "u", "adopt2", submitter_key=A_KEY
        )
        assert created is True and second.id != first.id

    def test_url_fallback_still_coalesces_for_the_same_owner(self, test_db):
        repo = "https://github.com/u/legacy"
        first, _ = task_manager.admit_repo_task(repo, "u", "legacy", submitter_key=A_KEY)
        _set_dedup_key(first.id, _legacy_key(repo))
        second, created = task_manager.admit_repo_task(
            repo, "u", "legacy", submitter_key=A_KEY
        )
        assert created is False and second.id == first.id

    def test_url_fallback_does_not_cross_owners(self, test_db):
        repo = "https://github.com/u/legacy2"
        first, _ = task_manager.admit_repo_task(repo, "u", "legacy2", submitter_key=A_KEY)
        # Key misses on lookup, so only the URL fallback can adopt this task.
        _set_dedup_key(first.id, _legacy_key(repo))
        second, created = task_manager.admit_repo_task(
            repo, "u", "legacy2", submitter_key=B_KEY
        )
        assert created is True and second.id != first.id

    def test_two_active_tasks_may_resolve_the_same_commit(self, test_db):
        """Different owners running one repository must not collide.

        uq_tasks_active_dedup only covers pending/running rows, so the key an
        active row carries must stay unique per owner — the commit-level key
        is shared across owners and can only be adopted at completion.
        """
        import asyncio

        repo = "https://github.com/u/collide"
        sha = "0123456789abcdef0123456789abcdef01234567"
        a, _ = task_manager.admit_repo_task(repo, "u", "collide", submitter_key=A_KEY)
        b, _ = task_manager.admit_repo_task(repo, "u", "collide", submitter_key=B_KEY)
        assert a.id != b.id

        for task_id in (a.id, b.id):
            asyncio.run(task_manager.set_resolved_commit_sha_async(task_id, sha))

        key_a, key_b = _row(a.id)[2], _row(b.id)[2]
        assert key_a != key_b
        assert sha not in key_a and sha not in key_b
        assert _row(a.id)[0] == "pending" and _row(b.id)[0] == "pending"

    def test_completed_tasks_share_one_commit_key_for_reuse(self, test_db):
        """Cross-owner cost control survives ownership scoping.

        B may reuse A's completed scan of the same public commit: the source is
        public and the copy lands in B's own task.
        """
        import asyncio

        from app.services.task_manager import mark_completed_async

        repo = "https://github.com/u/share"
        sha = "1111111111111111111111111111111111111111"
        a, _ = task_manager.admit_repo_task(repo, "u", "share", submitter_key=A_KEY)
        asyncio.run(task_manager.set_resolved_commit_sha_async(a.id, sha))
        asyncio.run(mark_completed_async(a.id, 10, 2048, "share"))

        found = asyncio.run(
            task_manager.find_completed_by_repo_sha_async(repo, sha)
        )
        assert found is not None and found.id == a.id

        # A second owner completing the same commit must not be blocked by the
        # first one's completed key, and both remain findable.
        b, _ = task_manager.admit_repo_task(repo, "u", "share", submitter_key=B_KEY)
        asyncio.run(task_manager.set_resolved_commit_sha_async(b.id, sha))
        asyncio.run(mark_completed_async(b.id, 10, 2048, "share"))
        assert asyncio.run(
            task_manager.find_completed_by_repo_sha_async(repo, sha)
        ).id in (a.id, b.id)


class TestReadAuthorization:
    @pytest.mark.parametrize("suffix,ok_status", TASK_ENDPOINTS)
    def test_wrong_key_answers_not_found(self, test_db, suffix, ok_status):
        from app.main import app

        task = task_manager.create_task(
            "https://github.com/u/read", "u", "read", submitter_key=A_KEY
        )
        with TestClient(app) as client:
            resp = client.get(
                f"/api/check/{task.id}{suffix}",
                headers={"X-Submitter-Key": B_KEY},
            )
            assert resp.status_code == 404
            assert resp.json()["detail"]["error_code"] == "TASK_NOT_FOUND"

    @pytest.mark.parametrize("suffix,ok_status", TASK_ENDPOINTS)
    def test_missing_key_answers_not_found_for_owned_task(
        self, test_db, suffix, ok_status
    ):
        from app.main import app

        task = task_manager.create_task(
            "https://github.com/u/nok", "u", "nok", submitter_key=A_KEY
        )
        with TestClient(app) as client:
            assert client.get(f"/api/check/{task.id}{suffix}").status_code == 404

    @pytest.mark.parametrize("suffix,ok_status", TASK_ENDPOINTS)
    def test_right_key_passes_the_gate(self, test_db, suffix, ok_status):
        from app.main import app

        task = task_manager.create_task(
            "https://github.com/u/ok", "u", "ok", submitter_key=A_KEY
        )
        with TestClient(app) as client:
            resp = client.get(
                f"/api/check/{task.id}{suffix}",
                headers={"X-Submitter-Key": A_KEY},
            )
            # The gate is passed: the endpoint reaches its own status logic.
            assert resp.status_code == ok_status

    @pytest.mark.parametrize("suffix,ok_status", TASK_ENDPOINTS)
    def test_unowned_task_keeps_public_access(self, test_db, suffix, ok_status):
        from app.main import app

        task = task_manager.create_task("https://github.com/u/free", "u", "free")
        with TestClient(app) as client:
            resp = client.get(f"/api/check/{task.id}{suffix}")
            assert resp.status_code == ok_status

    def test_wrong_key_is_indistinguishable_from_unknown_task(self, test_db):
        import uuid

        from app.main import app

        task = task_manager.create_task(
            "https://github.com/u/ind", "u", "ind", submitter_key=A_KEY
        )
        unknown = str(uuid.uuid4())
        with TestClient(app) as client:
            wrong_key = client.get(
                f"/api/check/{task.id}", headers={"X-Submitter-Key": B_KEY}
            )
            missing = client.get(
                f"/api/check/{unknown}", headers={"X-Submitter-Key": B_KEY}
            )
        assert wrong_key.status_code == missing.status_code == 404
        assert wrong_key.json() == missing.json()


class TestEndpointCoverage:
    """Every task-scoped route must speak the ownership header.

    Behavioural tests below pin the semantics of the routes that exist today;
    this one fails when a new `/api/check/{task_id}...` route is added without
    the header, which is the moment the control would silently stop covering
    the task list.
    """

    def test_all_task_routes_declare_the_header(self):
        import inspect

        from fastapi.routing import APIRoute

        from app.main import app

        def walk(routes):
            """Routers are included lazily, so descend past the wrappers."""
            for route in routes:
                inner = getattr(route, "original_router", None)
                if inner is not None:
                    yield from walk(inner.routes)
                elif isinstance(route, APIRoute):
                    yield route

        scoped = [route for route in walk(app.routes) if "{task_id}" in route.path]
        assert len(scoped) == 6, [route.path for route in scoped]
        unguarded = [
            f"{sorted(route.methods)} {route.path}"
            for route in scoped
            if "x_submitter_key" not in inspect.signature(route.endpoint).parameters
        ]
        assert unguarded == []


class TestCancelAuthorization:
    def test_wrong_key_cannot_cancel(self, test_db):
        from app.main import app

        task = task_manager.create_task(
            "https://github.com/u/cxl", "u", "cxl", submitter_key=A_KEY
        )
        with TestClient(app) as client:
            resp = client.post(
                f"/api/check/{task.id}/cancel",
                headers={"X-Submitter-Key": B_KEY},
            )
        assert resp.status_code == 404
        status, _, _, cancelled_at = _row(task.id)
        assert status == "pending" and cancelled_at is None

    def test_owner_can_cancel(self, test_db):
        from app.main import app

        task = task_manager.create_task(
            "https://github.com/u/cyo", "u", "cyo", submitter_key=A_KEY
        )
        with TestClient(app) as client:
            resp = client.post(
                f"/api/check/{task.id}/cancel",
                headers={"X-Submitter-Key": A_KEY},
            )
        assert resp.status_code == 200
        assert resp.json()["cancelled"] is True

    def test_unowned_task_cancel_is_unchanged(self, test_db):
        from app.main import app

        task = task_manager.create_task("https://github.com/u/cxx", "u", "cxx")
        with TestClient(app) as client:
            resp = client.post(f"/api/check/{task.id}/cancel")
        assert resp.status_code == 200
        assert resp.json()["cancelled"] is True
