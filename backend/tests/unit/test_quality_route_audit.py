"""Deterministic FastAPI route audit tests (no database required)."""

from __future__ import annotations

from pathlib import Path

from app.quality.analyzers.route_audit import analyze_backend_routes
from app.quality.models import (
    DIMENSION_BACKEND_ROUTES,
    REASON_NO_BACKEND,
    REASON_RUNTIME_UNVERIFIED,
    REASON_UNSUPPORTED_FRAMEWORK,
    STATUS_NOT_APPLICABLE,
    STATUS_PARTIAL,
)
from app.quality.repository_index import RepositoryIndex

ZERO_FINDINGS_MESSAGE = "在已覆盖输入范围内未发现问题"


def _write_repo(root: Path, files: dict[str, str]) -> RepositoryIndex:
    for rel, content in files.items():
        target = root / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
    return RepositoryIndex(root)


def _routes(block) -> list[dict]:
    return block.to_dict()["details"]["routes"]


def _route(block, path: str) -> dict:
    matches = [row for row in _routes(block) if row["path"] == path]
    assert matches, f"route {path} not enumerated: {[r['path'] for r in _routes(block)]}"
    return matches[0]


def test_nested_prefix_add_api_route_and_conditional_registration(tmp_path):
    index = _write_repo(
        tmp_path,
        {
            "backend/app/api/users.py": (
                "from fastapi import APIRouter\n"
                "router = APIRouter(prefix='/users')\n"
                "\n"
                "@router.get('/{user_id}')\n"
                "def read_user(user_id: str):\n"
                "    return {'id': user_id}\n"
            ),
            "backend/app/api/admin.py": (
                "from fastapi import APIRouter\n"
                "router = APIRouter(prefix='/admin')\n"
                "\n"
                "@router.get('/debug')\n"
                "def debug_state():\n"
                "    return {}\n"
            ),
            "backend/app/main.py": (
                "import os\n"
                "from fastapi import FastAPI\n"
                "from app.api import users, admin\n"
                "\n"
                "app = FastAPI()\n"
                "app.include_router(users.router)\n"
                "if os.environ.get('ENABLE_ADMIN'):\n"
                "    app.include_router(admin.router, prefix='/internal')\n"
                "\n"
                "def ping():\n"
                "    return {'ok': True}\n"
                "\n"
                "app.add_api_route('/ping', ping, methods=['GET'])\n"
            ),
            "README.md": "# Demo\n\nGET /users/{user_id}\nGET /ping\n",
        },
    )

    block = analyze_backend_routes(index)
    data = block.to_dict()

    assert data["status"] == STATUS_PARTIAL
    assert data["reason_code"] == REASON_RUNTIME_UNVERIFIED

    assert _route(block, "/users/{user_id}")["verdict"] == "public_contract"
    assert _route(block, "/ping")["verdict"] == "public_contract"

    conditional = _route(block, "/internal/admin/debug")
    assert conditional["conditional"] is True
    assert conditional["reachable"] is True
    assert conditional["verdict"] == "manual_confirm"


def test_conditional_registration_is_reported_as_manual_confirmation(tmp_path):
    index = _write_repo(
        tmp_path,
        {
            "backend/app/main.py": (
                "import os\n"
                "from fastapi import FastAPI\n"
                "\n"
                "app = FastAPI()\n"
                "\n"
                "if os.environ.get('ENABLE_DEBUG'):\n"
                "\n"
                "    @app.get('/internal/debug')\n"
                "    def debug():\n"
                "        return {}\n"
            ),
            "README.md": "# Demo\n",
        },
    )
    block = analyze_backend_routes(index)
    data = block.to_dict()

    item_titles = [item["title"] for item in data["items"]]
    assert any("/internal/debug" in title for title in item_titles)
    manual = [
        item for item in data["items"] if item["manual_decision_required"]
    ]
    assert manual, "conditional/risk routes must require manual confirmation"
    for item in manual:
        assert item["limitation"]


def test_zero_findings_uses_explicit_statement_not_empty_array(tmp_path):
    index = _write_repo(
        tmp_path,
        {
            "backend/app/main.py": (
                "from fastapi import FastAPI\n"
                "\n"
                "app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)\n"
                "\n"
                "@app.get('/items')\n"
                "def list_items():\n"
                "    return []\n"
            ),
            "README.md": "# Demo service\n\nGET /items\n",
        },
    )
    block = analyze_backend_routes(index)
    data = block.to_dict()

    assert data["status"] == "completed"
    assert data["items"] == []
    assert ZERO_FINDINGS_MESSAGE in data["conclusion"]["headline"]
    assert data["details"]["routes"]


def test_no_backend_is_explicitly_not_applicable(tmp_path):
    index = _write_repo(tmp_path, {"README.md": "# Library\n"})
    block = analyze_backend_routes(index)
    data = block.to_dict()

    assert data["dimension"] == DIMENSION_BACKEND_ROUTES
    assert data["status"] == STATUS_NOT_APPLICABLE
    assert data["reason_code"] == REASON_NO_BACKEND
    assert data["reason_message"]
    assert data["items"] == []


def test_frontend_only_repo_is_not_applicable_not_unsupported(tmp_path):
    index = _write_repo(
        tmp_path,
        {
            "frontend/app/page.tsx": "export default function Page() { return null }\n",
            "frontend/components/Button.tsx": "export const Button = () => null;\n",
            "README.md": "# Frontend\n",
        },
    )
    data = analyze_backend_routes(index).to_dict()
    assert data["status"] == STATUS_NOT_APPLICABLE
    assert data["reason_code"] == REASON_NO_BACKEND


def test_non_python_backend_is_partial_with_unsupported_reason(tmp_path):
    index = _write_repo(
        tmp_path,
        {
            "backend/main.go": "package main\n\nfunc main() {}\n",
            "README.md": "# Go service\n",
        },
    )
    data = analyze_backend_routes(index).to_dict()

    assert data["status"] == STATUS_PARTIAL
    assert data["reason_code"] == REASON_UNSUPPORTED_FRAMEWORK
    assert data["reason_message"]
    assert data["items"] == []


def test_this_repository_is_the_golden_sample():
    repo_root = Path(__file__).resolve().parents[3]
    index = RepositoryIndex(repo_root)
    block = analyze_backend_routes(index)
    data = block.to_dict()

    # Enumerated inventory exists and never collapses to an empty array.
    assert data["details"]["routes"]
    assert data["conclusion"]["headline"]

    cancel = _route(block, "/api/check/{task_id}/cancel")
    assert cancel["verdict"] != "unused_candidate", (
        "cancel route is referenced by docs/tests and must not be deletable"
    )

    ops_titles = [
        item["title"]
        for item in data["items"]
        if item["manual_decision_required"]
    ]
    for ops_path in ("/metrics", "/api/health", "/api/ready"):
        assert any(ops_path in title for title in ops_titles), (
            f"{ops_path} must land in manual confirmation"
        )


def test_non_literal_include_router_prefix_is_unresolved(tmp_path):
    index = _write_repo(
        tmp_path,
        {
            "backend/app/api/users.py": (
                "from fastapi import APIRouter\n"
                "router = APIRouter(prefix='/users')\n"
                "@router.get('/list')\n"
                "def list_users():\n"
                "    return []\n"
            ),
            "backend/app/main.py": (
                "import os\n"
                "from fastapi import FastAPI\n"
                "from app.api import users\n"
                "app = FastAPI()\n"
                "app.include_router(users.router, prefix=os.environ['API_PREFIX'])\n"
            ),
        },
    )
    block = analyze_backend_routes(index)
    rows = [
        row
        for row in _routes(block)
        if row["registration"]["file_path"].endswith("api/users.py")
    ]
    assert len(rows) == 1
    assert rows[0]["path"] == "<unresolved>"
    manual = [
        item
        for item in block.to_dict()["items"]
        if item["category"] == "unresolved_route"
    ]
    assert manual and all(item["manual_decision_required"] for item in manual)


def test_router_and_include_router_dependencies_count_as_auth_guards(tmp_path):
    index = _write_repo(
        tmp_path,
        {
            "backend/app/api/users.py": (
                "from fastapi import APIRouter, Depends\n"
                "def require_auth():\n"
                "    return None\n"
                "router = APIRouter(prefix='/users', dependencies=[Depends(require_auth)])\n"
                "@router.get('/list')\n"
                "def list_users():\n"
                "    return []\n"
            ),
            "backend/app/api/orders.py": (
                "from fastapi import APIRouter\n"
                "router = APIRouter(prefix='/orders')\n"
                "@router.get('/list')\n"
                "def list_orders():\n"
                "    return []\n"
            ),
            "backend/app/main.py": (
                "from fastapi import Depends, FastAPI\n"
                "from app.api import users, orders\n"
                "def require_auth():\n"
                "    return None\n"
                "app = FastAPI()\n"
                "app.include_router(users.router)\n"
                "app.include_router(orders.router, dependencies=[Depends(require_auth)])\n"
            ),
        },
    )
    block = analyze_backend_routes(index)
    assert _route(block, "/users/list")["auth_guard"] == "require_auth"
    assert _route(block, "/orders/list")["auth_guard"] == "require_auth"


def test_route_item_ids_are_unique_across_files(tmp_path):
    body = (
        "from fastapi import APIRouter\n"
        "router = APIRouter()\n"
        "@router.get('/same')\n"
        "def same():\n"
        "    return {}\n"
    )
    index = _write_repo(
        tmp_path,
        {"backend/app/api/a.py": body, "backend/app/api/b.py": body},
    )
    block = analyze_backend_routes(index)
    item_ids = [item["item_id"] for item in block.to_dict()["items"]]
    assert item_ids
    assert len(item_ids) == len(set(item_ids))
