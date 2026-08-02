"""High-confidence boundaries for the P0-12 basic-security dimension."""

from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor

import pytest

from app.scanner.base import BASIC_SECURITY_DIMENSION
from app.scanner.sensitive import scan_directory
from app.services.scan_result_service import serialize_scan_result


def _write_repo(tmp_path, files: dict[str, str]) -> None:
    for relative_path, content in files.items():
        path = tmp_path / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")


def _findings(tmp_path):
    return [
        finding for finding in scan_directory(tmp_path).findings
        if finding.dimension == BASIC_SECURITY_DIMENSION
    ]


def _rule_ids(tmp_path):
    return [finding.rule_id for finding in _findings(tmp_path)]


@pytest.mark.parametrize(
    ("path", "content"),
    (
        ("app.py", '@app.get("/items")\ndef items(): return []\n'),
        ("server.js", 'app.get("/items", handler);\n'),
        ("Api.java", '@GetMapping("/items")\nObject items() { return null; }\n'),
        ("Items.cs", '[HttpGet("/items")]\npublic object Items() => null;\n'),
        ("main.go", 'r.GET("/items", handler)\n'),
        ("routes.rb", 'get "/items" => "items#index"\n'),
        ("routes.php", 'Route::get("/items", handler);\n'),
        ("app/api/items/route.ts", 'export async function GET(request: Request) { return Response.json([]); }\n'),
        ("urls.py", 'path("items/", views.items)\n'),
    ),
)
def test_api_routes_without_controls_report_auth_and_rate_limit(tmp_path, path, content):
    _write_repo(tmp_path, {path: content})
    ids = _rule_ids(tmp_path)
    assert "B001_API_AUTHENTICATION" in ids
    assert "B003_RATE_LIMITING" in ids


@pytest.mark.parametrize(
    ("path", "content"),
    (
        ("app.py", '@api_router.get("/items")\ndef items(): return []\n'),
        ("routes.py", '@bp.route("/items")\ndef items(): return []\n'),
        ("server.js", 'server.get("/items", handler);\n'),
    ),
)
def test_custom_route_aliases_activate_repository_checks(tmp_path, path, content):
    _write_repo(tmp_path, {path: content})
    ids = _rule_ids(tmp_path)
    assert "B001_API_AUTHENTICATION" in ids
    assert "B003_RATE_LIMITING" in ids


def test_non_route_getter_with_path_like_key_is_not_an_api_route(tmp_path):
    _write_repo(tmp_path, {"cache.js": 'cache.get("/items");\n'})
    ids = _rule_ids(tmp_path)
    assert "B001_API_AUTHENTICATION" not in ids
    assert "B003_RATE_LIMITING" not in ids


def test_health_and_documentation_routes_do_not_activate_repository_checks(tmp_path):
    _write_repo(tmp_path, {
        "app.py": (
            '@app.get("/health")\ndef health(): return {"status": "ok"}\n'
            '@app.get("/ready")\ndef ready(): return {"status": "ok"}\n'
        ),
    })
    ids = _rule_ids(tmp_path)
    assert "B001_API_AUTHENTICATION" not in ids
    assert "B003_RATE_LIMITING" not in ids


def test_authentication_evidence_suppresses_only_auth_finding(tmp_path):
    _write_repo(tmp_path, {
        "app.py": (
            "from fastapi.security import HTTPBearer\n"
            'security = HTTPBearer()\n@app.get("/items")\ndef items(): return []\n'
        ),
    })
    ids = _rule_ids(tmp_path)
    assert "B001_API_AUTHENTICATION" not in ids
    assert "B003_RATE_LIMITING" in ids


def test_unused_security_dependencies_do_not_suppress_findings(tmp_path):
    _write_repo(tmp_path, {
        "package.json": (
            '{"dependencies":{"passport":"1.0.0","zod":"1.0.0",'
            '"express-rate-limit":"1.0.0"}}'
        ),
        "server.js": (
            'app.post("/items", handler);\n'
            'const name = req.body.name;\n'
        ),
    })
    ids = _rule_ids(tmp_path)
    assert "B001_API_AUTHENTICATION" in ids
    assert "B002_INPUT_VALIDATION" in ids
    assert "B003_RATE_LIMITING" in ids


def test_generic_current_user_name_is_not_authentication_evidence(tmp_path):
    _write_repo(tmp_path, {
        "app.py": (
            "current_user = None\n"
            '@app.get("/items")\n'
            "def items(): return []\n"
        ),
    })
    assert "B001_API_AUTHENTICATION" in _rule_ids(tmp_path)


@pytest.mark.parametrize(
    "raw_input",
    (
        "const value = req.body.name;",
        "value = request.get_json()",
        "value = request.args['name']",
        "value = request.getParameter(\"name\");",
        "value := r.FormValue(\"name\")",
        "$value = $_POST['name'];",
        "value = params[:name]",
        "var value = Request.Query[\"name\"];",
    ),
)
def test_raw_request_input_without_validation_is_reported(tmp_path, raw_input):
    _write_repo(tmp_path, {
        "server.ts": f'app.post("/items", handler);\n{raw_input}\n',
    })
    assert "B002_INPUT_VALIDATION" in _rule_ids(tmp_path)


def test_validation_evidence_suppresses_raw_input_finding(tmp_path):
    _write_repo(tmp_path, {
        "server.ts": (
            'import { z } from "zod";\n'
            'app.post("/items", handler);\n'
            "const body = schema.parse(req.body);\n"
        ),
    })
    assert "B002_INPUT_VALIDATION" not in _rule_ids(tmp_path)


def test_rate_limit_evidence_suppresses_rate_finding(tmp_path):
    _write_repo(tmp_path, {
        "server.js": (
            'const rateLimit = require("express-rate-limit");\n'
            'app.use(rateLimit({ windowMs: 60_000, limit: 100 }));\n'
            'app.get("/items", handler);\n'
        ),
    })
    assert "B003_RATE_LIMITING" not in _rule_ids(tmp_path)


def test_rate_limit_name_inside_a_string_is_not_control_evidence(tmp_path):
    _write_repo(tmp_path, {
        "server.js": (
            'app.get("/items", handler);\n'
            'const example = \'require("express-rate-limit")\';\n'
        ),
    })
    assert "B003_RATE_LIMITING" in _rule_ids(tmp_path)


def test_request_input_inside_comments_and_strings_is_not_reported(tmp_path):
    _write_repo(tmp_path, {
        "server.js": (
            'app.post("/items", handler);\r\n'
            '// const value = req.body.name;\r\n'
            'const example = "request.get_json()";\r\n'
        ),
    })
    assert "B002_INPUT_VALIDATION" not in _rule_ids(tmp_path)


def test_library_without_api_routes_has_no_missing_control_findings(tmp_path):
    _write_repo(tmp_path, {
        "lib.py": "def add(left, right): return left + right\n",
    })
    ids = _rule_ids(tmp_path)
    assert "B001_API_AUTHENTICATION" not in ids
    assert "B002_INPUT_VALIDATION" not in ids
    assert "B003_RATE_LIMITING" not in ids


@pytest.mark.parametrize(
    ("path", "content"),
    (
        ("app.py", 'allow_origins=["*"]\n'),
        ("server.js", 'response.setHeader("Access-Control-Allow-Origin", "*");\n'),
        ("config.cs", "policy.AllowAnyOrigin();\n"),
        ("settings.py", "CORS_ALLOW_ALL_ORIGINS = True\n"),
        ("Controller.java", '@CrossOrigin(origins = "*")\nclass Controller {}\n'),
        ("application.properties", "allowed-origins=*\n"),
    ),
)
def test_explicit_wildcard_cors_is_reported(tmp_path, path, content):
    _write_repo(tmp_path, {path: content})
    findings = [
        finding for finding in _findings(tmp_path)
        if finding.rule_id == "B004_PERMISSIVE_CORS"
    ]
    assert len(findings) == 1
    assert findings[0].file_path == path
    assert findings[0].severity.value == "high"


@pytest.mark.parametrize(
    ("path", "content"),
    (
        ("server.js", 'const cors = require("cors");\napp.use(cors());\n'),
        ("app.py", "from flask_cors import CORS\nCORS(app)\n"),
    ),
)
def test_known_bare_cors_defaults_are_reported(tmp_path, path, content):
    _write_repo(tmp_path, {path: content})
    assert "B004_PERMISSIVE_CORS" in _rule_ids(tmp_path)


def test_node_wildcard_origin_object_is_reported(tmp_path):
    _write_repo(tmp_path, {
        "server.js": (
            'const cors = require("cors");\n'
            'app.use(cors({ origin: "*" }));\n'
        ),
    })
    assert "B004_PERMISSIVE_CORS" in _rule_ids(tmp_path)


def test_restricted_cors_and_unrelated_strings_are_not_reported(tmp_path):
    _write_repo(tmp_path, {
        "server.js": (
            'const cors = require("cors");\n'
            'app.use(cors({ origin: "https://app.example.com" }));\n'
            'const documentation = "Access-Control-Allow-Origin: *";\n'
        ),
        "tests/config.py": 'allow_origins=["*"]\n',
    })
    assert "B004_PERMISSIVE_CORS" not in _rule_ids(tmp_path)


def test_cors_call_inside_a_string_is_not_reported(tmp_path):
    _write_repo(tmp_path, {
        "server.js": (
            'const cors = require("cors");\n'
            'const example = "app.use(cors())";\n'
        ),
    })
    assert "B004_PERMISSIVE_CORS" not in _rule_ids(tmp_path)


def test_cors_configuration_inside_strings_is_not_reported(tmp_path):
    _write_repo(tmp_path, {
        "app.py": 'docs = \'allow_origins=["*"]\'\n',
        "server.js": (
            'const cors = require("cors");\n'
            'const example = \'origin: "*"\';\n'
        ),
    })
    assert "B004_PERMISSIVE_CORS" not in _rule_ids(tmp_path)


@pytest.mark.parametrize(
    ("path", "line"),
    (
        ("app.py", 'cursor.execute(f"SELECT * FROM users WHERE id={request.args[\'id\']}")'),
        ("server.js", 'db.query(`SELECT * FROM users WHERE id=${req.query.id}`);'),
        ("Api.java", 'db.query("SELECT * FROM users WHERE id=" + request.getParameter("id"));'),
        ("Api.cs", 'db.Query($"SELECT * FROM users WHERE id={Request.Query[\"id\"]}");'),
        ("app.php", '$db->query("SELECT * FROM users WHERE id={$_GET[\'id\']}");'),
        ("app.rb", 'db.execute("SELECT * FROM users WHERE id=#{params[:id]}")'),
        ("main.go", 'db.Query(fmt.Sprintf("SELECT * FROM users WHERE id=%s", r.FormValue("id")))'),
    ),
)
def test_request_data_interpolated_into_sql_is_reported(tmp_path, path, line):
    _write_repo(tmp_path, {path: line + "\n"})
    findings = [
        finding for finding in _findings(tmp_path)
        if finding.rule_id == "B005_SQL_INJECTION"
    ]
    assert len(findings) == 1
    assert findings[0].file_path == path
    assert findings[0].line_start == 1
    assert findings[0].severity.value == "high"


def test_parameterized_sql_orm_comments_strings_and_tests_are_not_reported(tmp_path):
    _write_repo(tmp_path, {
        "app.py": (
            'cursor.execute("SELECT a+b FROM users WHERE id = ?", (request.args["id"],))\n'
            'user = User.query.filter_by(id=request.args["id"]).first()\n'
            '# cursor.execute(f"DELETE FROM users WHERE id={request.args[\'id\']}")\n'
            'text = "db.query(`SELECT * FROM users WHERE id=${req.query.id}`)"\n'
        ),
        "tests/app.py": 'cursor.execute(f"DELETE FROM users WHERE id={request.args[\'id\']}")\n',
    })
    assert "B005_SQL_INJECTION" not in _rule_ids(tmp_path)


@pytest.mark.parametrize(
    "suffix",
    (
        'label = f"{name}"',
        'label = "{}".format(name)',
        "total = left + right",
    ),
)
def test_unrelated_dynamic_expression_does_not_taint_parameterized_sql(
    tmp_path, suffix
):
    _write_repo(tmp_path, {
        "app.py": (
            'cursor.execute("SELECT * FROM users WHERE id = ?", '
            f'(request.args["id"],)); {suffix}\n'
        ),
    })
    assert "B005_SQL_INJECTION" not in _rule_ids(tmp_path)


def test_findings_are_deterministic_non_blocking_and_desensitized(tmp_path):
    token = "ghp_" + "aB1cD2eF3gH4iJ5kL6mN7oP8qR9sT0uV1wX2"
    _write_repo(tmp_path, {
        f"src/{token}.py": (
            '@app.get("/items")\n'
            'cursor.execute(f"SELECT * FROM users WHERE id={request.args[\'id\']}")\n'
        ),
    })
    first = scan_directory(tmp_path)
    second = scan_directory(tmp_path)
    assert first == second
    findings = [
        finding for finding in first.findings
        if finding.dimension == BASIC_SECURITY_DIMENSION
    ]
    assert findings
    assert all(not finding.is_blocking for finding in findings)
    serialized = json.dumps(serialize_scan_result(first))
    assert token not in serialized


def test_per_file_sql_and_cors_limits_are_enforced(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "app.scanner.basic_security_rules.settings.scan_max_findings_per_rule_per_file",
        1,
    )
    _write_repo(tmp_path, {
        "app.py": (
            'allow_origins=["*"]\nallow_origins=("*",)\n'
            'cursor.execute(f"SELECT * FROM a WHERE id={request.args[\'id\']}")\n'
            'cursor.execute(f"DELETE FROM b WHERE id={request.args[\'id\']}")\n'
        ),
    })
    findings = _findings(tmp_path)
    assert sum(f.rule_id == "B004_PERMISSIVE_CORS" for f in findings) == 1
    assert sum(f.rule_id == "B005_SQL_INJECTION" for f in findings) == 1


def test_probe_state_is_isolated_between_concurrent_scans(tmp_path):
    protected = tmp_path / "protected"
    unprotected = tmp_path / "unprotected"
    protected.mkdir()
    unprotected.mkdir()
    _write_repo(protected, {
        "app.py": (
            "from fastapi.security import HTTPBearer\n"
            "from slowapi import Limiter\n"
            "limiter = Limiter(key_func=get_remote_address)\n"
            '@app.get("/items")\ndef items(): return []\n'
        ),
    })
    _write_repo(unprotected, {
        "app.py": '@app.get("/items")\ndef items(): return []\n',
    })

    with ThreadPoolExecutor(max_workers=2) as executor:
        protected_future = executor.submit(scan_directory, protected)
        unprotected_future = executor.submit(scan_directory, unprotected)
    protected_ids = {
        finding.rule_id for finding in protected_future.result().findings
        if finding.dimension == BASIC_SECURITY_DIMENSION
    }
    unprotected_ids = {
        finding.rule_id for finding in unprotected_future.result().findings
        if finding.dimension == BASIC_SECURITY_DIMENSION
    }
    assert "B001_API_AUTHENTICATION" not in protected_ids
    assert "B003_RATE_LIMITING" not in protected_ids
    assert "B001_API_AUTHENTICATION" in unprotected_ids
    assert "B003_RATE_LIMITING" in unprotected_ids
