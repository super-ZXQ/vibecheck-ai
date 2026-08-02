"""High-precision tests for the incomplete-content scan dimension."""

from __future__ import annotations

import json

from app.scanner.base import INCOMPLETE_CONTENT_DIMENSION
from app.scanner.sensitive import scan_directory
from app.services.scan_result_service import serialize_scan_result


def _scan(tmp_path, relative_path: str, content: str):
    path = tmp_path / relative_path
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return scan_directory(tmp_path).findings


def _rule_ids(findings):
    return [finding.rule_id for finding in findings]


def test_todo_markers_are_detected_only_in_source_comments(tmp_path):
    findings = _scan(
        tmp_path,
        "src/app.ts",
        "// todo: finish\n/* FiXmE next */\nconst text = 'TODO is data';\n",
    )
    assert _rule_ids(findings) == ["I001_TODO_COMMENT", "I001_TODO_COMMENT"]
    assert all(f.dimension == INCOMPLETE_CONTENT_DIMENSION for f in findings)
    assert all(not f.is_blocking for f in findings)


def test_multiline_string_literals_do_not_produce_findings(tmp_path):
    _scan(
        tmp_path,
        "src/help.py",
        'HELP = """\n# TODO shown in help\nbreakpoint()\n'
        'raise RuntimeError("not implemented")\n'
        + "\n".join("print(value)" for _ in range(6))
        + '\n"""\n',
    )
    findings = _scan(
        tmp_path,
        "src/help.ts",
        "const help = `\n// FIXME shown to users\ndebugger;\n"
        + "\n".join("console.log(value);" for _ in range(6))
        + "\n`;\n",
    )
    assert not any(
        finding.dimension == INCOMPLETE_CONTENT_DIMENSION
        for finding in findings
    )


def test_unimplemented_constructs_across_languages(tmp_path):
    _scan(tmp_path, "src/service.py", "def run():\n    raise NotImplementedError()\n")
    _scan(tmp_path, "src/service.rs", "todo!();\nlet value = unimplemented!();\n")
    findings = _scan(
        tmp_path,
        "src/service.ts",
        'throw new Error("Not implemented");\n',
    )
    result = scan_directory(tmp_path)
    assert sum(f.rule_id == "I002_UNIMPLEMENTED_CODE" for f in result.findings) == 4
    assert sum(
        f.rule_id == "I002_UNIMPLEMENTED_CODE" and f.file_path == "src/service.ts"
        for f in findings
    ) == 1


def test_explicit_not_implemented_exceptions_are_detected(tmp_path):
    _scan(
        tmp_path,
        "src/variants.py",
        'raise RuntimeError("NOT IMPLEMENTED")\n',
    )
    findings = _scan(
        tmp_path,
        "src/variants.cs",
        "throw new NotImplementedException();\n",
    )
    assert _rule_ids(findings).count("I002_UNIMPLEMENTED_CODE") == 2


def test_abstract_not_implemented_and_string_literals_are_not_reported(tmp_path):
    findings = _scan(
        tmp_path,
        "src/base.py",
        "from abc import abstractmethod\n"
        "@abstractmethod\n"
        "def run(self):\n"
        "    raise NotImplementedError\n"
        "text = 'raise NotImplementedError'\n",
    )
    assert "I002_UNIMPLEMENTED_CODE" not in _rule_ids(findings)


def test_explicit_abstract_base_classes_are_not_reported(tmp_path):
    findings = _scan(
        tmp_path,
        "src/base.py",
        "from abc import ABC, ABCMeta\n"
        "class Base(ABC):\n"
        "    def run(self):\n"
        "        raise NotImplementedError\n"
        "class MetaBase(metaclass=ABCMeta):\n"
        "    def save(self):\n"
        "        raise NotImplementedError\n",
    )
    assert "I002_UNIMPLEMENTED_CODE" not in _rule_ids(findings)


def test_placeholder_return_requires_adjacent_explicit_comment(tmp_path):
    findings = _scan(
        tmp_path,
        "src/service.py",
        "def valid():\n    return []\n"
        "def pending():\n    # placeholder until API is ready\n    return None\n",
    )
    assert _rule_ids(findings).count("I003_PLACEHOLDER_RETURN") == 1


def test_debug_breakpoints_are_detected_but_comments_are_not(tmp_path):
    findings = _scan(
        tmp_path,
        "src/debug.py",
        "# breakpoint()\ntext = 'pdb.set_trace()'\nbreakpoint()\npdb.set_trace()\n",
    )
    assert _rule_ids(findings).count("I004_DEBUG_BREAKPOINT") == 2

    js_findings = _scan(tmp_path, "src/debug.js", 'if (ready) debugger;\n"debugger";\n')
    assert sum(
        finding.rule_id == "I004_DEBUG_BREAKPOINT" and finding.file_path == "src/debug.js"
        for finding in js_findings
    ) == 1


def test_excessive_debug_output_threshold_is_six(tmp_path):
    five = _scan(tmp_path, "src/five.js", "\n".join("console.log(x);" for _ in range(5)))
    six = _scan(tmp_path, "src/six.js", "\n".join("console.log(x);" for _ in range(6)))
    assert "I005_EXCESSIVE_DEBUG_OUTPUT" not in _rule_ids(five)
    excessive = [f for f in six if f.rule_id == "I005_EXCESSIVE_DEBUG_OUTPUT"]
    assert len(excessive) == 1
    assert excessive[0].finding_type.value == "file"
    assert excessive[0].snippet_masked == "<debug-output-count:6>"


def test_java_system_out_println_threshold_is_six(tmp_path):
    five = _scan(
        tmp_path,
        "src/Five.java",
        "\n".join('System.out.println("debug");' for _ in range(5)),
    )
    six = _scan(
        tmp_path,
        "src/Six.java",
        "\n".join('System.out.println("debug");' for _ in range(6)),
    )
    assert not any(
        finding.rule_id == "I005_EXCESSIVE_DEBUG_OUTPUT"
        and finding.file_path == "src/Five.java"
        for finding in five
    )
    assert sum(
        finding.rule_id == "I005_EXCESSIVE_DEBUG_OUTPUT"
        and finding.file_path == "src/Six.java"
        for finding in six
    ) == 1


def test_non_source_and_non_production_paths_are_excluded(tmp_path):
    paths = (
        "tests/app.py", "spec/app.ts", "fixtures/sample.go", "mocks/client.js",
        "docs/example.py", "README.md", "package-lock.json", "src/app.test.ts",
        "src/service_spec.py", "test_root.py",
    )
    for path in paths:
        _scan(tmp_path, path, "# TODO\nbreakpoint()\n")
    assert not any(f.dimension == INCOMPLETE_CONTENT_DIMENSION
                   for f in scan_directory(tmp_path).findings)


def test_bare_low_precision_keywords_are_not_rules(tmp_path):
    findings = _scan(
        tmp_path,
        "src/words.py",
        "deprecated = True\nmock = object()\ndummy = 1\nurl = 'https://example.com'\n",
    )
    assert not any(f.dimension == INCOMPLETE_CONTENT_DIMENSION for f in findings)


def test_rule_limit_sorting_and_repeated_runs_are_deterministic(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "app.scanner.incomplete_rules.settings.scan_max_findings_per_rule_per_file", 2
    )
    content = "# TODO first\n# FIXME second\n# HACK third\n"
    first = _scan(tmp_path, "src/app.py", content)
    second = scan_directory(tmp_path).findings
    todo_lines = [f.line_start for f in first if f.rule_id == "I001_TODO_COMMENT"]
    assert todo_lines == [1, 2]
    assert first == second


def test_repo_derived_text_remains_masked_at_result_boundary(tmp_path, caplog):
    token = "ghp_" + "aB1cD2eF3gH4iJ5kL6mN7oP8qR9sT0uV1wX2"
    (tmp_path / "app.py").write_text(f"# TODO remove {token}\n", encoding="utf-8")
    result = scan_directory(tmp_path)
    serialized = json.dumps(serialize_scan_result(result))
    assert token not in serialized
    assert token not in repr(result)
    assert token not in caplog.text
