"""LLM analysis service — generates plain-language explanations for non-blocking findings.

SECURITY:
- Reads ONLY from persisted scan_results (already desensitized by P0-5).
- Sends ONLY snippet_masked, file_path (POSIX relative), rule_id, and
  rule_name to the LLM. NEVER sends raw secrets, absolute paths,
  repo_url, or blocking findings (R001-R005).
- LLM failures are NON-BLOCKING: the task still completes with
  fallback templates.
- All output string fields pass through mask_untrusted_text as a
  second defensive desensitization pass.
- No LLM API key or base_url is ever logged or persisted.

NON-BLOCKING CONTRACT:
- generate_and_save_llm_analysis() NEVER raises to the caller.
- On any failure, it persists a fallback-only result and returns.
- The background runner does NOT need to catch exceptions from this module.
- Assessment scoring (P0-6) is completely independent and unaffected.

ASYNC:
- Database reads/writes and LLM HTTP calls are synchronous.
- Callers MUST wrap in asyncio.to_thread().
"""

from __future__ import annotations

import json
import logging
import urllib.error
import urllib.request
from typing import Any, Optional

from app.core.config import settings
from app.core.security.desensitize import mask_untrusted_text
from app.db.database import _get_connection, init_db, now_iso
from app.services.llm_fallback_templates import (
    FALLBACK_TEMPLATES,
    GENERIC_FALLBACK,
    get_fallback_template,
)

logger = logging.getLogger(__name__)

# --- Constants ---

SCHEMA_VERSION = 1
LLM_ANALYSIS_SCOPE = "non_blocking_findings"

# Rule IDs that are BLOCKING and must NEVER be sent to LLM.
_BLOCKING_RULE_PREFIXES: frozenset[str] = frozenset({
    "R001_", "R002_", "R003_", "R004_", "R005_",
})

# Maximum characters for snippet_masked sent to LLM (defense in depth).
_MAX_SNIPPET_CHARS = 500


# ---------------------------------------------------------------------------
# --- Exception classes ---
# ---------------------------------------------------------------------------

class LLMAnalysisPersistError(Exception):
    """SQLite persistence failure for LLM analysis."""
    pass


class LLMAnalysisTooLargeError(Exception):
    """LLM analysis result exceeds size limit."""
    pass


# ---------------------------------------------------------------------------
# --- Public: availability check ---
# ---------------------------------------------------------------------------

def get_llm_analysis_available(task_id: str) -> bool:
    """Lightweight check for status polling — returns True if an LLM
    analysis result exists for the task.

    Reads ONLY the task_id column — does NOT parse analysis_json.
    """
    init_db()
    conn = _get_connection()
    try:
        row = conn.execute(
            "SELECT 1 FROM llm_analysis_results WHERE task_id = ?",
            (task_id,),
        ).fetchone()
        return row is not None
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# --- Finding extraction ---
# ---------------------------------------------------------------------------

def _is_blocking_finding(rule_id: str) -> bool:
    """Check if a finding is blocking (R001-R005) and must not be sent to LLM."""
    return any(rule_id.startswith(prefix) for prefix in _BLOCKING_RULE_PREFIXES)


def _extract_non_blocking_findings(scan_result: dict) -> list[dict]:
    """Extract non-blocking findings from a persisted scan result dict.

    Filters out:
    - Blocking findings (R001-R005) — never sent to LLM.
    - Findings without a valid rule_id.

    Returns a list of finding dicts, limited to
    settings.llm_max_findings_per_task entries (highest severity first).
    """
    findings = scan_result.get("findings", [])
    if not isinstance(findings, list):
        return []

    non_blocking: list[dict] = []
    for f in findings:
        if not isinstance(f, dict):
            continue
        rule_id = f.get("rule_id", "")
        if not rule_id or not isinstance(rule_id, str):
            continue
        if _is_blocking_finding(rule_id):
            continue
        non_blocking.append(f)

    # Sort by severity (critical > high > medium > low > info) to
    # prioritize higher-severity findings for LLM analysis.
    _severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    non_blocking.sort(
        key=lambda f: _severity_order.get(
            f.get("severity", "low"), 4
        )
    )

    max_findings = settings.llm_max_findings_per_task
    if len(non_blocking) > max_findings:
        non_blocking = non_blocking[:max_findings]

    return non_blocking


# ---------------------------------------------------------------------------
# --- LLM prompt building ---
# ---------------------------------------------------------------------------

def _build_llm_prompt(finding: dict) -> str:
    """Build a safe LLM prompt for a single non-blocking finding.

    Only sends:
    - rule_id, rule_name (machine-readable identifiers)
    - file_path (POSIX relative path, already desensitized)
    - snippet_masked (already desensitized by scanner)
    - description (already desensitized by scanner)

    NEVER sends: raw secrets, absolute paths, repo_url, blocking findings.
    """
    rule_id = finding.get("rule_id", "")
    rule_name = finding.get("rule_name", "")
    file_path = finding.get("file_path", "")
    snippet = finding.get("snippet_masked", "")
    description = finding.get("description", "")
    severity = finding.get("severity", "")

    # Defense in depth: truncate snippet to prevent oversized prompts.
    if len(snippet) > _MAX_SNIPPET_CHARS:
        snippet = snippet[:_MAX_SNIPPET_CHARS] + "..."

    prompt = (
        f"你是一位代码安全与质量分析专家。请分析以下代码问题并生成"
        f"通俗解释和修复指令。\n\n"
        f"规则ID: {rule_id}\n"
        f"规则名称: {rule_name}\n"
        f"严重级别: {severity}\n"
        f"文件路径: {file_path}\n"
        f"问题描述: {description}\n"
        f"代码片段(已脱敏):\n{snippet}\n\n"
        f"请以JSON格式返回，包含以下字段:\n"
        f'{{"explanation": "用通俗语言解释这个问题为什么是个问题",'
        f' "instruction": "给出具体的修复步骤"}}\n'
        f"要求:\n"
        f"1. explanation 不超过{settings.llm_max_explanation_chars}字\n"
        f"2. instruction 不超过{settings.llm_max_instruction_chars}字\n"
        f"3. 只返回JSON，不要包含其他内容\n"
        f"4. 不要泄露任何敏感信息\n"
    )
    return prompt


# ---------------------------------------------------------------------------
# --- LLM API call ---
# ---------------------------------------------------------------------------

def _call_llm_api(prompt: str) -> Optional[str]:
    """Call the LLM API and return the response text.

    Returns None on any failure (network error, timeout, auth error).
    Never raises — failures are logged and return None.

    Uses urllib (standard library) to avoid adding dependencies.
    """
    if not settings.llm_enabled:
        return None
    if not settings.llm_base_url:
        logger.warning("LLM enabled but llm_base_url not configured")
        return None
    if not settings.llm_api_key:
        logger.warning("LLM enabled but llm_api_key not configured")
        return None
    if not settings.llm_model:
        logger.warning("LLM enabled but llm_model not configured")
        return None

    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {settings.llm_api_key}",
    }

    body = json.dumps({
        "model": settings.llm_model,
        "messages": [
            {"role": "user", "content": prompt},
        ],
        "max_tokens": 1024,
        "temperature": 0.3,
    }).encode("utf-8")

    last_error = None
    for attempt in range(settings.llm_max_retries + 1):
        try:
            req = urllib.request.Request(
                settings.llm_base_url,
                data=body,
                headers=headers,
                method="POST",
            )
            with urllib.request.urlopen(
                req, timeout=settings.llm_timeout
            ) as resp:
                response_data = json.loads(resp.read().decode("utf-8"))
                # OpenAI-compatible response format.
                choices = response_data.get("choices", [])
                if choices:
                    content = choices[0].get("message", {}).get("content", "")
                    return content
                return None
        except urllib.error.HTTPError as e:
            last_error = e
            # 4xx errors are not retryable.
            if 400 <= e.code < 500:
                logger.warning(
                    "LLM API returned HTTP %d (non-retryable)", e.code
                )
                return None
            # 5xx errors are retryable.
            logger.warning(
                "LLM API returned HTTP %d (attempt %d)", e.code, attempt + 1
            )
        except (urllib.error.URLError, TimeoutError, ConnectionError) as e:
            last_error = e
            logger.warning(
                "LLM API request failed (attempt %d): %s",
                attempt + 1, type(e).__name__,
            )
        except Exception as e:
            # Catch-all: never raise to caller.
            last_error = e
            logger.warning(
                "LLM API unexpected error (attempt %d): %s",
                attempt + 1, type(e).__name__,
            )

    if last_error is not None:
        logger.warning(
            "LLM API call exhausted retries: %s", type(last_error).__name__
        )
    return None


# ---------------------------------------------------------------------------
# --- LLM response parsing ---
# ---------------------------------------------------------------------------

def _parse_llm_response(content: str) -> Optional[dict]:
    """Parse the LLM response text into a dict with explanation and instruction.

    Returns None if parsing fails or the response is invalid.
    Never raises.
    """
    if not content or not isinstance(content, str):
        return None

    # Strip markdown code fences if present.
    text = content.strip()
    if text.startswith("```"):
        lines = text.split("\n")
        # Remove first line (```json or ```)
        lines = lines[1:]
        # Remove last line if it's just ```
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        text = "\n".join(lines).strip()

    try:
        parsed = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        logger.warning("LLM response is not valid JSON")
        return None

    if not isinstance(parsed, dict):
        return None

    explanation = parsed.get("explanation", "")
    instruction = parsed.get("instruction", "")

    if not isinstance(explanation, str) or not isinstance(instruction, str):
        return None

    # Truncate to configured limits.
    max_exp = settings.llm_max_explanation_chars
    max_inst = settings.llm_max_instruction_chars
    if len(explanation) > max_exp:
        explanation = explanation[:max_exp]
    if len(instruction) > max_inst:
        instruction = instruction[:max_inst]

    # Defense in depth: apply mask_untrusted_text to LLM output.
    explanation = mask_untrusted_text(explanation)
    instruction = mask_untrusted_text(instruction)

    if not explanation.strip() or not instruction.strip():
        return None

    return {
        "explanation": explanation.strip(),
        "instruction": instruction.strip(),
    }


# ---------------------------------------------------------------------------
# --- Analysis item generation ---
# ---------------------------------------------------------------------------

def _generate_analysis_item(
    finding: dict,
    use_llm: bool,
) -> dict:
    """Generate a single analysis item for a finding.

    If use_llm is True and the LLM call succeeds, returns an LLM-sourced item.
    Otherwise, returns a fallback-template item.
    """
    rule_id = finding.get("rule_id", "")

    if use_llm:
        prompt = _build_llm_prompt(finding)
        raw_response = _call_llm_api(prompt)
        if raw_response is not None:
            parsed = _parse_llm_response(raw_response)
            if parsed is not None:
                return {
                    "rule_id": rule_id,
                    "rule_name": finding.get("rule_name", ""),
                    "file_path": mask_untrusted_text(
                        finding.get("file_path", "")
                    ),
                    "severity": finding.get("severity", ""),
                    "explanation": parsed["explanation"],
                    "instruction": parsed["instruction"],
                    "source": "llm",
                }

    # Fallback: use fixed template.
    template = get_fallback_template(rule_id)
    if template is None:
        template = GENERIC_FALLBACK

    return {
        "rule_id": rule_id,
        "rule_name": finding.get("rule_name", ""),
        "file_path": mask_untrusted_text(finding.get("file_path", "")),
        "severity": finding.get("severity", ""),
        "explanation": template.explanation,
        "instruction": template.instruction,
        "source": "fallback",
    }


# ---------------------------------------------------------------------------
# --- Persistence ---
# ---------------------------------------------------------------------------

def _save_llm_analysis(
    task_id: str,
    analysis_items: list[dict],
    scan_updated_at: str,
    total_llm: int,
    total_fallback: int,
) -> dict:
    """Persist the LLM analysis result to the database.

    Returns the safe output dict.

    Raises:
        LLMAnalysisPersistError: If SQLite write fails.
        LLMAnalysisTooLargeError: If serialized JSON exceeds size limit.
    """
    if total_llm > 0 and total_fallback > 0:
        source = "mixed"
    elif total_llm > 0:
        source = "llm"
    else:
        source = "fallback"

    output = {
        "schema_version": SCHEMA_VERSION,
        "scope": LLM_ANALYSIS_SCOPE,
        "task_id": task_id,
        "total_analyzed": len(analysis_items),
        "total_llm": total_llm,
        "total_fallback": total_fallback,
        "source": source,
        "items": analysis_items,
    }

    analysis_json = json.dumps(output, ensure_ascii=False, sort_keys=True)

    # Check size limit.
    if len(analysis_json.encode("utf-8")) > settings.llm_max_result_json_bytes:
        raise LLMAnalysisTooLargeError(
            "LLM analysis result exceeds size limit"
        )

    now = now_iso()
    conn = _get_connection()
    try:
        conn.execute(
            """INSERT OR REPLACE INTO llm_analysis_results
               (task_id, schema_version, analysis_json,
                total_analyzed, total_fallback, source,
                source_scan_updated_at, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                task_id,
                SCHEMA_VERSION,
                analysis_json,
                len(analysis_items),
                total_fallback,
                source,
                scan_updated_at,
                now,
                now,
            ),
        )
        conn.commit()
    except Exception as e:
        logger.error(
            "LLM analysis persistence failed: %s", type(e).__name__
        )
        raise LLMAnalysisPersistError("Failed to persist LLM analysis")
    finally:
        conn.close()

    return output


# ---------------------------------------------------------------------------
# --- Public: main entry point ---
# ---------------------------------------------------------------------------

def generate_and_save_llm_analysis(task_id: str) -> dict:
    """Generate LLM analysis for a task and persist it.

    This is the entry point called by the background runner via
    asyncio.to_thread().

    Pipeline:
    1. Read the persisted scan result from scan_results.
    2. Extract non-blocking findings (R006+, I0xx, D0xx, B0xx, C0xx).
    3. For each finding, call LLM (if enabled) or use fallback template.
    4. Persist the result to llm_analysis_results.

    NON-BLOCKING CONTRACT:
    - This function NEVER raises to the caller.
    - On any internal failure, it persists a fallback-only result.
    - If persistence also fails, it logs and returns an empty dict.

    Returns:
        The persisted analysis dict, or an empty dict on total failure.
    """
    try:
        # Step 1: Read persisted scan result.
        from app.services.scan_result_service import get_scan_result

        scan_result = get_scan_result(task_id)
        if scan_result is None:
            logger.warning(
                "No scan result found for task %s — "
                "LLM analysis skipped", task_id
            )
            return {}

        # Get scan_updated_at for source tracking.
        conn = _get_connection()
        try:
            row = conn.execute(
                "SELECT updated_at FROM scan_results WHERE task_id = ?",
                (task_id,),
            ).fetchone()
            scan_updated_at = row["updated_at"] if row else now_iso()
        finally:
            conn.close()

        # Step 2: Extract non-blocking findings.
        findings = _extract_non_blocking_findings(scan_result)

        if not findings:
            # No non-blocking findings — persist an empty result.
            return _save_llm_analysis(
                task_id, [], scan_updated_at, 0, 0,
            )

        # Step 3: Generate analysis items.
        use_llm = settings.llm_enabled
        analysis_items: list[dict] = []
        total_llm = 0
        total_fallback = 0

        for finding in findings:
            item = _generate_analysis_item(finding, use_llm)
            analysis_items.append(item)
            if item["source"] == "llm":
                total_llm += 1
            else:
                total_fallback += 1

        # Step 4: Persist.
        return _save_llm_analysis(
            task_id, analysis_items, scan_updated_at,
            total_llm, total_fallback,
        )

    except LLMAnalysisTooLargeError:
        # Result too large — persist a fallback-only truncated version.
        logger.warning(
            "LLM analysis too large for task %s — "
            "using fallback templates only", task_id
        )
        try:
            return _generate_fallback_only(task_id, findings, scan_updated_at)
        except Exception:
            logger.error(
                "Fallback LLM analysis also failed for task %s", task_id
            )
            return {}

    except Exception as e:
        # Catch-all: never raise to caller.
        logger.error(
            "LLM analysis failed for task %s: %s",
            task_id, type(e).__name__,
        )
        try:
            return _generate_fallback_only(task_id, [], now_iso())
        except Exception:
            logger.error(
                "Fallback LLM analysis also failed for task %s", task_id
            )
            return {}


def _generate_fallback_only(
    task_id: str,
    findings: list[dict],
    scan_updated_at: str,
) -> dict:
    """Generate and persist a fallback-only analysis result.

    Used when LLM is unavailable or the LLM result is too large.
    """
    analysis_items: list[dict] = []
    for finding in findings:
        item = _generate_analysis_item(finding, use_llm=False)
        analysis_items.append(item)

    return _save_llm_analysis(
        task_id, analysis_items, scan_updated_at,
        0, len(analysis_items),
    )


# ---------------------------------------------------------------------------
# --- Public: retrieve persisted result ---
# ---------------------------------------------------------------------------

def get_llm_analysis(task_id: str) -> Optional[dict]:
    """Retrieve the persisted LLM analysis result for a task.

    Returns None if no result has been persisted.

    The returned dict has the structure:
    {
        "schema_version": int,
        "scope": str,
        "task_id": str,
        "total_analyzed": int,
        "total_llm": int,
        "total_fallback": int,
        "source": str,  # "llm", "fallback", or "mixed"
        "items": [
            {
                "rule_id": str,
                "rule_name": str,
                "file_path": str,
                "severity": str,
                "explanation": str,
                "instruction": str,
                "source": str,  # "llm" or "fallback"
            },
            ...
        ]
    }
    """
    init_db()
    conn = _get_connection()
    try:
        row = conn.execute(
            "SELECT analysis_json FROM llm_analysis_results WHERE task_id = ?",
            (task_id,),
        ).fetchone()
        if row is None:
            return None
        return json.loads(row["analysis_json"])
    except Exception:
        # Malformed JSON or DB failure — treat as "not available".
        logger.error(
            "Failed to read LLM analysis for task %s", task_id
        )
        return None
    finally:
        conn.close()


def get_llm_analysis_summary(task_id: str) -> Optional[dict]:
    """Lightweight summary for status polling — reads only redundant columns.

    Returns None if no result has been persisted.
    """
    init_db()
    conn = _get_connection()
    try:
        row = conn.execute(
            """SELECT total_analyzed, total_fallback, source
               FROM llm_analysis_results WHERE task_id = ?""",
            (task_id,),
        ).fetchone()
        if row is None:
            return None
        return {
            "total_analyzed": row["total_analyzed"],
            "total_fallback": row["total_fallback"],
            "source": row["source"],
        }
    finally:
        conn.close()
