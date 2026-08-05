"""In-memory per-task LLM configuration store.

SECURITY:
- Stores the caller-supplied LLM credentials (API key, base URL, model)
  ONLY in process memory. NEVER persisted to SQLite, disk, or logs.
- Entries are bound to a task_id, cleaned up when the task finishes, and
  pruned by a hard TTL as a safety net for tasks that never complete.
- A process restart clears everything; no sensitive data survives.
- The API key is never logged, never returned to any caller, and never
  written to any response.

THREADING:
- FastAPI handlers (event loop) and the background runner (worker thread)
  access this store concurrently. All operations go through one lock.
"""

from __future__ import annotations

import logging
import threading
import time

logger = logging.getLogger(__name__)

# Safety net: drop entries older than this even if the task never finishes.
_USER_CONFIG_TTL_SECONDS = 4 * 3600

# --- Validation limits ---
_MAX_API_KEY_CHARS = 1000
_MAX_BASE_URL_CHARS = 500
_MAX_MODEL_CHARS = 200

_LOCK = threading.Lock()
_STORE: dict[str, dict] = {}


def _prune_locked() -> None:
    """Drop expired entries. Caller MUST hold _LOCK."""
    now = time.monotonic()
    expired = [
        task_id
        for task_id, cfg in _STORE.items()
        if now - cfg["_created"] > _USER_CONFIG_TTL_SECONDS
    ]
    for task_id in expired:
        del _STORE[task_id]


def _valid_base_url(raw: str) -> bool:
    """A user-supplied base URL must be http(s) with no embedded credentials.

    Rejects javascript:, file:, credentials (user:pass@), fragments, and
    anything longer than the limit. Non-HTTP schemes would fail the
    urllib request anyway, but we fail fast and drop the entry.
    """
    if len(raw) > _MAX_BASE_URL_CHARS:
        return False
    lowered = raw.lower()
    if not (lowered.startswith(("https://", "http://"))):
        return False
    # Embedded credentials are forbidden (defense in depth: the key itself
    # is sent via the Authorization header, never in the URL).
    return "@" not in raw


def store_user_config(
    task_id: str,
    api_key: str | None,
    base_url: str | None,
    model: str | None,
) -> None:
    """Bind a caller-supplied LLM config to a task.

    Only stores entries that are both non-empty AND pass validation.
    A fully invalid config is ignored (the task falls back to the
    server-side settings, never fails).

    Returns nothing; errors are silently ignored (log only the reason
    class, never the value).
    """
    api_key = (api_key or "").strip()
    base_url = (base_url or "").strip()
    model = (model or "").strip()

    if not api_key and not base_url and not model:
        return
    if len(api_key) > _MAX_API_KEY_CHARS or len(model) > _MAX_MODEL_CHARS:
        logger.warning("User LLM config rejected for task %s", task_id)
        return
    if base_url and not _valid_base_url(base_url):
        logger.warning("User LLM base URL rejected for task %s", task_id)
        return

    with _LOCK:
        _prune_locked()
        _STORE[task_id] = {
            "api_key": api_key,
            "base_url": base_url,
            "model": model,
            "_created": time.monotonic(),
        }


def get_user_config(task_id: str) -> dict | None:
    """Return the stored user config for a task, or None.

    Returns a copy with the private "_created" key removed. Never raises.
    """
    with _LOCK:
        _prune_locked()
        entry = _STORE.get(task_id)
        if entry is None:
            return None
        return {
            "api_key": entry["api_key"],
            "base_url": entry["base_url"],
            "model": entry["model"],
        }


def pop_user_config(task_id: str) -> dict | None:
    """Remove and return the stored user config for a task.

    Called by the background runner when a task finishes (success or
    failure) so credentials never outlive the task.
    """
    with _LOCK:
        _prune_locked()
        entry = _STORE.pop(task_id, None)
        if entry is None:
            return None
        return {
            "api_key": entry["api_key"],
            "base_url": entry["base_url"],
            "model": entry["model"],
        }


def clear_user_configs() -> None:
    """Drop all stored configs — for testing only."""
    with _LOCK:
        _STORE.clear()


def count_user_configs() -> int:
    """Number of live entries — for testing only."""
    with _LOCK:
        _prune_locked()
        return len(_STORE)
