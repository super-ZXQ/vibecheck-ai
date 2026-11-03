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

import ipaddress
import logging
import re
import socket
import threading
import time
from urllib.parse import urlsplit

logger = logging.getLogger(__name__)

# Safety net: drop entries older than this even if the task never finishes.
_USER_CONFIG_TTL_SECONDS = 4 * 3600

# --- Validation limits ---
_MAX_API_KEY_CHARS = 1000
_MAX_BASE_URL_CHARS = 500
_MAX_MODEL_CHARS = 200

# A public API endpoint is at least two labels with an alphabetic top-level
# label. This also rejects decimal/hex octet encodings such as 2130706433 and
# 0x7f.0.0.1, and dotless container names such as "postgres".
_HOSTNAME_LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
_HOSTNAME_RE = re.compile(rf"(?:{_HOSTNAME_LABEL}\.)+[a-z]{{2,63}}")

# RFC 6762 / RFC 6761 names that never identify a public service.
_RESERVED_HOST_SUFFIXES = (
    ".local",
    ".localhost",
    ".internal",
    ".cluster.local",
    ".home.arpa",
    ".onion",
)

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
    """A user-supplied base URL must be a public HTTPS API endpoint.

    The caller controls this URL and the worker fetches it from inside the
    deployment network, so it is an SSRF surface: an operator's own
    ``llm_base_url`` may point anywhere, but a browser-supplied header may not.

    Enforced here (deterministic, no DNS): HTTPS only, no embedded
    credentials, a real dotted hostname, and no address in a non-global range.
    Obfuscated forms (``2130706433``, ``0x7f.0.0.1``) fall out of the hostname
    shape check. Names that *resolve* to an internal address are handled at
    request time by :func:`is_public_endpoint`.
    """
    if len(raw) > _MAX_BASE_URL_CHARS:
        return False
    if "@" in raw:
        # Embedded credentials are forbidden (defense in depth: the key itself
        # is sent via the Authorization header, never in the URL).
        return False
    if not raw.lower().startswith("https://"):
        return False
    try:
        parsed = urlsplit(raw)
    except ValueError:
        return False
    host = parsed.hostname
    if not host or not _HOSTNAME_RE.fullmatch(host):
        return False
    return not host.endswith(_RESERVED_HOST_SUFFIXES)


def is_public_endpoint(raw: str) -> bool:
    """Resolve a validated base URL and require every address to be global.

    Guards against a public hostname pointing at loopback or the link-local
    metadata address. Returns False on resolution failure — an endpoint we
    cannot place is an endpoint we do not call.
    """
    try:
        parsed = urlsplit(raw)
        host = parsed.hostname
        if not host:
            return False
        try:
            literal = ipaddress.ip_address(host)
        except ValueError:
            literal = None
        if literal is not None:
            return literal.is_global
        records = socket.getaddrinfo(host, parsed.port or 443)
    except (OSError, ValueError):
        return False
    if not records:
        return False
    for record in records:
        address = record[4][0]
        try:
            resolved = ipaddress.ip_address(address)
        except ValueError:
            return False
        if not resolved.is_global:
            return False
    return True


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
