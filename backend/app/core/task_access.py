"""Anonymous task ownership enforced by the ``X-Submitter-Key`` header.

A submitter key is an opaque value the browser generates once and keeps in
localStorage. It is not an identity and carries no personal data; it only
records which browser submitted a task, so reads and cancels can be scoped
to that browser instead of to anyone who learns the task id.

Contract:
- Present and well-formed on submit: stored on the task, and every later
  read or cancel of that task requires the same value.
- Absent on submit: the task records no owner and stays reachable by task id
  alone (the pre-ownership behaviour, kept for API clients that opt out).
- Present but malformed on submit: 400, because a client that means to be
  protected must not be silently left unprotected.
- Wrong or missing key on a read: the same 404 as an unknown task id, so a
  failed match never confirms that the task exists.
"""

import re
from typing import TYPE_CHECKING, Annotated

from fastapi import Header, HTTPException, status

from app.core.error_codes import INVALID_SUBMITTER_KEY, get_error_message

if TYPE_CHECKING:
    from app.db.repositories.tasks import TaskRecord

SUBMITTER_KEY_HEADER = "X-Submitter-Key"

# 16-64 URL-safe characters: long enough to be unguessable, short enough to
# stay inside tasks.submitter_key VARCHAR(64).
_KEY_PATTERN = re.compile(r"[A-Za-z0-9_-]{16,64}")

SubmitterKeyHeader = Annotated[str | None, Header(alias=SUBMITTER_KEY_HEADER)]


def parse_submitter_key(raw: str | None) -> str | None:
    """Return the usable key, or None when absent or malformed."""
    if raw is None:
        return None
    key = raw.strip()
    return key if _KEY_PATTERN.fullmatch(key) else None


def submitter_key_for_create(raw: str | None) -> str | None:
    """Validate a submitter key on task creation.

    None means "no owner recorded"; a malformed value is rejected outright.
    """
    if raw is None or not raw.strip():
        return None
    key = parse_submitter_key(raw)
    if key is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "error_code": INVALID_SUBMITTER_KEY,
                "error_message": get_error_message(INVALID_SUBMITTER_KEY),
            },
        )
    return key


def ensure_task_access(task: "TaskRecord", raw: str | None) -> None:
    """Raise the not-found error unless ``raw`` may access ``task``.

    Tasks with no recorded owner are unrestricted; owned tasks answer 404 to
    every other key.
    """
    if task.submitter_key is None:
        return
    if parse_submitter_key(raw) == task.submitter_key:
        return
    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail={
            "error_code": "TASK_NOT_FOUND",
            "error_message": "任务不存在。",
        },
    )
