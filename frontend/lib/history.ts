/**
 * Check history stored in localStorage.
 *
 * Security constraint: only non-sensitive metadata is persisted
 * (task_id, repo identity, score, verdict, status). API response
 * bodies and code snippets are NEVER stored here.
 */

export interface HistoryEntry {
  task_id: string;
  repo_url: string;
  owner: string;
  repo_name: string;
  created_at: string; // ISO 8601
  security_score: number | null;
  security_verdict: string | null;
  status: string; // "completed" | "failed"
}

const STORAGE_KEY = "vibecheck_history";
const MAX_ENTRIES = 10;

function isHistoryEntry(value: unknown): value is HistoryEntry {
  if (typeof value !== "object" || value === null) return false;
  const entry = value as Record<string, unknown>;
  return (
    typeof entry.task_id === "string" &&
    typeof entry.repo_url === "string" &&
    typeof entry.created_at === "string" &&
    typeof entry.status === "string"
  );
}

export function getHistory(): HistoryEntry[] {
  if (typeof window === "undefined") return [];
  try {
    const raw = window.localStorage.getItem(STORAGE_KEY);
    if (!raw) return [];
    const parsed: unknown = JSON.parse(raw);
    if (!Array.isArray(parsed)) return [];
    return parsed.filter(isHistoryEntry).slice(0, MAX_ENTRIES);
  } catch {
    return [];
  }
}

export function addHistory(entry: HistoryEntry): void {
  if (typeof window === "undefined") return;
  try {
    const existing = getHistory().filter((e) => e.task_id !== entry.task_id);
    const next = [entry, ...existing].slice(0, MAX_ENTRIES);
    window.localStorage.setItem(STORAGE_KEY, JSON.stringify(next));
  } catch {
    // Storage full or unavailable — history is best-effort only.
  }
}

export function clearHistory(): void {
  if (typeof window === "undefined") return;
  try {
    window.localStorage.removeItem(STORAGE_KEY);
  } catch {
    // Ignore — nothing to clear.
  }
}

/**
 * Build a HistoryEntry from a completed/failed task status.
 *
 * The status response does not include the original repo URL, so the
 * repo identity is derived from top_level_dir (GitHub tarball layout:
 * "owner-repo-ref"). Falls back gracefully when the layout is unusual.
 */
export function entryFromTaskStatus(status: {
  task_id: string;
  status: string;
  top_level_dir: string | null;
  security_score: number | null;
  security_verdict: string | null;
}): HistoryEntry {
  let owner = "";
  let repoName = status.top_level_dir ?? "unknown-repo";
  if (status.top_level_dir) {
    const parts = status.top_level_dir.split("-");
    if (parts.length >= 3) {
      owner = parts[0];
      repoName = parts.slice(1, -1).join("-");
    }
  }
  return {
    task_id: status.task_id,
    repo_url: owner
      ? `https://github.com/${owner}/${repoName}`
      : status.top_level_dir ?? "",
    owner,
    repo_name: repoName,
    created_at: new Date().toISOString(),
    security_score: status.security_score,
    security_verdict: status.security_verdict,
    status: status.status === "failed" ? "failed" : "completed",
  };
}
