/**
 * Anonymous per-browser submitter key (task ownership).
 *
 * The key is generated once by this browser, kept in localStorage, and sent
 * as X-Submitter-Key on every task request. The backend records it on the
 * task, so only this browser can read or cancel that task — and a second
 * visitor submitting the same repository gets their own task instead of being
 * handed the first visitor's task id.
 *
 * It is not an identity: it contains no account, device or user data, and
 * clearing site data or reloading in private mode simply means the browser no
 * longer owns the tasks it created.
 *
 * If localStorage is unavailable, the key is used for this session only; if
 * even that fails, requests go without a header and the task is created
 * unowned (reachable by task id alone), which is the documented opt-out.
 */

export const SUBMITTER_KEY_STORAGE = "vibecheck.submitter-key.v1";
export const SUBMITTER_KEY_HEADER = "X-Submitter-Key";

const KEY_BYTES = 16;

// Mirrors the backend pattern in app/core/task_access.py: 16-64 URL-safe
// characters. A stored value outside it is discarded and replaced.
const KEY_PATTERN = /^[A-Za-z0-9_-]{16,64}$/;

function defaultGetRandomValues(bytes) {
  return globalThis.crypto.getRandomValues(bytes);
}

function toHex(bytes) {
  let out = "";
  for (const byte of bytes) out += byte.toString(16).padStart(2, "0");
  return out;
}

/** 32 lowercase hex characters from 16 random bytes. */
export function createSubmitterKey(getRandomValues = defaultGetRandomValues) {
  const bytes = new Uint8Array(KEY_BYTES);
  getRandomValues(bytes);
  return toHex(bytes);
}

/**
 * Return this browser's key, creating and storing it on first use.
 * `storage` is injectable so the contract is testable without a DOM;
 * null means "no persistence available".
 */
export function resolveSubmitterKey(
  storage,
  getRandomValues = defaultGetRandomValues,
) {
  if (!storage) return createSubmitterKey(getRandomValues);
  let stored = null;
  try {
    stored = storage.getItem(SUBMITTER_KEY_STORAGE);
  } catch {
    return null;
  }
  if (typeof stored === "string" && KEY_PATTERN.test(stored)) return stored;
  const fresh = createSubmitterKey(getRandomValues);
  try {
    storage.setItem(SUBMITTER_KEY_STORAGE, fresh);
  } catch {
    // Persisting failed: keep the session key rather than dropping ownership.
  }
  return fresh;
}

function browserStorage() {
  if (typeof window === "undefined") return null;
  try {
    return window.localStorage;
  } catch {
    return null;
  }
}

/**
 * Headers for one request. Empty during SSR, where no task is ever owned.
 */
export function buildSubmitterHeaders() {
  const storage = browserStorage();
  if (!storage) return {};
  const key = resolveSubmitterKey(storage);
  return key ? { [SUBMITTER_KEY_HEADER]: key } : {};
}
