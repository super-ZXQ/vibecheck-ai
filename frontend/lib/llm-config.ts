/**
 * Per-user LLM configuration.
 *
 * The user's own LLM credentials (API key, base URL, model) live ONLY in
 * this browser's localStorage and are attached to detection requests as
 * X-LLM-* headers. The backend uses them in process memory for the LLM
 * analysis stage only — never persisted, never logged, never returned.
 *
 * Security constraints:
 * - The API key never leaves this browser except in the Authorization
 *   header-equivalent X-LLM-API-KEY sent to OUR backend over the same
 *   connection as the request itself.
 * - Config values are never written to console, sessionStorage, or any
 *   server.
 */

const LLM_CONFIG_KEY = "vibecheck.llm-config";

export interface LLMConfig {
  apiKey: string;
  baseUrl: string;
  model: string;
}

const EMPTY_CONFIG: LLMConfig = { apiKey: "", baseUrl: "", model: "" };

/** Read the stored config; any malformed value is treated as empty. */
export function getLLMConfig(): LLMConfig {
  try {
    const raw = window.localStorage.getItem(LLM_CONFIG_KEY);
    if (!raw) return { ...EMPTY_CONFIG };
    const parsed = JSON.parse(raw) as Partial<LLMConfig>;
    return {
      apiKey: typeof parsed.apiKey === "string" ? parsed.apiKey : "",
      baseUrl: typeof parsed.baseUrl === "string" ? parsed.baseUrl : "",
      model: typeof parsed.model === "string" ? parsed.model : "",
    };
  } catch {
    return { ...EMPTY_CONFIG };
  }
}

/** Persist the config to localStorage. */
export function saveLLMConfig(config: LLMConfig): void {
  window.localStorage.setItem(LLM_CONFIG_KEY, JSON.stringify(config));
}

/** Remove the stored config. */
export function clearLLMConfig(): void {
  window.localStorage.removeItem(LLM_CONFIG_KEY);
}

/** True when at least one field is configured. */
export function hasLLMConfig(config: LLMConfig): boolean {
  return Boolean(config.apiKey || config.baseUrl || config.model);
}

/**
 * Build the X-LLM-* request headers from the stored config.
 * Only fields the user actually filled in are sent; an empty config
 * contributes no headers at all.
 */
export function buildLLMHeaders(): Record<string, string> {
  const config = getLLMConfig();
  const headers: Record<string, string> = {};
  if (config.apiKey) headers["X-LLM-API-KEY"] = config.apiKey;
  if (config.baseUrl) headers["X-LLM-BASE-URL"] = config.baseUrl;
  if (config.model) headers["X-LLM-MODEL"] = config.model;
  return headers;
}
