export const SUBMITTER_KEY_STORAGE: string;
export const SUBMITTER_KEY_HEADER: string;

export function createSubmitterKey(
  getRandomValues?: (bytes: Uint8Array) => Uint8Array,
): string;

export function resolveSubmitterKey(
  storage: Storage | null,
  getRandomValues?: (bytes: Uint8Array) => Uint8Array,
): string | null;

export function buildSubmitterHeaders(): Record<string, string>;
