/**
 * Safe lookup into a plain record keyed by untrusted strings.
 *
 * Direct indexing like `MAP[key] ?? fallback` is dangerous: keys such as
 * "constructor", "__proto__", or "toString" resolve to inherited
 * Object.prototype members (non-null), so the fallback never fires and
 * React throws when rendering the resulting function/object.
 *
 * `lookup` only returns values owned by the record itself.
 */

export function lookup<T>(
  record: Record<string, T>,
  key: string | null | undefined,
  fallback: T,
): T {
  if (key === null || key === undefined) return fallback;
  return Object.prototype.hasOwnProperty.call(record, key)
    ? record[key]
    : fallback;
}
