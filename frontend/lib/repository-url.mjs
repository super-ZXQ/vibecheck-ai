/**
 * Normalize the one safe shorthand accepted by the submission form.
 * Backend URL validation remains the security boundary.
 */
export function normalizeGitHubRepoUrl(value) {
  const trimmed = value.trim();
  const shorthand = /^github\.com\//i.exec(trimmed);
  if (!shorthand) return trimmed;
  return `https://github.com/${trimmed.slice(shorthand[0].length)}`;
}
