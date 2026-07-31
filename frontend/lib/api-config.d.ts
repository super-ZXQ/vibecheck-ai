export class ApiConfigError extends Error {}

export function normalizeApiBaseUrl(configuredUrl: string | undefined): string;
export function getApiBaseUrl(): string;
