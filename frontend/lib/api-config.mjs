export class ApiConfigError extends Error {
  constructor() {
    super("API_BASE_URL_NOT_CONFIGURED");
    this.name = "ApiConfigError";
  }
}

export function getApiBaseUrl(
  configuredUrl = process.env.NEXT_PUBLIC_API_BASE_URL,
) {
  if (!configuredUrl || configuredUrl.trim() === "") {
    throw new ApiConfigError();
  }
  return configuredUrl.replace(/\/+$/, "");
}
