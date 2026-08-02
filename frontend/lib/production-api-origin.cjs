"use strict";

const LOOPBACK_HOSTS = new Set(["localhost", "127.0.0.1", "[::1]"]);

function normalizeApiOrigin(configuredUrl) {
  let parsed;
  try {
    parsed = new URL(configuredUrl);
  } catch {
    throw new Error("NEXT_PUBLIC_API_BASE_URL must be a pure HTTP(S) origin");
  }

  if (
    !["http:", "https:"].includes(parsed.protocol) ||
    parsed.username ||
    parsed.password ||
    parsed.search ||
    parsed.hash ||
    configuredUrl !== parsed.origin
  ) {
    throw new Error("NEXT_PUBLIC_API_BASE_URL must be a pure HTTP(S) origin");
  }

  return parsed;
}

function getProductionApiOrigin(configuredUrl) {
  if (!configuredUrl) {
    throw new Error("NEXT_PUBLIC_API_BASE_URL is required for production");
  }

  const parsed = normalizeApiOrigin(configuredUrl);
  if (parsed.protocol !== "https:" && !LOOPBACK_HOSTS.has(parsed.hostname)) {
    throw new Error(
      "NEXT_PUBLIC_API_BASE_URL must use HTTPS except for loopback hosts",
    );
  }
  return parsed.origin;
}

module.exports = {
  getProductionApiOrigin,
  normalizeApiOrigin,
};
