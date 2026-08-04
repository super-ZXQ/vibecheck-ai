/** @type {import('next').NextConfig} */

const {
  getProductionApiOrigin,
  normalizeApiOrigin,
} = require("./lib/production-api-origin.cjs");

const production = process.env.NODE_ENV === "production";
const configuredApiBaseUrl = process.env.NEXT_PUBLIC_API_BASE_URL;

function getConfiguredApiOrigin() {
  if (production) return getProductionApiOrigin(configuredApiBaseUrl);
  if (!configuredApiBaseUrl) return null;
  return normalizeApiOrigin(configuredApiBaseUrl).origin;
}

const apiOrigin = getConfiguredApiOrigin();
const connectSources = ["'self'"];
if (apiOrigin) connectSources.push(apiOrigin);
if (!production) connectSources.push("http:", "https:", "ws:", "wss:");

const scriptSources = ["'self'", "'unsafe-inline'"];
if (!production) scriptSources.push("'unsafe-eval'");

// NOTE: "'unsafe-inline'" in script-src is required in production. Next.js
// App Router emits inline bootstrap scripts (self.__next_f.push(...)) into
// the rendered HTML for hydration; removing it would break every page under
// CSP. Impact is bounded: all application code ships as external hashed
// bundles from 'self', inline scripts are framework-generated constant
// strings, and object-src 'none' / base-uri 'self' / frame-ancestors 'none'
// limit exploit surface. Switching to nonce/hash-based CSP would require
// nonce injection via middleware (not supported natively for the RSC
// bootstrap) and is out of scope.

const contentSecurityPolicy = [
  "default-src 'self'",
  "base-uri 'self'",
  `connect-src ${connectSources.join(" ")}`,
  "font-src 'self' data:",
  "form-action 'self'",
  "frame-ancestors 'none'",
  "img-src 'self' data: blob:",
  "object-src 'none'",
  `script-src ${scriptSources.join(" ")}`,
  "style-src 'self' 'unsafe-inline'",
].join("; ");

const securityHeaders = [
  {
    key: "Content-Security-Policy",
    value: contentSecurityPolicy,
  },
  {
    key: "Permissions-Policy",
    value: "camera=(), microphone=(), geolocation=(), payment=()",
  },
  {
    key: "Referrer-Policy",
    value: "no-referrer",
  },
  {
    key: "X-Content-Type-Options",
    value: "nosniff",
  },
  {
    key: "X-Frame-Options",
    value: "DENY",
  },
  {
    key: "X-Permitted-Cross-Domain-Policies",
    value: "none",
  },
  {
    key: "X-XSS-Protection",
    value: "0",
  },
];

if (production) {
  securityHeaders.push({
    key: "Strict-Transport-Security",
    value: "max-age=31536000; includeSubDomains",
  });
}

const nextConfig = {
  output: "standalone",
  poweredByHeader: false,
  reactStrictMode: true,
  async headers() {
    return [
      {
        source: "/:path*",
        headers: securityHeaders,
      },
    ];
  },
};

module.exports = nextConfig;
