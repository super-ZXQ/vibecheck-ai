/** @type {import('next').NextConfig} */

const production = process.env.NODE_ENV === "production";
const configuredApiBaseUrl = process.env.NEXT_PUBLIC_API_BASE_URL;

function getConfiguredApiOrigin() {
  if (!configuredApiBaseUrl) {
    if (production) {
      throw new Error("NEXT_PUBLIC_API_BASE_URL is required for production");
    }
    return null;
  }

  const parsed = new URL(configuredApiBaseUrl);
  if (
    !["http:", "https:"].includes(parsed.protocol) ||
    parsed.username ||
    parsed.password ||
    parsed.search ||
    parsed.hash ||
    (parsed.pathname && parsed.pathname !== "/")
  ) {
    throw new Error("NEXT_PUBLIC_API_BASE_URL must be a pure HTTP(S) origin");
  }
  return parsed.origin;
}

const apiOrigin = getConfiguredApiOrigin();
const connectSources = ["'self'"];
if (apiOrigin) connectSources.push(apiOrigin);
if (!production) connectSources.push("http:", "https:", "ws:", "wss:");

const scriptSources = ["'self'", "'unsafe-inline'"];
if (!production) scriptSources.push("'unsafe-eval'");

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
