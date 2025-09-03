/** @type {import('next').NextConfig} */
const nextConfig = {
  async rewrites() {
    const base = process.env.NEXT_PUBLIC_API_URL || "http://localhost:9000";
    return [
      // Map legacy UI calls to the real backend endpoints
      { source: "/api/v2/import/url", destination: `${base}/scan/url` },
      { source: "/api/v2/import/postman", destination: `${base}/scan/postman` },
      { source: "/api/v2/import/openapi", destination: `${base}/scan/report` },
      { source: "/api/v2/scans/start", destination: `${base}/scan/url` },

      // General API proxy for new code
      { source: "/api/:path*", destination: `${base}/:path*` },

      // Legacy catch-all for /v2 that isn't covered by the above
      { source: "/api/v2/:path*", destination: `${base}/:path*` },
    ];
  },
};

module.exports = nextConfig;
