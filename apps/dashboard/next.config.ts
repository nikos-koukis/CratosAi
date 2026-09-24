import type { NextConfig } from 'next'

// Headers for every response. The Content-Security-Policy (with a per-request
// nonce) and HSTS are set in src/proxy.ts.
const securityHeaders = [
  { key: 'X-Content-Type-Options', value: 'nosniff' },
  { key: 'X-Frame-Options', value: 'DENY' },
  { key: 'Referrer-Policy', value: 'same-origin' },
  { key: 'Cross-Origin-Opener-Policy', value: 'same-origin' },
  { key: 'Cross-Origin-Resource-Policy', value: 'same-origin' },
  {
    key: 'Permissions-Policy',
    value:
      'camera=(), microphone=(), geolocation=(), payment=(), usb=(), ' +
      'publickey-credentials-create=(self), publickey-credentials-get=(self)',
  },
]

// Server actions accept only requests whose Origin is this host. Behind a
// proxy that rewrites Host (e.g. Tailscale Serve), name the public origin.
const publicHost = process.env.DASHBOARD_ORIGIN ? new URL(process.env.DASHBOARD_ORIGIN).host : undefined

const config: NextConfig = {
  reactStrictMode: true,
  experimental: publicHost ? { serverActions: { allowedOrigins: [publicHost] } } : {},
  poweredByHeader: false,
  typedRoutes: true,
  // The generated protobuf code is TypeScript source in the workspace.
  transpilePackages: ['@jarvis/proto'],
  async headers() {
    return [{ source: '/:path*', headers: securityHeaders }]
  },
}

export default config
