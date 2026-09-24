import { NextResponse, type NextRequest } from 'next/server'

/**
 * Content-Security-Policy with a fresh nonce per request (Next.js puts it on
 * its scripts), and HSTS when served over https. Pages are rendered per
 * request (the root layout awaits connection()), so every one gets a nonce.
 */
export function proxy(request: NextRequest): NextResponse {
  const nonce = Buffer.from(crypto.randomUUID()).toString('base64')
  const dev = process.env.NODE_ENV === 'development'
  const https = process.env.DASHBOARD_ORIGIN?.startsWith('https:') ?? false
  const policy = [
    "default-src 'self'",
    // React needs eval in development only, for its error overlays.
    `script-src 'self' 'nonce-${nonce}' 'strict-dynamic'${dev ? " 'unsafe-eval'" : ''}`,
    // Development tooling injects styles without the nonce.
    dev ? "style-src 'self' 'unsafe-inline'" : `style-src 'self' 'nonce-${nonce}'`,
    "img-src 'self' data:",
    "font-src 'self'",
    `connect-src 'self'${dev ? ' ws: wss:' : ''}`,
    "object-src 'none'",
    "base-uri 'none'",
    "form-action 'self'",
    "frame-ancestors 'none'",
    ...(https ? ['upgrade-insecure-requests'] : []),
  ].join('; ')

  const headers = new Headers(request.headers)
  headers.set('x-nonce', nonce)
  headers.set('content-security-policy', policy)
  const response = NextResponse.next({ request: { headers } })
  response.headers.set('content-security-policy', policy)
  if (https) response.headers.set('strict-transport-security', 'max-age=63072000; includeSubDomains')
  return response
}

export const config = {
  matcher: [
    {
      source: '/((?!_next/static|_next/image|favicon.ico|api/health).*)',
      missing: [
        { type: 'header', key: 'next-router-prefetch' },
        { type: 'header', key: 'purpose', value: 'prefetch' },
      ],
    },
  ],
}
