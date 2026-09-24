import { NextRequest } from 'next/server'
import { afterEach, describe, expect, it, vi } from 'vitest'

import { proxy } from '@/proxy'

function policyOf(url = 'http://localhost:3000/w/x/keys') {
  const response = proxy(new NextRequest(url))
  return { policy: response.headers.get('content-security-policy') ?? '', response }
}

describe('proxy', () => {
  afterEach(() => vi.unstubAllEnvs())

  it('sets a strict CSP with a fresh nonce per request', () => {
    vi.stubEnv('NODE_ENV', 'production')
    const a = policyOf().policy
    const b = policyOf().policy
    const nonce = /'nonce-([^']+)'/.exec(a)?.[1]
    expect(nonce).toBeTruthy()
    expect(b).not.toContain(nonce)
    expect(a).toContain("script-src 'self' 'nonce-")
    expect(a).toContain("'strict-dynamic'")
    expect(a).toContain("frame-ancestors 'none'")
    expect(a).toContain("object-src 'none'")
    expect(a).not.toContain('unsafe-eval')
    expect(a).not.toContain('unsafe-inline')
  })

  it('allows eval and inline styles only in development', () => {
    vi.stubEnv('NODE_ENV', 'development')
    const { policy } = policyOf()
    expect(policy).toContain("'unsafe-eval'")
    expect(policy).toContain("style-src 'self' 'unsafe-inline'")
  })

  it('adds HSTS and upgrades requests only when served over https', () => {
    vi.stubEnv('DASHBOARD_ORIGIN', 'http://localhost:3000')
    expect(policyOf().response.headers.get('strict-transport-security')).toBeNull()
    expect(policyOf().policy).not.toContain('upgrade-insecure-requests')

    vi.stubEnv('DASHBOARD_ORIGIN', 'https://jarvis.example.com')
    const { policy, response } = policyOf('https://jarvis.example.com/')
    expect(response.headers.get('strict-transport-security')).toContain('max-age=')
    expect(policy).toContain('upgrade-insecure-requests')
  })
})
