import 'server-only'

import { headers } from 'next/headers'

import { config } from './config'

/**
 * The client's address, for rate limiting. Behind a trusted proxy
 * (DASHBOARD_TRUST_PROXY=true) it is the first X-Forwarded-For entry;
 * otherwise all clients share one bucket per limit, which is safe but coarse.
 */
export async function clientAddress(): Promise<string> {
  if (!config().trustProxy) return 'direct'
  const forwarded = (await headers()).get('x-forwarded-for')
  return forwarded?.split(',')[0]?.trim() || 'unknown'
}

export async function userAgent(): Promise<string> {
  return ((await headers()).get('user-agent') ?? '').slice(0, 256)
}
