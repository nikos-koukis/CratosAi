import 'server-only'

import { readFileSync } from 'node:fs'

import { z } from 'zod'

/** The dashboard's settings, from DASHBOARD_* environment variables. */
export type Config = {
  /** Where browsers reach the dashboard; WebAuthn and invite links use it. */
  origin: URL
  /** WebAuthn relying party: the origin's host or a registrable suffix of it. */
  rpID: string
  rpName: string
  /** Cookies are Secure and __Host- prefixed (https); only localhost may be http. */
  secureCookies: boolean
  databaseUrl: string
  /** Its identity towards the services (spiffe://jarvis.local/dashboard-api). */
  tls: { ca: Buffer; cert: Buffer; key: Buffer }
  vaultAddr: string
  appAdminAddr: string
  mcpAddr: string
  /** The audit service: the dashboard records what people do there, and shows the trail. */
  auditAddr: string
  /** A session ends after this long without use, and at the latest after sessionLifetime. */
  sessionIdleMs: number
  sessionLifetimeMs: number
  /** Take the client address from X-Forwarded-For (behind a trusted proxy). */
  trustProxy: boolean
}

const UNITS: Record<string, number> = { ms: 1, s: 1_000, m: 60_000, h: 3_600_000, d: 86_400_000 }

/** Parses durations like "90s", "30m", "12h", "7d". */
export function parseDuration(value: string): number {
  const match = /^(\d+)(ms|s|m|h|d)$/.exec(value.trim())
  if (!match) throw new Error(`not a duration: ${JSON.stringify(value)} (use e.g. 30m, 12h, 7d)`)
  return Number(match[1]) * UNITS[match[2]!]!
}

const hostPort = z.string().regex(/^[A-Za-z0-9.-]+:\d{1,5}$/, 'must be host:port')

const schema = z.object({
  DASHBOARD_ORIGIN: z.url(),
  DASHBOARD_RP_ID: z.string().optional(),
  DASHBOARD_RP_NAME: z.string().min(1).max(64).default('Jarvis'),
  DASHBOARD_DATABASE_URL: z.string().optional(),
  DASHBOARD_DATABASE_URL_FILE: z.string().optional(),
  DASHBOARD_TLS_CA: z.string().min(1),
  DASHBOARD_TLS_CERT: z.string().min(1),
  DASHBOARD_TLS_KEY: z.string().min(1),
  DASHBOARD_VAULT_ADDR: hostPort.default('127.0.0.1:50051'),
  DASHBOARD_APP_ADMIN_ADDR: hostPort.default('127.0.0.1:50055'),
  DASHBOARD_MCP_ADDR: hostPort.default('127.0.0.1:50052'),
  DASHBOARD_AUDIT_ADDR: hostPort.default('127.0.0.1:50056'),
  DASHBOARD_SESSION_IDLE: z.string().default('24h'),
  DASHBOARD_SESSION_LIFETIME: z.string().default('7d'),
  DASHBOARD_TRUST_PROXY: z.enum(['true', 'false']).default('false'),
})

/** Reads and checks the configuration; the error names every problem (never values). */
export function loadConfig(env: Record<string, string | undefined> = process.env): Config {
  const parsed = schema.safeParse(env)
  if (!parsed.success) {
    const problems = parsed.error.issues.map((i) => `${i.path.join('.')}: ${i.message}`)
    throw new Error(`invalid dashboard configuration:\n  ${problems.join('\n  ')}`)
  }
  const e = parsed.data
  const problems: string[] = []

  const origin = new URL(e.DASHBOARD_ORIGIN)
  const local = origin.hostname === 'localhost'
  if (origin.protocol !== 'https:' && !(local && origin.protocol === 'http:')) {
    problems.push('DASHBOARD_ORIGIN: must be https (http only for localhost)')
  }
  if (origin.pathname !== '/' || origin.search || origin.hash) {
    problems.push('DASHBOARD_ORIGIN: must be an origin, without path, query or fragment')
  }
  const rpID = e.DASHBOARD_RP_ID ?? origin.hostname
  if (origin.hostname !== rpID && !origin.hostname.endsWith(`.${rpID}`)) {
    problems.push('DASHBOARD_RP_ID: must be the origin host or a parent domain of it')
  }

  let databaseUrl = e.DASHBOARD_DATABASE_URL
  if (!databaseUrl && e.DASHBOARD_DATABASE_URL_FILE) {
    databaseUrl = readSetting(e.DASHBOARD_DATABASE_URL_FILE, 'DASHBOARD_DATABASE_URL_FILE', problems)
      ?.toString('utf8')
      .trim()
  }
  if (!databaseUrl) problems.push('DASHBOARD_DATABASE_URL or DASHBOARD_DATABASE_URL_FILE: required')

  const ca = readSetting(e.DASHBOARD_TLS_CA, 'DASHBOARD_TLS_CA', problems)
  const cert = readSetting(e.DASHBOARD_TLS_CERT, 'DASHBOARD_TLS_CERT', problems)
  const key = readSetting(e.DASHBOARD_TLS_KEY, 'DASHBOARD_TLS_KEY', problems)

  let sessionIdleMs = 0
  let sessionLifetimeMs = 0
  try {
    sessionIdleMs = parseDuration(e.DASHBOARD_SESSION_IDLE)
    sessionLifetimeMs = parseDuration(e.DASHBOARD_SESSION_LIFETIME)
    if (sessionIdleMs > sessionLifetimeMs) problems.push('DASHBOARD_SESSION_IDLE: longer than the lifetime')
  } catch (error) {
    problems.push(`DASHBOARD_SESSION_IDLE/LIFETIME: ${(error as Error).message}`)
  }

  if (problems.length > 0) {
    throw new Error(`invalid dashboard configuration:\n  ${problems.join('\n  ')}`)
  }
  return {
    origin,
    rpID,
    rpName: e.DASHBOARD_RP_NAME,
    secureCookies: origin.protocol === 'https:',
    databaseUrl: databaseUrl!,
    tls: { ca: ca!, cert: cert!, key: key! },
    vaultAddr: e.DASHBOARD_VAULT_ADDR,
    appAdminAddr: e.DASHBOARD_APP_ADMIN_ADDR,
    mcpAddr: e.DASHBOARD_MCP_ADDR,
    auditAddr: e.DASHBOARD_AUDIT_ADDR,
    sessionIdleMs,
    sessionLifetimeMs,
    trustProxy: e.DASHBOARD_TRUST_PROXY === 'true',
  }
}

function readSetting(path: string, name: string, problems: string[]): Buffer | undefined {
  try {
    return readFileSync(path)
  } catch {
    problems.push(`${name}: cannot read the file`)
    return undefined
  }
}

let cached: Config | undefined

/** The process's configuration, loaded once. */
export function config(): Config {
  cached ??= loadConfig()
  return cached
}
