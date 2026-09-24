import { mkdtempSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { describe, expect, it } from 'vitest'

import { loadConfig, parseDuration } from '@/server/config'

const dir = mkdtempSync(join(tmpdir(), 'dashboard-config-'))
for (const name of ['ca.pem', 'cert.pem', 'key.pem']) writeFileSync(join(dir, name), `-- ${name} --`)
writeFileSync(join(dir, 'db-url'), 'postgres://dashboard:from-file@127.0.0.1:5432/dashboard\n')

const base = {
  DASHBOARD_ORIGIN: 'http://localhost:3000',
  DASHBOARD_DATABASE_URL: 'postgres://dashboard:secret-password@127.0.0.1:5432/dashboard',
  DASHBOARD_TLS_CA: join(dir, 'ca.pem'),
  DASHBOARD_TLS_CERT: join(dir, 'cert.pem'),
  DASHBOARD_TLS_KEY: join(dir, 'key.pem'),
}

function problems(env: Record<string, string | undefined>): string {
  try {
    loadConfig(env)
  } catch (error) {
    return (error as Error).message
  }
  throw new Error('expected the configuration to be refused')
}

describe('configuration', () => {
  it('has development defaults on localhost', () => {
    const c = loadConfig(base)
    expect(c.origin.origin).toBe('http://localhost:3000')
    expect(c.rpID).toBe('localhost')
    expect(c.secureCookies).toBe(false)
    expect(c.vaultAddr).toBe('127.0.0.1:50051')
    expect(c.appAdminAddr).toBe('127.0.0.1:50055')
    expect(c.mcpAddr).toBe('127.0.0.1:50052')
    expect(c.auditAddr).toBe('127.0.0.1:50056')
    expect(c.sessionIdleMs).toBe(24 * 3_600_000)
    expect(c.sessionLifetimeMs).toBe(7 * 86_400_000)
    expect(c.tls.cert.toString()).toBe('-- cert.pem --')
    expect(c.trustProxy).toBe(false)
  })

  it('uses secure cookies over https, and accepts a parent domain as RP ID', () => {
    const c = loadConfig({
      ...base,
      DASHBOARD_ORIGIN: 'https://jarvis.example.com',
      DASHBOARD_RP_ID: 'example.com',
    })
    expect(c.secureCookies).toBe(true)
    expect(c.rpID).toBe('example.com')
  })

  it('reads the database URL from a file', () => {
    const c = loadConfig({
      ...base,
      DASHBOARD_DATABASE_URL: undefined,
      DASHBOARD_DATABASE_URL_FILE: join(dir, 'db-url'),
    })
    expect(c.databaseUrl).toBe('postgres://dashboard:from-file@127.0.0.1:5432/dashboard')
  })

  it('refuses plain http beyond localhost, paths, and foreign RP IDs', () => {
    expect(problems({ ...base, DASHBOARD_ORIGIN: 'http://jarvis.example.com' })).toContain('must be https')
    expect(problems({ ...base, DASHBOARD_ORIGIN: 'https://jarvis.example.com/app' })).toContain(
      'without path',
    )
    expect(
      problems({ ...base, DASHBOARD_ORIGIN: 'https://jarvis.example.com', DASHBOARD_RP_ID: 'evil.com' }),
    ).toContain('DASHBOARD_RP_ID')
  })

  it('names every problem, never a value', () => {
    const message = problems({
      ...base,
      DASHBOARD_DATABASE_URL: undefined,
      DASHBOARD_TLS_KEY: join(dir, 'missing.pem'),
      DASHBOARD_SESSION_IDLE: '30d',
    })
    expect(message).toContain('DASHBOARD_DATABASE_URL')
    expect(message).toContain('DASHBOARD_TLS_KEY')
    expect(message).toContain('DASHBOARD_SESSION_IDLE')
    expect(problems({ ...base, DASHBOARD_VAULT_ADDR: 'secret-password' })).not.toContain('secret-password')
  })

  it('parses durations', () => {
    expect(parseDuration('90s')).toBe(90_000)
    expect(parseDuration('30m')).toBe(1_800_000)
    expect(parseDuration('12h')).toBe(43_200_000)
    expect(parseDuration('7d')).toBe(604_800_000)
    expect(() => parseDuration('1 week')).toThrow()
  })
})
