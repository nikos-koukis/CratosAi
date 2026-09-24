import { mkdtempSync, writeFileSync } from 'node:fs'
import { randomBytes } from 'node:crypto'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import type pg from 'pg'
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest'

import { startPostgres, stopPostgres, type TestDatabase } from './support/postgres'

// A cookie jar and request headers in place of Next.js's request context.
const browser = vi.hoisted(() => ({
  cookies: new Map<string, { value: string; options?: Record<string, unknown> }>(),
}))

vi.mock('next/headers', () => ({
  cookies: async () => ({
    get: (name: string) => {
      const c = browser.cookies.get(name)
      return c && { name, value: c.value }
    },
    set: (name: string, value: string, options?: { maxAge?: number }) => {
      if (options?.maxAge === 0) browser.cookies.delete(name)
      else browser.cookies.set(name, { value, options })
    },
    delete: (name: string) => browser.cookies.delete(name),
  }),
  headers: async () => new Headers({ 'user-agent': 'vitest' }),
}))

vi.mock('next/navigation', () => ({
  redirect: (url: string) => {
    throw new Error(`redirect:${url}`)
  },
  notFound: () => {
    throw new Error('not-found')
  },
}))

let db: TestDatabase
let passkeys: typeof import('@/server/auth/passkeys')
let sessions: typeof import('@/server/auth/session')
let accounts: typeof import('@/server/store/accounts')
let ws: typeof import('@/server/store/workspaces')
let ids: typeof import('@/server/ids')
let withTx: typeof import('@/server/db/db').withTx
let Problem: typeof import('@/server/problem').Problem

beforeAll(async () => {
  db = await startPostgres()
  const dir = mkdtempSync(join(tmpdir(), 'dashboard-auth-'))
  for (const name of ['ca.pem', 'cert.pem', 'key.pem']) writeFileSync(join(dir, name), 'unused here')
  Object.assign(process.env, {
    DASHBOARD_ORIGIN: 'http://localhost:3000',
    DASHBOARD_DATABASE_URL: db.url,
    DASHBOARD_TLS_CA: join(dir, 'ca.pem'),
    DASHBOARD_TLS_CERT: join(dir, 'cert.pem'),
    DASHBOARD_TLS_KEY: join(dir, 'key.pem'),
  })
  passkeys = await import('@/server/auth/passkeys')
  sessions = await import('@/server/auth/session')
  accounts = await import('@/server/store/accounts')
  ws = await import('@/server/store/workspaces')
  ids = await import('@/server/ids')
  withTx = (await import('@/server/db/db')).withTx
  Problem = (await import('@/server/problem')).Problem
})

afterAll(async () => {
  await (globalThis as { __jarvisDashboardPool?: pg.Pool }).__jarvisDashboardPool?.end()
  await stopPostgres(db)
})

beforeEach(() => browser.cookies.clear())

async function failure(promise: Promise<unknown>): Promise<{ code: string; message: string }> {
  try {
    await promise
  } catch (error) {
    if (error instanceof Problem) return { code: error.code, message: error.message }
    throw error
  }
  throw new Error('expected a Problem')
}

/** A user with one recovery code; returns the code as they would type it. */
async function userWithCode(): Promise<{ userId: string; code: string }> {
  const userId = ids.uuidv7()
  await accounts.createUser(db.pool, { userId, displayName: 'Ana', webauthnUserId: randomBytes(32) })
  const code = ids.recoveryCode()
  await withTx(db.pool, (tx) => accounts.replaceRecoveryCodes(tx, userId, [ids.sha256(code)]))
  return { userId, code }
}

const sessionCookie = () => browser.cookies.get('jarvis-session')

describe('recovery codes', () => {
  it('sign in once, into a session that may only add a passkey', async () => {
    const { userId, code } = await userWithCode()
    await passkeys.signInWithRecoveryCode(` ${code.toLowerCase().replace(/-/g, ' ')} `)

    expect(sessionCookie()?.options).toMatchObject({ httpOnly: true, sameSite: 'lax', path: '/' })
    const session = await sessions.currentSession()
    expect(session).toMatchObject({ userId, recovered: true })
    expect((await failure(sessions.actionSession())).code).toBe('forbidden')
    await expect(sessions.actionSession({ allowRecovered: true })).resolves.toMatchObject({ userId })
    await expect(sessions.requireSession()).rejects.toThrow('redirect:/account')

    browser.cookies.clear()
    expect((await failure(passkeys.signInWithRecoveryCode(code))).code).toBe('unauthenticated')
  })
})

describe('sessions', () => {
  it('start fresh on every sign-in, and end on sign-out', async () => {
    const { userId, code } = await userWithCode()
    await passkeys.signInWithRecoveryCode(code)
    const first = sessionCookie()!.value
    await withTx(db.pool, (tx) => accounts.replaceRecoveryCodes(tx, userId, [ids.sha256('AAAA-BBBB-CCCC')]))
    await passkeys.signInWithRecoveryCode('AAAA-BBBB-CCCC')
    const second = sessionCookie()!.value

    expect(second).not.toBe(first)
    // The token from before is dead: no session fixation.
    expect(await accounts.findSession(db.pool, ids.sha256(first), 60_000)).toBeUndefined()
    expect((await sessions.currentSession())?.userId).toBe(userId)

    await sessions.endSession()
    expect(sessionCookie()).toBeUndefined()
    expect(await accounts.findSession(db.pool, ids.sha256(second), 60_000)).toBeUndefined()
    await expect(sessions.requireSession()).rejects.toThrow('redirect:/sign-in')
    expect((await failure(sessions.actionSession())).code).toBe('unauthenticated')
  })

  it('ignore forged and oversized cookies', async () => {
    browser.cookies.set('jarvis-session', { value: 'x'.repeat(43) })
    expect(await sessions.currentSession()).toBeUndefined()
    browser.cookies.set('jarvis-session', { value: 'x'.repeat(5000) })
    expect(await sessions.currentSession()).toBeUndefined()
  })
})

describe('passkey ceremonies', () => {
  it('ask for discoverable passkeys with user verification, for this site', async () => {
    const options = await passkeys.beginSignUp({ displayName: ' Ana ', workspaceName: 'Acme' })
    expect(options.rp).toEqual({ name: 'Jarvis', id: 'localhost' })
    expect(options.user.name).toBe('Ana')
    expect(options.authenticatorSelection).toMatchObject({
      residentKey: 'required',
      userVerification: 'required',
    })
    expect(options.attestation).toBe('none')
    expect(browser.cookies.get('jarvis-challenge')?.options).toMatchObject({
      httpOnly: true,
      sameSite: 'strict',
    })

    const signIn = await passkeys.beginSignIn()
    expect(signIn.userVerification).toBe('required')
    expect(signIn.allowCredentials ?? []).toEqual([])
  })

  it('use a challenge once, only from the browser that asked for it', async () => {
    await passkeys.beginSignIn()
    const challengeCookie = browser.cookies.get('jarvis-challenge')!
    const forged = {
      id: randomBytes(16).toString('base64url'),
      rawId: randomBytes(16).toString('base64url'),
      type: 'public-key' as const,
      response: { clientDataJSON: '', authenticatorData: '', signature: '' },
      clientExtensionResults: {},
    }
    // An unknown passkey does not sign in, and uses up the challenge.
    expect((await failure(passkeys.finishSignIn(forged))).code).toBe('unauthenticated')
    browser.cookies.set('jarvis-challenge', challengeCookie)
    expect((await failure(passkeys.finishSignIn(forged))).code).toBe('expired')

    // Without the challenge cookie (another browser), nothing to finish.
    await passkeys.beginSignIn()
    browser.cookies.delete('jarvis-challenge')
    expect((await failure(passkeys.finishSignIn(forged))).code).toBe('expired')
    expect(sessionCookie()).toBeUndefined()
  })

  it('check names and invitations before asking for a passkey', async () => {
    await expect(passkeys.beginSignUp({ displayName: '   ', workspaceName: 'Acme' })).rejects.toThrow(
      'Enter your name.',
    )
    await expect(passkeys.beginSignUp({ displayName: 'Ana', workspaceName: 'x'.repeat(65) })).rejects.toThrow(
      'At most 64',
    )
    expect(
      (await failure(passkeys.beginSignUp({ displayName: 'Ana', inviteToken: 'no-such-token' }))).code,
    ).toBe('expired')

    const owner = ids.uuidv7()
    await accounts.createUser(db.pool, {
      userId: owner,
      displayName: 'Owner',
      webauthnUserId: randomBytes(32),
    })
    const workspaceId = ids.uuidv7()
    await withTx(db.pool, (tx) => ws.createWorkspace(tx, { workspaceId, name: 'Acme', ownerId: owner }))
    const { token, hash } = passkeys.newInvitationToken()
    await ws.createInvitation(db.pool, {
      tokenHash: hash,
      invitationId: ids.uuidv7(),
      workspaceId,
      role: 'member',
      createdBy: owner,
      ttlMs: 60_000,
    })
    const options = await passkeys.beginSignUp({ displayName: 'Bob', inviteToken: token })
    expect(options.user.name).toBe('Bob')
  })
})

describe('workspace access', () => {
  // The server checks the caller's role in every action; the pages hiding a
  // button is not the protection.
  it('lets owners manage, members use (and leave), and strangers see nothing', async () => {
    const access = await import('@/server/access')
    const members = await import('@/server/members')
    const person = async (name: string) => {
      const userId = ids.uuidv7()
      await accounts.createUser(db.pool, { userId, displayName: name, webauthnUserId: randomBytes(32) })
      return userId
    }
    const [owner, member, stranger] = [
      await person('Owner'),
      await person('Member'),
      await person('Stranger'),
    ]
    const workspaceId = ids.uuidv7()
    await withTx(db.pool, (tx) => ws.createWorkspace(tx, { workspaceId, name: 'Acme', ownerId: owner }))
    await db.pool.query("INSERT INTO memberships (workspace_id, user_id, role) VALUES ($1, $2, 'member')", [
      workspaceId,
      member,
    ])

    await sessions.startSession(member, false)
    const asMember = await access.actionWorkspace(workspaceId)
    expect(asMember.workspace.role).toBe('member')
    expect((await failure(access.actionWorkspace(workspaceId, 'owner'))).code).toBe('forbidden')
    expect((await failure(members.removeMember(asMember, owner))).code).toBe('forbidden')

    await sessions.startSession(stranger, false)
    expect((await failure(access.actionWorkspace(workspaceId))).code).toBe('not_found')
    expect((await failure(access.actionWorkspace('../../etc'))).code).toBe('not_found')
    await expect(access.requireWorkspace(workspaceId)).rejects.toThrow('not-found')

    await sessions.startSession(owner, false)
    const asOwner = await access.actionWorkspace(workspaceId, 'owner')
    await members.changeRole(asOwner, member, 'owner')
    expect(asOwner.workspace.role).toBe('owner')

    await sessions.startSession(member, false)
    await members.removeMember(await access.actionWorkspace(workspaceId), member) // leaving
    expect((await failure(access.actionWorkspace(workspaceId))).code).toBe('not_found')
  })
})

describe('rate limits', () => {
  it('stop guessing recovery codes', async () => {
    const results = []
    for (let i = 0; i < 8; i++)
      results.push((await failure(passkeys.signInWithRecoveryCode('ZZZZ-ZZZZ-ZZZZ'))).code)
    expect(results).toContain('rate_limited')
    expect(results.filter((c) => c === 'unauthenticated').length).toBeLessThanOrEqual(5)
  })
})
