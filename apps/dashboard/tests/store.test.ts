import { randomBytes } from 'node:crypto'

import { afterAll, beforeAll, describe, expect, it } from 'vitest'

import { migrate, withTx } from '@/server/db/db'
import { sha256, uuidv7 } from '@/server/ids'
import { Problem } from '@/server/problem'
import * as accounts from '@/server/store/accounts'
import * as integrations from '@/server/store/integrations'
import * as ws from '@/server/store/workspaces'

import { startPostgres, stopPostgres, type TestDatabase } from './support/postgres'

let db: TestDatabase

beforeAll(async () => {
  db = await startPostgres()
})
afterAll(() => stopPostgres(db))

async function user(name = 'Ana'): Promise<string> {
  const userId = uuidv7()
  await accounts.createUser(db.pool, { userId, displayName: name, webauthnUserId: randomBytes(32) })
  return userId
}

async function passkey(userId: string): Promise<string> {
  const credentialId = randomBytes(16).toString('base64url')
  await accounts.addPasskey(db.pool, {
    credentialId,
    userId,
    publicKey: randomBytes(77),
    counter: 0,
    transports: ['internal'],
    deviceType: 'multiDevice',
    backedUp: true,
    name: 'Passkey',
  })
  return credentialId
}

async function workspace(ownerId: string): Promise<string> {
  const workspaceId = uuidv7()
  await withTx(db.pool, (tx) => ws.createWorkspace(tx, { workspaceId, name: 'Acme', ownerId }))
  return workspaceId
}

async function problemOf(promise: Promise<unknown>): Promise<Problem> {
  try {
    await promise
  } catch (error) {
    if (error instanceof Problem) return error
    throw error
  }
  throw new Error('expected a Problem')
}

async function session(userId: string, lifetimeMs = 60_000): Promise<{ token: Buffer; sessionId: string }> {
  const token = sha256(uuidv7())
  const sessionId = uuidv7()
  await accounts.createSession(db.pool, {
    tokenHash: token,
    sessionId,
    userId,
    recovered: false,
    userAgent: 'test',
    lifetimeMs,
  })
  return { token, sessionId }
}

describe('migrations', () => {
  it('apply once', async () => {
    expect(await migrate(db.pool)).toEqual([])
  })
})

describe('sessions', () => {
  it('last until idle or past their lifetime, and end on sign-out', async () => {
    const ana = await user()
    const live = await session(ana)
    expect((await accounts.findSession(db.pool, live.token, 60_000))?.userId).toBe(ana)
    expect(await accounts.findSession(db.pool, sha256('other'), 60_000)).toBeUndefined()

    const expired = await session(ana, -1)
    expect(await accounts.findSession(db.pool, expired.token, 60_000)).toBeUndefined()

    await db.pool.query(
      "UPDATE sessions SET last_seen_time = now() - interval '2 hours' WHERE session_id = $1",
      [live.sessionId],
    )
    expect(await accounts.findSession(db.pool, live.token, 3_600_000)).toBeUndefined() // idle for too long
    expect(await accounts.findSession(db.pool, live.token, 3 * 3_600_000)).toBeDefined()

    await accounts.deleteSession(db.pool, live.sessionId)
    expect(await accounts.findSession(db.pool, live.token, 3 * 3_600_000)).toBeUndefined()
  })

  it('"sign out other browsers" keeps only this one', async () => {
    const ana = await user()
    const bob = await user('Bob')
    const [a1, a2, a3] = [await session(ana), await session(ana), await session(ana)]
    const b1 = await session(bob)
    expect(await accounts.deleteUserSessions(db.pool, ana, a2.sessionId)).toBe(2)
    expect(await accounts.findSession(db.pool, a1.token, 60_000)).toBeUndefined()
    expect(await accounts.findSession(db.pool, a3.token, 60_000)).toBeUndefined()
    expect(await accounts.findSession(db.pool, a2.token, 60_000)).toBeDefined()
    expect(await accounts.findSession(db.pool, b1.token, 60_000)).toBeDefined()
  })
})

describe('WebAuthn challenges', () => {
  it('work once, for their purpose, before they expire', async () => {
    const challengeId = uuidv7()
    await accounts.saveChallenge(db.pool, { challengeId, challenge: 'c1', purpose: 'sign_in', ttlMs: 60_000 })
    expect(await accounts.takeChallenge(db.pool, challengeId, 'sign_up')).toBeUndefined() // wrong purpose
    expect((await accounts.takeChallenge(db.pool, challengeId, 'sign_in'))?.challenge).toBe('c1')
    expect(await accounts.takeChallenge(db.pool, challengeId, 'sign_in')).toBeUndefined() // used

    const stale = uuidv7()
    await accounts.saveChallenge(db.pool, {
      challengeId: stale,
      challenge: 'c2',
      purpose: 'sign_in',
      ttlMs: -1,
    })
    expect(await accounts.takeChallenge(db.pool, stale, 'sign_in')).toBeUndefined()
  })

  it('carry the pending sign-up', async () => {
    const challengeId = uuidv7()
    const pending = { displayName: 'Ana', workspaceName: 'Acme', webauthnUserId: 'abc' }
    await accounts.saveChallenge(db.pool, {
      challengeId,
      challenge: 'c',
      purpose: 'sign_up',
      pending,
      ttlMs: 60_000,
    })
    expect((await accounts.takeChallenge(db.pool, challengeId, 'sign_up'))?.pending).toEqual(pending)
  })
})

describe('recovery codes', () => {
  it('work once each, and new ones replace the old', async () => {
    const ana = await user()
    const [c1, c2] = [sha256('code-1'), sha256('code-2')]
    await withTx(db.pool, (tx) => accounts.replaceRecoveryCodes(tx, ana, [c1, c2]))
    expect(await accounts.countRecoveryCodes(db.pool, ana)).toBe(2)
    expect(await accounts.redeemRecoveryCode(db.pool, c1)).toBe(ana)
    expect(await accounts.redeemRecoveryCode(db.pool, c1)).toBeUndefined()
    expect(await accounts.countRecoveryCodes(db.pool, ana)).toBe(1)

    await withTx(db.pool, (tx) => accounts.replaceRecoveryCodes(tx, ana, [sha256('code-3')]))
    expect(await accounts.redeemRecoveryCode(db.pool, c2)).toBeUndefined()
    expect(await accounts.redeemRecoveryCode(db.pool, sha256('code-3'))).toBe(ana)
  })
})

describe('passkeys', () => {
  it('are found by credential id, and the last one cannot be removed', async () => {
    const ana = await user()
    const bob = await user('Bob')
    const first = await passkey(ana)
    const bobs = await passkey(bob)
    expect((await accounts.findPasskey(db.pool, first))?.userId).toBe(ana)

    expect((await problemOf(withTx(db.pool, (tx) => accounts.removePasskey(tx, ana, first)))).code).toBe(
      'last_passkey',
    )
    // Someone else's passkey is "not found", not removable.
    expect((await problemOf(withTx(db.pool, (tx) => accounts.removePasskey(tx, ana, bobs)))).code).toBe(
      'not_found',
    )

    const second = await passkey(ana)
    await withTx(db.pool, (tx) => accounts.removePasskey(tx, ana, first))
    expect((await accounts.listPasskeys(db.pool, ana)).map((p) => p.credentialId)).toEqual([second])

    await accounts.recordPasskeyUse(db.pool, second, 7)
    const used = await accounts.findPasskey(db.pool, second)
    expect(used?.counter).toBe(7)
    expect(used?.lastUseTime).toBeInstanceOf(Date)
  })
})

describe('workspaces', () => {
  it('belong to their members only', async () => {
    const ana = await user()
    const bob = await user('Bob')
    const acme = await workspace(ana)
    expect(await ws.getMembership(db.pool, acme, ana)).toMatchObject({ role: 'owner', name: 'Acme' })
    expect(await ws.getMembership(db.pool, acme, bob)).toBeUndefined()
    expect((await ws.listWorkspaces(db.pool, bob)).length).toBe(0)
  })

  it('always keep an owner', async () => {
    const ana = await user()
    const bob = await user('Bob')
    const acme = await workspace(ana)
    await db.pool.query("INSERT INTO memberships (workspace_id, user_id, role) VALUES ($1, $2, 'member')", [
      acme,
      bob,
    ])

    const demote = (id: string) => withTx(db.pool, (tx) => ws.setRole(tx, acme, id, 'member'))
    const remove = (id: string) => withTx(db.pool, (tx) => ws.removeMember(tx, acme, id))
    expect((await problemOf(demote(ana))).code).toBe('last_owner')
    expect((await problemOf(remove(ana))).code).toBe('last_owner')

    await withTx(db.pool, (tx) => ws.setRole(tx, acme, bob, 'owner'))
    await demote(ana)
    expect((await problemOf(remove(bob))).code).toBe('last_owner')
    await remove(ana)
    expect((await ws.listMembers(db.pool, acme)).map((m) => [m.displayName, m.role])).toEqual([
      ['Bob', 'owner'],
    ])
  })

  it('keep an owner when two owners step down at once', async () => {
    const ana = await user()
    const bob = await user('Bob')
    const acme = await workspace(ana)
    await db.pool.query("INSERT INTO memberships (workspace_id, user_id, role) VALUES ($1, $2, 'owner')", [
      acme,
      bob,
    ])

    // Ana steps down, and has not committed yet when Bob steps down too.
    const first = await db.pool.connect()
    const second = await db.pool.connect()
    try {
      await first.query('BEGIN')
      await ws.setRole(first, acme, ana, 'member')
      await second.query('BEGIN')
      const bobStepsDown = ws.setRole(second, acme, bob, 'member').then(
        () => 'done',
        (error: unknown) => (error instanceof Problem ? error.code : 'error'),
      )
      await new Promise((resolve) => setTimeout(resolve, 200)) // Bob's check must wait for Ana's
      await first.query('COMMIT')
      expect(await bobStepsDown).toBe('last_owner')
      await second.query('ROLLBACK')
    } finally {
      first.release()
      second.release()
    }
    const owners = (await ws.listMembers(db.pool, acme)).filter((m) => m.role === 'owner')
    expect(owners.map((m) => m.displayName)).toEqual(['Bob'])
  })
})

describe('invitations', () => {
  async function invite(workspaceId: string, createdBy: string, ttlMs = 60_000) {
    const token = uuidv7()
    const invitationId = uuidv7()
    await ws.createInvitation(db.pool, {
      tokenHash: sha256(token),
      invitationId,
      workspaceId,
      role: 'member',
      createdBy,
      ttlMs,
    })
    return { token, invitationId }
  }

  it('work once, and make the user a member with their role', async () => {
    const ana = await user()
    const bob = await user('Bob')
    const carol = await user('Carol')
    const acme = await workspace(ana)
    const { token, invitationId } = await invite(acme, ana)

    expect(await ws.findInvitation(db.pool, sha256(token))).toMatchObject({
      state: 'pending',
      workspaceName: 'Acme',
      invitedBy: 'Ana',
    })
    expect(await ws.listPendingInvitations(db.pool, acme)).toHaveLength(1)

    expect(await withTx(db.pool, (tx) => ws.acceptInvitation(tx, sha256(token), bob))).toEqual({
      workspaceId: acme,
      role: 'member',
      invitationId,
    })
    expect((await ws.getMembership(db.pool, acme, bob))?.role).toBe('member')
    expect((await ws.findInvitation(db.pool, sha256(token)))?.state).toBe('used')
    expect(await ws.listPendingInvitations(db.pool, acme)).toHaveLength(0)

    const again = await problemOf(withTx(db.pool, (tx) => ws.acceptInvitation(tx, sha256(token), carol)))
    expect(again.code).toBe('expired')
    expect(await ws.getMembership(db.pool, acme, carol)).toBeUndefined()
  })

  it('refuse members, expired and withdrawn links, and unknown tokens', async () => {
    const ana = await user()
    const bob = await user('Bob')
    const acme = await workspace(ana)

    const own = await invite(acme, ana)
    expect(
      (await problemOf(withTx(db.pool, (tx) => ws.acceptInvitation(tx, sha256(own.token), ana)))).code,
    ).toBe('conflict')
    expect((await ws.findInvitation(db.pool, sha256(own.token)))?.state).toBe('pending') // still usable

    const old = await invite(acme, ana, -1)
    expect((await ws.findInvitation(db.pool, sha256(old.token)))?.state).toBe('expired')
    expect(
      (await problemOf(withTx(db.pool, (tx) => ws.acceptInvitation(tx, sha256(old.token), bob)))).message,
    ).toContain('expired')

    const withdrawn = await invite(acme, ana)
    await ws.revokeInvitation(db.pool, acme, withdrawn.invitationId)
    expect((await ws.findInvitation(db.pool, sha256(withdrawn.token)))?.state).toBe('revoked')
    expect((await problemOf(ws.revokeInvitation(db.pool, acme, withdrawn.invitationId))).code).toBe(
      'not_found',
    )

    expect(
      (await problemOf(withTx(db.pool, (tx) => ws.acceptInvitation(tx, sha256('nope'), bob)))).code,
    ).toBe('not_found')
    // Another workspace cannot withdraw it.
    const other = await workspace(bob)
    expect((await problemOf(ws.revokeInvitation(db.pool, other, own.invitationId))).code).toBe('not_found')
  })
})

describe('MCP authorizations', () => {
  it('can be finished once, only by the user who started them, before they expire', async () => {
    const ana = await user()
    const bob = await user('Bob')
    const acme = await workspace(ana)
    const started = { userId: ana, workspaceId: acme, integrationId: uuidv7(), ttlMs: 60_000 }
    await integrations.saveAuthorization(db.pool, { ...started, stateHash: sha256('state-1') })

    expect(await integrations.takeAuthorization(db.pool, sha256('state-1'), bob)).toBeUndefined()
    expect(await integrations.takeAuthorization(db.pool, sha256('state-1'), ana)).toEqual({
      workspaceId: acme,
      integrationId: started.integrationId,
    })
    expect(await integrations.takeAuthorization(db.pool, sha256('state-1'), ana)).toBeUndefined()

    await integrations.saveAuthorization(db.pool, { ...started, stateHash: sha256('old'), ttlMs: -1 })
    expect(await integrations.takeAuthorization(db.pool, sha256('old'), ana)).toBeUndefined()
  })
})
