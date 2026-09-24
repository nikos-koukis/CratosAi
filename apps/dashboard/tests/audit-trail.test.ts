import { randomBytes } from 'node:crypto'
import http2 from 'node:http2'
import type { AddressInfo } from 'node:net'
import { join } from 'node:path'
import type { TLSSocket } from 'node:tls'

import { create, type MessageInitShape } from '@bufbuild/protobuf'
import { timestampFromDate } from '@bufbuild/protobuf/wkt'
import { Code, ConnectError, type ConnectRouter } from '@connectrpc/connect'
import { connectNodeAdapter } from '@connectrpc/connect-node'
import {
  ActorKind,
  AuditService,
  EventSchema,
  Outcome,
  type Event,
  type ListEventsRequest,
} from '@jarvis/proto/jarvis/audit/v1/audit_pb'
import type pg from 'pg'
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest'

import { makePki } from './support/pki'
import { startPostgres, stopPostgres, type TestDatabase } from './support/postgres'

// The audit trail through the dashboard: a real PostgreSQL, a fake audit
// service over real mTLS, and an owner (Ana) and a member (Bob).

const browser = vi.hoisted(() => ({ cookies: new Map<string, { value: string }>() }))

vi.mock('next/headers', () => ({
  cookies: async () => ({
    get: (name: string) => {
      const c = browser.cookies.get(name)
      return c && { name, value: c.value }
    },
    set: (name: string, value: string, options?: { maxAge?: number }) => {
      if (options?.maxAge === 0) browser.cookies.delete(name)
      else browser.cookies.set(name, { value })
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
  unstable_rethrow: () => {},
}))

/** Stores what is recorded, with the caller's identity as the source, like the real service. */
const fake = {
  events: [] as Event[],
  lists: [] as ListEventsRequest[],
  refuse: undefined as Code | undefined,
  broken: false,
}

function routes(r: ConnectRouter) {
  r.service(AuditService, {
    record(req, ctx) {
      if (fake.refuse !== undefined) throw new ConnectError('refused', fake.refuse)
      const source = ctx.requestHeader.get('x-peer') ?? ''
      for (const e of req.events) {
        fake.events.push({ ...e, source, sequence: BigInt(fake.events.length + 1) })
      }
      return { recorded: req.events.length, duplicates: 0 }
    },
    listEvents(req) {
      if (fake.refuse !== undefined) throw new ConnectError('refused', fake.refuse)
      fake.lists.push(req)
      const matching = fake.events
        .filter(
          (e) =>
            e.tenantId === req.tenantId &&
            (!req.userId || e.actor?.id === req.userId || e.onBehalfOf === req.userId) &&
            e.action.startsWith(req.actionPrefix),
        )
        .reverse()
      const start = req.pageToken ? Number(req.pageToken) : 0
      const page = matching.slice(start, start + req.pageSize)
      const more = start + req.pageSize < matching.length
      return { events: page, nextPageToken: more ? String(start + req.pageSize) : '' }
    },
    verifyChain(req) {
      if (fake.refuse !== undefined) throw new ConnectError('refused', fake.refuse)
      const n = fake.events.filter((e) => e.tenantId === req.tenantId).length
      return fake.broken
        ? { intact: false, events: BigInt(n), firstBrokenSequence: 2n, headHash: new Uint8Array() }
        : { intact: true, events: BigInt(n), headHash: new Uint8Array([0xab, 0xcd]) }
    },
  })
}

let db: TestDatabase
let server: http2.Http2SecureServer
const connections = new Set<http2.ServerHttp2Session>()
let sessions: typeof import('@/server/auth/session')
let access: typeof import('@/server/access')
let members: typeof import('@/server/members')
let trail: typeof import('@/server/audit-trail')
let audit: typeof import('@/server/audit')
let runAction: typeof import('@/server/action').runAction
let accounts: typeof import('@/server/store/accounts')
let ws: typeof import('@/server/store/workspaces')
let ids: typeof import('@/server/ids')
let withTx: typeof import('@/server/db/db').withTx
let Problem: typeof import('@/server/problem').Problem

let ana: string
let bob: string
let acme: string
let side: string

beforeAll(async () => {
  db = await startPostgres()
  const pki = makePki()
  const adapter = connectNodeAdapter({ routes })
  server = http2.createSecureServer(
    { cert: pki.server.cert, key: pki.server.key, ca: pki.ca, requestCert: true, rejectUnauthorized: true },
    (req, res) => {
      // Hand the verified client identity to the handler, as the real service takes it from mTLS.
      req.headers['x-peer'] = (req.socket as TLSSocket)
        .getPeerCertificate()
        .subjectaltname?.replace('URI:', '')
      adapter(req, res)
    },
  )
  server.on('session', (s) => {
    connections.add(s)
    s.on('close', () => connections.delete(s))
  })
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve))
  Object.assign(process.env, {
    DASHBOARD_ORIGIN: 'http://localhost:3000',
    DASHBOARD_DATABASE_URL: db.url,
    DASHBOARD_TLS_CA: join(pki.dir, 'ca.pem'),
    DASHBOARD_TLS_CERT: join(pki.dir, 'client.pem'),
    DASHBOARD_TLS_KEY: join(pki.dir, 'client-key.pem'),
    DASHBOARD_AUDIT_ADDR: `127.0.0.1:${(server.address() as AddressInfo).port}`,
  })
  sessions = await import('@/server/auth/session')
  access = await import('@/server/access')
  members = await import('@/server/members')
  trail = await import('@/server/audit-trail')
  audit = await import('@/server/audit')
  runAction = (await import('@/server/action')).runAction
  accounts = await import('@/server/store/accounts')
  ws = await import('@/server/store/workspaces')
  ids = await import('@/server/ids')
  withTx = (await import('@/server/db/db')).withTx
  Problem = (await import('@/server/problem')).Problem

  const person = async (name: string) => {
    const userId = ids.uuidv7()
    await accounts.createUser(db.pool, { userId, displayName: name, webauthnUserId: randomBytes(32) })
    return userId
  }
  ana = await person('Ana')
  bob = await person('Bob')
  acme = ids.uuidv7()
  side = ids.uuidv7()
  await withTx(db.pool, async (tx) => {
    await ws.createWorkspace(tx, { workspaceId: acme, name: 'Acme', ownerId: ana })
    await ws.createWorkspace(tx, { workspaceId: side, name: 'Side project', ownerId: ana })
  })
  await db.pool.query("INSERT INTO memberships (workspace_id, user_id, role) VALUES ($1, $2, 'member')", [
    acme,
    bob,
  ])
})

afterAll(async () => {
  for (const c of connections) c.destroy()
  await new Promise<void>((resolve) => server.close(() => resolve()))
  await (globalThis as { __jarvisDashboardPool?: pg.Pool }).__jarvisDashboardPool?.end()
  await stopPostgres(db)
})

beforeEach(() => {
  browser.cookies.clear()
  fake.events = []
  fake.lists = []
  fake.refuse = undefined
  fake.broken = false
})

async function as(userId: string, workspaceId = acme) {
  browser.cookies.clear()
  await sessions.startSession(userId, false)
  return access.actionWorkspace(workspaceId)
}

/** What reached the audit service. */
async function recorded(): Promise<Event[]> {
  expect(await audit.recorder().flush()).toBe(true)
  return fake.events
}

function stored(e: MessageInitShape<typeof EventSchema>): Event {
  return create(EventSchema, {
    eventId: ids.uuidv7(),
    tenantId: acme,
    occurTime: timestampFromDate(new Date()),
    outcome: Outcome.SUCCESS,
    source: 'spiffe://jarvis.local/orchestrator',
    sequence: BigInt(fake.events.length + 1),
    ...e,
  })
}

describe('recording', () => {
  it('records what owners do, as dashboard-api, without secrets', async () => {
    const owner = await as(ana)
    const invitation = await members.createInvitation(owner, 'member')
    const [invited] = await recorded()
    expect(invited).toMatchObject({
      tenantId: acme,
      actor: { kind: ActorKind.USER, id: ana },
      action: 'workspace.member_invited',
      targetType: 'invitation',
      outcome: Outcome.SUCCESS,
      details: { role: 'member' },
      source: 'spiffe://jarvis.local/dashboard-api',
    })
    expect(ids.isUuid(invited!.targetId)).toBe(true)
    // The link's token is the secret: it never reaches the trail.
    const token = new URL(invitation.url).pathname.split('/').pop()!
    expect(JSON.stringify(invited, (_, v: unknown) => (typeof v === 'bigint' ? String(v) : v))).not.toContain(
      token,
    )

    await members.revokeInvitation(owner, invited!.targetId)
    await members.changeRole(owner, bob, 'owner')
    await members.changeRole(owner, bob, 'member')
    const created = await members.createWorkspace(await sessions.actionSession(), 'Third')
    const actions = (await recorded()).map((e) => [e.action, e.targetId, e.details.role ?? e.details.name])
    expect(actions.slice(1)).toEqual([
      ['workspace.invitation_revoked', invited!.targetId, undefined],
      ['workspace.member_role_changed', bob, 'owner'],
      ['workspace.member_role_changed', bob, 'member'],
      ['workspace.created', created, 'Third'],
    ])
    expect(fake.events.at(-1)!.tenantId).toBe(created)
  })

  it('records a member trying what only owners may do, with what they tried', async () => {
    await as(bob)
    const result = await runAction('keys.revoke', () => access.actionWorkspace(acme, 'owner'))
    expect(result).toMatchObject({ ok: false, code: 'forbidden' })
    const refused = await members
      .removeMember(await access.actionWorkspace(acme), ana)
      .catch((error: unknown) => error)
    expect(refused).toBeInstanceOf(Problem)

    const events = await recorded()
    expect(events.map((e) => [e.action, e.outcome, e.reason, e.details.attempted])).toEqual([
      ['workspace.access_denied', Outcome.DENIED, 'owner_required', 'keys.revoke'],
      ['workspace.access_denied', Outcome.DENIED, 'owner_required', undefined],
    ])
    expect(events.every((e) => e.actor?.id === bob && e.tenantId === acme)).toBe(true)
  })

  it('records account events in every workspace of the user', async () => {
    await as(ana)
    await sessions.endOtherSessions(await sessions.actionSession())
    await sessions.endSession()
    const events = await recorded()
    const theirs = (await ws.listWorkspaces(db.pool, ana)).map((w) => w.workspaceId)
    expect(theirs).toEqual(expect.arrayContaining([acme, side]))
    expect(events.map((e) => [e.action, e.tenantId]).sort()).toEqual(
      theirs
        .flatMap((w) => [
          ['account.signed_out', w],
          ['account.signed_out_elsewhere', w],
        ])
        .sort(),
    )
    expect(events.some((e) => e.actor?.id === bob || e.tenantId === ids.uuidv7())).toBe(false)
  })

  it('holds events while the audit service is down, and delivers them after', async () => {
    fake.refuse = Code.Unavailable
    const owner = await as(ana)
    await members.createInvitation(owner, 'owner') // the action itself succeeds
    expect(await audit.recorder().flush()).toBe(false)
    expect(audit.recorder().pending).toBe(1)
    fake.refuse = undefined
    expect((await recorded()).map((e) => e.action)).toEqual(['workspace.member_invited'])
  })
})

describe('reading the trail', () => {
  it('shows owners everything and members their own, with names', async () => {
    fake.events.push(
      stored({
        actor: { kind: ActorKind.USER, id: ana },
        action: 'key.stored',
        details: { provider: 'openai' },
      }),
      stored({
        actor: { kind: ActorKind.ASSISTANT, id: 'jarvis' },
        onBehalfOf: bob,
        action: 'tool.called',
        details: { tool: 'search', integration: 'Tracker' },
      }),
      stored({
        actor: { kind: ActorKind.DEVICE, id: 'app-session:0199e2e0' },
        onBehalfOf: bob,
        action: 'device.paired',
        source: 'spiffe://jarvis.local/app-api',
      }),
      stored({
        actor: { kind: ActorKind.SERVICE, id: 'voice-gateway' },
        action: 'key.read',
        outcome: Outcome.DENIED,
        reason: 'permission_denied',
        source: 'spiffe://jarvis.local/vault',
      }),
      stored({ tenantId: side, actor: { kind: ActorKind.USER, id: ana }, action: 'workspace.created' }),
    )

    const owner = await as(ana)
    const all = await trail.listTrail(owner, {})
    expect(fake.lists.at(-1)).toMatchObject({ tenantId: acme, userId: '', actionPrefix: '', pageSize: 50 })
    expect(all.events.map((e) => [e.actor, e.onBehalfOf, e.action, e.outcome, e.source])).toEqual([
      ['Voice service', null, 'key.read', 'denied', 'Key vault'],
      ['A paired phone', 'Bob', 'device.paired', 'success', 'App service'],
      ['Jarvis', 'Bob', 'tool.called', 'success', 'Orchestrator'],
      ['Ana', null, 'key.stored', 'success', 'Orchestrator'],
    ])
    expect(all.events[2]!.details).toEqual([
      ['integration', 'Tracker'],
      ['tool', 'search'],
    ])

    const bobs = await trail.listTrail(owner, { person: bob, category: 'device' })
    expect(fake.lists.at(-1)).toMatchObject({ userId: bob, actionPrefix: 'device.' })
    expect(bobs.events.map((e) => e.action)).toEqual(['device.paired'])

    // A member sees only their own, whatever the URL asks for.
    const member = await as(bob)
    const own = await trail.listTrail(member, { person: ana })
    expect(fake.lists.at(-1)).toMatchObject({ userId: bob })
    expect(own.events.map((e) => e.action)).toEqual(['device.paired', 'tool.called'])
  })

  it('pages through older entries', async () => {
    for (let i = 0; i < 60; i++) {
      fake.events.push(stored({ actor: { kind: ActorKind.USER, id: ana }, action: 'account.signed_in' }))
    }
    const owner = await as(ana)
    const first = await trail.listTrail(owner, {})
    expect(first.events).toHaveLength(50)
    expect(first.nextPage).toBe('50')
    const second = await trail.listTrail(owner, { page: first.nextPage! })
    expect(second.events).toHaveLength(10)
    expect(second.nextPage).toBeNull()
    expect(second.events.at(-1)!.sequence).toBe('1')
  })

  it('ignores filters that are not valid', () => {
    expect(
      trail.parseTrailFilter({ category: 'secrets', person: 'not-a-uuid', page: '../x', extra: 'y' }),
    ).toEqual({})
    expect(trail.parseTrailFilter({ category: ['key', 'device'], page: 'eyJ0Ijo' })).toEqual({
      category: 'key',
      page: 'eyJ0Ijo',
    })
  })

  it('verifies the chain for owners, and says when it is broken', async () => {
    fake.events.push(stored({ actor: { kind: ActorKind.USER, id: ana }, action: 'account.signed_in' }))
    const owner = await as(ana)
    expect(await trail.verifyTrail(owner)).toEqual({
      intact: true,
      events: '1',
      firstBrokenSequence: null,
      headHash: 'abcd',
    })
    fake.broken = true
    expect(await trail.verifyTrail(owner)).toMatchObject({ intact: false, firstBrokenSequence: '2' })
  })

  it('says when the trail cannot be reached', async () => {
    const owner = await as(ana)
    fake.refuse = Code.Unavailable
    const down = await trail.listTrail(owner, {}).catch((error: unknown) => error)
    expect(down).toBeInstanceOf(Problem)
    expect((down as InstanceType<typeof Problem>).code).toBe('unavailable')
    fake.refuse = Code.PermissionDenied
    const refused = await trail.verifyTrail(owner).catch((error: unknown) => error)
    expect((refused as Error).message).toContain('refused the dashboard')
  })
})
