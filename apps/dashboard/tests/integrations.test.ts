import { randomBytes } from 'node:crypto'
import http2 from 'node:http2'
import type { AddressInfo } from 'node:net'
import { join } from 'node:path'

import { BinaryWriter, WireType } from '@bufbuild/protobuf/wire'
import { Code, ConnectError, type ConnectRouter } from '@connectrpc/connect'
import { connectNodeAdapter } from '@connectrpc/connect-node'
import {
  AuthKind,
  IntegrationStatus,
  McpRouterService,
  type CompleteAuthorizationRequest,
} from '@jarvis/proto/jarvis/mcp/v1/mcp_pb'
import type pg from 'pg'
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest'

import { makePki } from './support/pki'
import { startPostgres, stopPostgres, type TestDatabase } from './support/postgres'

// Connecting MCP servers through the dashboard: a real PostgreSQL, a fake MCP
// router over real mTLS, and two users' sessions.

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
}))

type OutgoingDetail = NonNullable<ConstructorParameters<typeof ConnectError>[3]>[number]

/**
 * A google.rpc.ErrorInfo detail, as the Go router sends it. Encoded by hand
 * (no ErrorInfo schema here); connect-node sends such raw details as they are,
 * though its constructor's type names only schema-based ones.
 */
function errorInfo(reason: string, domain = 'mcp.jarvis'): OutgoingDetail {
  const value = new BinaryWriter()
    .tag(1, WireType.LengthDelimited)
    .string(reason)
    .tag(2, WireType.LengthDelimited)
    .string(domain)
    .finish()
  return { type: 'google.rpc.ErrorInfo', value } as unknown as OutgoingDetail
}

const router = {
  completed: [] as CompleteAuthorizationRequest[],
  created: [] as { userId: string; token: string }[],
  authorizationUrl: '',
  failCreate: undefined as ConnectError | undefined,
  integrationUser: '' as string | undefined,
}

function routes(r: ConnectRouter) {
  r.service(McpRouterService, {
    createIntegration(req) {
      if (router.failCreate) throw router.failCreate
      router.created.push({ userId: req.userId, token: Buffer.from(req.bearerToken).toString() })
      const oauth = req.bearerToken.length === 0
      return {
        integration: {
          integrationId: '0199e2e0-0000-7000-8000-00000000cafe',
          tenantId: req.tenantId,
          userId: req.userId,
          displayName: 'Tracker',
          auth: oauth ? AuthKind.OAUTH : AuthKind.BEARER_TOKEN,
          status: oauth ? IntegrationStatus.PENDING_AUTHORIZATION : IntegrationStatus.CONNECTED,
        },
        authorizationUrl: oauth ? router.authorizationUrl : '',
      }
    },
    completeAuthorization(req) {
      router.completed.push(req)
      if (req.error) {
        throw new ConnectError('the user denied access', Code.FailedPrecondition, undefined, [
          errorInfo('ERROR_REASON_AUTHORIZATION_FAILED'),
        ])
      }
      return {
        integration: {
          integrationId: '0199e2e0-0000-7000-8000-00000000cafe',
          userId: router.integrationUser,
          status: IntegrationStatus.CONNECTED,
        },
      }
    },
  })
}

let db: TestDatabase
let server: http2.Http2SecureServer
const connections = new Set<http2.ServerHttp2Session>()
let integrations: typeof import('@/server/integrations')
let sessions: typeof import('@/server/auth/session')
let access: typeof import('@/server/access')
let accounts: typeof import('@/server/store/accounts')
let ws: typeof import('@/server/store/workspaces')
let ids: typeof import('@/server/ids')
let withTx: typeof import('@/server/db/db').withTx
let Problem: typeof import('@/server/problem').Problem

let ana: string
let bob: string
let workspaceId: string

beforeAll(async () => {
  db = await startPostgres()
  const pki = makePki()
  const adapter = connectNodeAdapter({ routes })
  server = http2.createSecureServer(
    { cert: pki.server.cert, key: pki.server.key, ca: pki.ca, requestCert: true, rejectUnauthorized: true },
    adapter,
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
    DASHBOARD_MCP_ADDR: `127.0.0.1:${(server.address() as AddressInfo).port}`,
  })
  integrations = await import('@/server/integrations')
  sessions = await import('@/server/auth/session')
  access = await import('@/server/access')
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
  workspaceId = ids.uuidv7()
  await withTx(db.pool, (tx) => ws.createWorkspace(tx, { workspaceId, name: 'Acme', ownerId: ana }))
  await db.pool.query("INSERT INTO memberships (workspace_id, user_id, role) VALUES ($1, $2, 'member')", [
    workspaceId,
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
  router.completed = []
  router.created = []
  router.failCreate = undefined
  router.authorizationUrl = `https://auth.example.com/authorize?client_id=c&state=${randomBytes(16).toString('base64url')}`
})

async function as(userId: string) {
  browser.cookies.clear()
  await sessions.startSession(userId, false)
  return { session: (await sessions.currentSession())!, access: await access.actionWorkspace(workspaceId) }
}

const callback = (url: string, extra: Partial<{ code: string; error: string }> = {}) => ({
  state: new URL(url).searchParams.get('state') ?? '',
  code: extra.code ?? 'auth-code',
  iss: 'https://auth.example.com',
  error: extra.error ?? '',
})

async function problem(promise: Promise<unknown>) {
  try {
    await promise
  } catch (error) {
    if (error instanceof Problem) return error
    throw error
  }
  throw new Error('expected a Problem')
}

describe('connecting with OAuth', () => {
  it('only finishes for the user who started it, once', async () => {
    const asAna = await as(ana)
    const { authorizationUrl } = await integrations.connect(asAna.access, { slug: 'linear' })
    expect(authorizationUrl).toBe(router.authorizationUrl)
    router.integrationUser = ana

    // Bob opens Ana's callback link: nothing reaches the router.
    const asBob = await as(bob)
    expect(await integrations.finishAuthorization(asBob.session, callback(authorizationUrl!))).toEqual({
      workspaceId: undefined,
      outcome: 'expired',
    })
    expect(router.completed).toHaveLength(0)

    // Ana finishes it, exactly once.
    const again = await as(ana)
    expect(await integrations.finishAuthorization(again.session, callback(authorizationUrl!))).toEqual({
      workspaceId,
      outcome: 'connected',
    })
    expect(router.completed.map((c) => [c.code, c.iss])).toEqual([['auth-code', 'https://auth.example.com']])
    expect((await integrations.finishAuthorization(again.session, callback(authorizationUrl!))).outcome).toBe(
      'expired',
    )
    expect(router.completed).toHaveLength(1)
  })

  it('reports a refusal at the server as denied', async () => {
    const asAna = await as(ana)
    const { authorizationUrl } = await integrations.connect(asAna.access, { slug: 'linear' })
    const result = await integrations.finishAuthorization(
      asAna.session,
      callback(authorizationUrl!, { code: '', error: 'access_denied' }),
    )
    expect(result).toEqual({ workspaceId, outcome: 'denied' })
    expect(router.completed[0]?.error).toBe('access_denied')
  })

  it('stops if the user left the workspace meanwhile', async () => {
    const asBob = await as(bob)
    const { authorizationUrl } = await integrations.connect(asBob.access, { slug: 'linear' })
    await db.pool.query('DELETE FROM memberships WHERE workspace_id = $1 AND user_id = $2', [
      workspaceId,
      bob,
    ])
    try {
      expect(
        (await integrations.finishAuthorization(asBob.session, callback(authorizationUrl!))).outcome,
      ).toBe('expired')
      expect(router.completed).toHaveLength(0)
    } finally {
      await db.pool.query("INSERT INTO memberships (workspace_id, user_id, role) VALUES ($1, $2, 'member')", [
        workspaceId,
        bob,
      ])
    }
  })

  it('refuses a completion the router ties to someone else', async () => {
    const asAna = await as(ana)
    const { authorizationUrl } = await integrations.connect(asAna.access, { slug: 'linear' })
    router.integrationUser = bob
    expect((await integrations.finishAuthorization(asAna.session, callback(authorizationUrl!))).outcome).toBe(
      'failed',
    )
  })

  it('never sends the browser to an unsafe sign-in link', async () => {
    const asAna = await as(ana)
    for (const bad of [
      'http://auth.example.com/authorize?state=x',
      'javascript:alert(1)//?state=x',
      'https://auth.example.com/authorize',
    ]) {
      router.authorizationUrl = bad
      expect((await problem(integrations.connect(asAna.access, { slug: 'linear' }))).code).toBe('unavailable')
    }
    // Loopback http is the development fake server, and allowed.
    router.authorizationUrl = 'http://127.0.0.1:8931/as/authorize?state=dev'
    expect((await integrations.connect(asAna.access, { slug: 'linear' })).authorizationUrl).toContain(
      '127.0.0.1',
    )
  })
})

describe('connecting with a token', () => {
  it('connects at once, for the signed-in user', async () => {
    const asBob = await as(bob)
    expect(await integrations.connect(asBob.access, { slug: 'github', token: 'ghp_e2e_0123456789' })).toEqual(
      {
        name: 'Tracker',
        authorizationUrl: null,
      },
    )
    expect(router.created).toEqual([{ userId: bob, token: 'ghp_e2e_0123456789' }])
  })
})

describe('router errors', () => {
  it('become messages by their reason, not their status code', async () => {
    const asAna = await as(ana)
    router.failCreate = new ConnectError('resolves to a private address', Code.PermissionDenied, undefined, [
      errorInfo('ERROR_REASON_SERVER_NOT_ALLOWED'),
    ])
    const notAllowed = await problem(integrations.connect(asAna.access, { url: 'https://10.0.0.1/mcp' }))
    expect(notAllowed.code).toBe('invalid')
    expect(notAllowed.message).toContain('public https MCP servers (resolves to a private address)')

    router.failCreate = new ConnectError('needs credentials', Code.FailedPrecondition, undefined, [
      errorInfo('ERROR_REASON_CATALOG_NOT_CONFIGURED'),
    ])
    expect((await problem(integrations.connect(asAna.access, { slug: 'slack' }))).message).toContain(
      'set up first',
    )

    // The same status code without the router's reason is the policy refusing the dashboard.
    router.failCreate = new ConnectError('denied', Code.PermissionDenied)
    expect((await problem(integrations.connect(asAna.access, { slug: 'linear' }))).message).toContain(
      'refused the dashboard',
    )
    // A reason from another service's domain does not count.
    router.failCreate = new ConnectError('x', Code.PermissionDenied, undefined, [
      errorInfo('ERROR_REASON_SERVER_NOT_ALLOWED', 'vault.jarvis'),
    ])
    expect((await problem(integrations.connect(asAna.access, { slug: 'linear' }))).message).toContain(
      'refused the dashboard',
    )
  })

  it('check the input first', () => {
    expect(integrations.connectSchema.safeParse({}).success).toBe(false)
    expect(
      integrations.connectSchema.safeParse({ slug: 'linear', url: 'https://x.example/mcp' }).success,
    ).toBe(false)
    expect(integrations.connectSchema.safeParse({ url: 'not a url' }).success).toBe(false)
    expect(integrations.connectSchema.safeParse({ slug: 'github', token: 'has space' }).success).toBe(false)
    expect(
      integrations.connectSchema.safeParse({ url: 'https://mcp.example.com/mcp', name: 'Tracker' }).success,
    ).toBe(true)
  })
})
