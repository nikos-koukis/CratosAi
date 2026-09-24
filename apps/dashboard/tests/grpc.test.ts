import http2 from 'node:http2'
import type { AddressInfo } from 'node:net'
import { join } from 'node:path'
import type { TLSSocket } from 'node:tls'

import { create } from '@bufbuild/protobuf'
import { timestampFromDate } from '@bufbuild/protobuf/wkt'
import { Code, ConnectError, type ConnectRouter } from '@connectrpc/connect'
import { connectNodeAdapter } from '@connectrpc/connect-node'
import { AppAdminService } from '@jarvis/proto/jarvis/app/v1/admin_pb'
import type { Provider } from '@jarvis/proto/jarvis/common/v1/provider_pb'
import {
  KeyMetadataSchema,
  KeyStatus,
  RevocationReason,
  VaultService,
  type KeyMetadata,
} from '@jarvis/proto/jarvis/vault/v1/vault_pb'
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest'

import type { Access } from '@/server/access'
import { createPairing, listDevices } from '@/server/devices'
import { addKey, listKeys, revokeKey } from '@/server/keys'
import { Problem } from '@/server/problem'

import { makePki } from './support/pki'

// Fake Vault and app API over real mTLS, so the dashboard's clients are
// tested as they run: its certificate, its request ids, its error mapping.

const tenant = '0199e2e0-0000-7000-8000-00000000abcd'
const access: Access = {
  session: {
    sessionId: 's',
    userId: '0199e2e0-0000-7000-8000-0000000000aa',
    displayName: 'Ana',
    recovered: false,
    lastSeenTime: new Date(),
  },
  workspace: { workspaceId: tenant, name: 'Acme', role: 'owner' },
}

type Seen = { rpc: string; requestId: string | null }

const fake = {
  seen: [] as Seen[],
  keys: [] as KeyMetadata[],
  secrets: new Map<string, string>(),
  refuse: undefined as Code | undefined,
}

function routes(router: ConnectRouter) {
  const note = (rpc: string, header: Headers) => {
    fake.seen.push({ rpc, requestId: header.get('x-request-id') })
    if (fake.refuse !== undefined) throw new ConnectError('refused by policy', fake.refuse)
  }
  router.service(VaultService, {
    listKeys(req, ctx) {
      note('ListKeys', ctx.requestHeader)
      return {
        keys: fake.keys.filter(
          (k) => k.tenantId === req.tenantId && (req.includeRevoked || k.status === KeyStatus.ACTIVE),
        ),
      }
    },
    createKey(req, ctx) {
      note('CreateKey', ctx.requestHeader)
      const active = fake.keys.find((k) => k.provider === req.provider && k.status === KeyStatus.ACTIVE)
      if (active && !req.replaceActive)
        throw new ConnectError('the tenant already has an active key', Code.AlreadyExists)
      if (active) active.status = KeyStatus.REVOKED
      const key = create(KeyMetadataSchema, {
        keyId: `key-${fake.keys.length}`,
        tenantId: req.tenantId,
        provider: req.provider,
        label: req.label,
        keyHint: Buffer.from(req.secret).toString('utf8').slice(-4),
        status: KeyStatus.ACTIVE,
        createTime: timestampFromDate(new Date()),
      })
      fake.secrets.set(key.keyId, Buffer.from(req.secret).toString('utf8'))
      fake.keys.push(key)
      return { key, replacedKey: active }
    },
    revokeKey(req, ctx) {
      note('RevokeKey', ctx.requestHeader)
      const key = fake.keys.find((k) => k.keyId === req.keyId && k.tenantId === req.tenantId)
      if (!key) throw new ConnectError('no such key', Code.NotFound)
      key.status = KeyStatus.REVOKED
      key.revocationReason = req.reason
      return { key }
    },
  })
  router.service(AppAdminService, {
    createPairingCode(req, ctx) {
      note('CreatePairingCode', ctx.requestHeader)
      return {
        code: '7KQ2-M9XD-4TFA',
        pairingUrl: `jarvis://pair?server=https%3A%2F%2Fapp.test&code=7KQ2-M9XD-4TFA&user=${req.userId}`,
        expireTime: timestampFromDate(new Date(Date.now() + 600_000)),
      }
    },
    listSessions(req, ctx) {
      note('ListSessions', ctx.requestHeader)
      return {
        sessions: [
          {
            sessionId: 'phone',
            deviceName: 'Ana’s iPhone',
            deviceModel: 'iPhone17,1',
            createTime: timestampFromDate(new Date(0)),
          },
        ],
      }
    },
  })
}

let server: http2.Http2SecureServer
let port = 0
const peers: string[] = []
const connections = new Set<http2.ServerHttp2Session>()

/** Stops the server, cutting the dashboard's open HTTP/2 connections. */
function stop(): Promise<void> {
  for (const c of connections) c.destroy()
  connections.clear()
  return new Promise((resolve) => server.close(() => resolve()))
}

beforeAll(async () => {
  const pki = makePki()
  const adapter = connectNodeAdapter({ routes })
  server = http2.createSecureServer(
    { cert: pki.server.cert, key: pki.server.key, ca: pki.ca, requestCert: true, rejectUnauthorized: true },
    (req, res) => {
      peers.push((req.socket as TLSSocket).getPeerCertificate().subjectaltname ?? '')
      adapter(req, res)
    },
  )
  server.on('session', (session) => {
    connections.add(session)
    session.on('close', () => connections.delete(session))
  })
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve))
  port = (server.address() as AddressInfo).port
  Object.assign(process.env, {
    DASHBOARD_ORIGIN: 'http://localhost:3000',
    DASHBOARD_DATABASE_URL: 'postgres://unused',
    DASHBOARD_TLS_CA: join(pki.dir, 'ca.pem'),
    DASHBOARD_TLS_CERT: join(pki.dir, 'client.pem'),
    DASHBOARD_TLS_KEY: join(pki.dir, 'client-key.pem'),
    DASHBOARD_VAULT_ADDR: `127.0.0.1:${port}`,
    DASHBOARD_APP_ADMIN_ADDR: `localhost:${port}`,
  })
})

afterAll(() => stop())

beforeEach(() => {
  fake.seen = []
  fake.refuse = undefined
  peers.length = 0
})

async function problem(promise: Promise<unknown>): Promise<Problem> {
  try {
    await promise
  } catch (error) {
    if (error instanceof Problem) return error
    throw error
  }
  throw new Error('expected a Problem')
}

describe('vault client', () => {
  it('stores, lists and revokes keys as dashboard-api, with request ids', async () => {
    const stored = await addKey(access, {
      provider: 'openai',
      label: 'Prod',
      secret: 'sk-e2e-0123456789abcd',
      replace: false,
    })
    expect(stored).toMatchObject({ provider: 'openai', label: 'Prod', hint: 'abcd', status: 'active' })
    expect(fake.secrets.get(stored!.keyId)).toBe('sk-e2e-0123456789abcd')

    const listed = await listKeys(access, false)
    expect(listed.map((k) => k.keyId)).toEqual([stored!.keyId])

    await revokeKey(access, { keyId: stored!.keyId, reason: 'compromised' })
    const all = await listKeys(access, true)
    expect(all[0]).toMatchObject({ status: 'revoked', revocationReason: 'compromised' })
    expect(await listKeys(access, false)).toEqual([])

    expect(peers.every((p) => p === 'URI:spiffe://jarvis.local/dashboard-api')).toBe(true)
    expect(fake.seen.map((s) => s.rpc)).toEqual([
      'CreateKey',
      'ListKeys',
      'RevokeKey',
      'ListKeys',
      'ListKeys',
    ])
    const ids = fake.seen.map((s) => s.requestId)
    expect(ids.every((id) => /^[0-9a-f-]{36}$/.test(id ?? ''))).toBe(true)
    expect(new Set(ids).size).toBe(ids.length)
  })

  it('asks before replacing an active key', async () => {
    const input = { provider: 'xai' as const, label: 'A', secret: 'xai-e2e-0123456789-aaaa', replace: false }
    await addKey(access, input)
    const conflict = await problem(
      addKey(access, { ...input, label: 'B', secret: 'xai-e2e-0123456789-bbbb' }),
    )
    expect(conflict.code).toBe('conflict')
    expect(conflict.message).toContain('active xAI key')
    const replaced = await addKey(access, {
      ...input,
      label: 'B',
      secret: 'xai-e2e-0123456789-bbbb',
      replace: true,
    })
    expect(replaced?.hint).toBe('bbbb')
    const xai = (await listKeys(access, true)).filter((k) => k.provider === 'xai')
    expect(xai.map((k) => [k.label, k.status])).toEqual([
      ['A', 'revoked'],
      ['B', 'active'],
    ])
  })

  it('turns refusals and outages into messages, not internals', async () => {
    fake.refuse = Code.PermissionDenied
    const refused = await problem(listKeys(access, true))
    expect(refused.code).toBe('unavailable')
    expect(refused.message).toContain('refused the dashboard')

    fake.refuse = Code.Unavailable
    expect((await problem(listKeys(access, true))).message).toContain('not reachable')

    fake.refuse = undefined
    expect(
      (
        await problem(
          revokeKey(access, { keyId: '0199e2e0-0000-7000-8000-000000000999', reason: 'user_requested' }),
        )
      ).code,
    ).toBe('not_found')
  })

  it('ignores providers it does not know yet', async () => {
    fake.keys.push(
      create(KeyMetadataSchema, {
        keyId: 'future',
        tenantId: tenant,
        provider: 99 as Provider,
        label: 'x',
        status: KeyStatus.ACTIVE,
      }),
    )
    expect((await listKeys(access, true)).some((k) => k.keyId === 'future')).toBe(false)
    expect(RevocationReason.ROTATED).toBe(2) // the enum the view maps
  })
})

describe('app API client', () => {
  it('issues a pairing code with a QR code, and lists the user’s phones', async () => {
    const pairing = await createPairing(access)
    expect(pairing.code).toBe('7KQ2-M9XD-4TFA')
    expect(pairing.qrDataUrl.startsWith('data:image/svg+xml;base64,')).toBe(true)
    expect(Buffer.from(pairing.qrDataUrl.split(',')[1]!, 'base64').toString()).toContain('<svg')
    expect(new Date(pairing.expireTime).getTime()).toBeGreaterThan(Date.now())

    const devices = await listDevices(access)
    expect(devices).toEqual([
      {
        sessionId: 'phone',
        deviceName: 'Ana’s iPhone',
        deviceModel: 'iPhone17,1',
        createTime: '1970-01-01T00:00:00.000Z',
        lastUseTime: null,
      },
    ])
    expect(peers).toHaveLength(2)
  })
})

describe('without the service', () => {
  it('says it is not reachable', async () => {
    await stop()
    const down = await problem(listKeys(access, true))
    expect(down.code).toBe('unavailable')
    await new Promise<void>((resolve) => server.listen(port, '127.0.0.1', resolve))
  })
})
