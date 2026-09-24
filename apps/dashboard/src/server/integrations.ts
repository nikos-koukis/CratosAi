import 'server-only'

import { timestampDate } from '@bufbuild/protobuf/wkt'
import { Code, ConnectError } from '@connectrpc/connect'
import { AuthKind, IntegrationStatus, type Integration } from '@jarvis/proto/jarvis/mcp/v1/mcp_pb'
import { z } from 'zod'

import type { AuthorizationOutcome, CatalogServerView, IntegrationView, ToolsView } from '@/lib/types'

import type { Access } from './access'
import { nameSchema } from './auth/passkeys'
import type { Session } from './auth/session'
import { errorReason, mcpRouter, serviceProblem, type Reasons } from './grpc/clients'
import { sha256 } from './ids'
import { log } from './log'
import { Problem } from './problem'
import { db } from './runtime'
import { saveAuthorization, takeAuthorization } from './store/integrations'
import { getMembership } from './store/workspaces'

// A user's connections to MCP servers (Jira, Linear, Notion, GitHub, ...),
// kept by the MCP router. They are personal: every call names the signed-in
// user, and nobody else in the workspace sees or uses them.

const ROUTER = 'The integration service'
const DOMAIN = 'mcp.jarvis'
/** The router's authorization URLs are valid this long. */
const AUTHORIZATION_TTL_MS = 10 * 60_000

const REASONS: Reasons = {
  domain: DOMAIN,
  problems: {
    ERROR_REASON_SERVER_NOT_ALLOWED: (message) =>
      new Problem('invalid', `Jarvis connects only to public https MCP servers (${message}).`),
    ERROR_REASON_CATALOG_NOT_CONFIGURED: () =>
      new Problem(
        'unavailable',
        'This server needs to be set up first by whoever runs Jarvis (OAuth app credentials).',
      ),
    ERROR_REASON_AUTHORIZATION_FAILED: (message) =>
      new Problem('conflict', `The server did not accept the connection: ${message}`),
    ERROR_REASON_INTEGRATION_NOT_FOUND: () => new Problem('not_found', 'No such connection.'),
  },
}

const iso = (t: Parameters<typeof timestampDate>[0] | undefined) => (t ? timestampDate(t).toISOString() : '')

const STATUS: Record<IntegrationStatus, IntegrationView['status']> = {
  [IntegrationStatus.UNSPECIFIED]: 'pending',
  [IntegrationStatus.PENDING_AUTHORIZATION]: 'pending',
  [IntegrationStatus.CONNECTED]: 'connected',
  [IntegrationStatus.NEEDS_REAUTHORIZATION]: 'needs_reauthorization',
}

function view(i: Integration): IntegrationView {
  return {
    integrationId: i.integrationId,
    name: i.displayName,
    serverUrl: i.serverUrl,
    catalogSlug: i.catalogSlug || null,
    auth: i.auth === AuthKind.BEARER_TOKEN ? 'token' : 'oauth',
    status: STATUS[i.status],
    statusDetail: i.statusDetail,
    createTime: iso(i.createTime),
  }
}

/** The servers anyone can connect (the router's catalog). */
export async function listCatalog(): Promise<CatalogServerView[]> {
  try {
    const { servers } = await mcpRouter().listCatalog({})
    return servers.map((s) => ({
      slug: s.slug,
      name: s.name,
      auth: s.auth === AuthKind.BEARER_TOKEN ? 'token' : 'oauth',
      available: s.available,
      notes: s.notes,
    }))
  } catch (error) {
    serviceProblem(error, ROUTER, REASONS)
  }
}

const owner = (access: Access) => ({
  tenantId: access.workspace.workspaceId,
  userId: access.session.userId,
})

export async function listIntegrations(access: Access): Promise<IntegrationView[]> {
  try {
    const { integrations } = await mcpRouter().listIntegrations(owner(access))
    return integrations.map(view)
  } catch (error) {
    serviceProblem(error, ROUTER, REASONS)
  }
}

/** The tools of the user's connected servers (cached by the router for minutes). */
export async function listTools(access: Access): Promise<ToolsView> {
  try {
    const { tools, unavailable } = await mcpRouter().listTools({ ...owner(access), refresh: false })
    return {
      tools: tools.map((t) => ({
        integrationId: t.integrationId,
        name: t.name,
        title: t.title,
        description: t.description,
        readOnly: t.annotations?.readOnly ?? false,
      })),
      unavailable: unavailable.map((u) => ({ integrationId: u.integrationId, message: u.message })),
    }
  } catch (error) {
    serviceProblem(error, ROUTER, REASONS)
  }
}

/**
 * Remembers that this user started an authorization, from the `state` of the
 * URL the router returned, and checks the URL before the browser goes there.
 */
async function bind(access: Access, integrationId: string, authorizationUrl: string): Promise<string> {
  let url: URL | undefined
  try {
    url = new URL(authorizationUrl)
  } catch {
    url = undefined
  }
  const loopback = url && ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname)
  const state = url?.searchParams.get('state')
  if (!url || !(url.protocol === 'https:' || (url.protocol === 'http:' && loopback)) || !state) {
    log.error({ integrationId }, 'the router returned an unusable authorization URL')
    throw new Problem('unavailable', `${ROUTER} returned an invalid sign-in link.`)
  }
  await saveAuthorization(db(), {
    stateHash: sha256(state),
    userId: access.session.userId,
    workspaceId: access.workspace.workspaceId,
    integrationId,
    ttlMs: AUTHORIZATION_TTL_MS,
  })
  return url.toString()
}

const printable = /^[\x21-\x7e]+$/

export const connectSchema = z
  .object({
    slug: z
      .string()
      .regex(/^[a-z0-9-]{1,64}$/)
      .optional(),
    url: z.url({ error: 'Enter the server’s https URL.' }).max(2048).optional(),
    name: nameSchema('Name the connection.').optional(),
    token: z.string().trim().max(8192).regex(printable, 'A token has no spaces.').optional(),
  })
  .refine((v) => Boolean(v.slug) !== Boolean(v.url), 'Choose a server.')

/**
 * Connects a server for the user. OAuth servers answer with the URL to send
 * the browser to; token servers are connected at once.
 */
export async function connect(
  access: Access,
  input: z.infer<typeof connectSchema>,
): Promise<{ authorizationUrl: string | null; name: string }> {
  const token = input.token ? Buffer.from(input.token, 'utf8') : undefined
  try {
    const response = await mcpRouter().createIntegration({
      ...owner(access),
      server: input.slug
        ? { case: 'catalogSlug', value: input.slug }
        : { case: 'serverUrl', value: input.url! },
      displayName: input.name ?? '',
      bearerToken: token,
    })
    const integration = response.integration
    if (!integration) throw new Error('CreateIntegration returned no integration')
    log.info(
      {
        userId: access.session.userId,
        workspaceId: access.workspace.workspaceId,
        integrationId: integration.integrationId,
        server: input.slug ?? 'custom',
      },
      'integration created',
    )
    return {
      name: integration.displayName,
      authorizationUrl: response.authorizationUrl
        ? await bind(access, integration.integrationId, response.authorizationUrl)
        : null,
    }
  } catch (error) {
    if (error instanceof Problem) throw error
    return serviceProblem(error, ROUTER, REASONS)
  } finally {
    token?.fill(0)
  }
}

/** A new authorization for a connection whose sign-in stopped working. */
export async function reconnect(access: Access, integrationId: string): Promise<string> {
  let authorizationUrl: string
  try {
    ;({ authorizationUrl } = await mcpRouter().reauthorizeIntegration({ ...owner(access), integrationId }))
  } catch (error) {
    serviceProblem(error, ROUTER, REASONS)
  }
  return bind(access, integrationId, authorizationUrl)
}

/** Disconnects a server; the router destroys its stored tokens. */
export async function disconnect(access: Access, integrationId: string): Promise<void> {
  try {
    await mcpRouter().deleteIntegration({ ...owner(access), integrationId })
    log.info(
      { userId: access.session.userId, workspaceId: access.workspace.workspaceId, integrationId },
      'integration deleted',
    )
  } catch (error) {
    serviceProblem(error, ROUTER, REASONS)
  }
}

export type Callback = { state: string; code: string; iss: string; error: string }

/**
 * Finishes an authorization when the browser comes back from the server.
 * Only the user who started it can finish it, and only while they are still
 * in its workspace; anything else is not passed to the router at all.
 */
export async function finishAuthorization(
  session: Session,
  callback: Callback,
): Promise<{ workspaceId: string | undefined; outcome: AuthorizationOutcome }> {
  const started = callback.state
    ? await takeAuthorization(db(), sha256(callback.state), session.userId)
    : undefined
  if (!started) {
    log.warn({ userId: session.userId }, 'an authorization callback that this user did not start')
    return { workspaceId: undefined, outcome: 'expired' }
  }
  const { workspaceId, integrationId } = started
  if (!(await getMembership(db(), workspaceId, session.userId)))
    return { workspaceId: undefined, outcome: 'expired' }

  try {
    const { integration } = await mcpRouter().completeAuthorization(callback)
    if (integration?.integrationId !== integrationId || integration.userId !== session.userId) {
      // The router bound the state to another integration: never expected.
      log.error({ userId: session.userId, integrationId }, 'the router completed a different integration')
      return { workspaceId, outcome: 'failed' }
    }
    log.info({ userId: session.userId, workspaceId, integrationId }, 'integration connected')
    return { workspaceId, outcome: 'connected' }
  } catch (error) {
    const e = ConnectError.from(error)
    const refused =
      e.code === Code.FailedPrecondition && errorReason(e, DOMAIN) === 'ERROR_REASON_AUTHORIZATION_FAILED'
    log.warn(
      { userId: session.userId, integrationId, code: Code[e.code], denied: Boolean(callback.error) },
      'authorization did not complete',
    )
    if (refused) return { workspaceId, outcome: callback.error ? 'denied' : 'failed' }
    if (e.code === Code.Unavailable || e.code === Code.DeadlineExceeded)
      return { workspaceId, outcome: 'failed' }
    throw error
  }
}
