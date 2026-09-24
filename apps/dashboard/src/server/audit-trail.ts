import 'server-only'

import { timestampDate } from '@bufbuild/protobuf/wkt'
import { ActorKind, Outcome, type Event } from '@jarvis/proto/jarvis/audit/v1/audit_pb'
import { z } from 'zod'

import { AUDIT_CATEGORIES, serviceLabel } from '@/lib/audit'
import type { AuditEventView, AuditPageView, ChainView } from '@/lib/types'

import type { Access } from './access'
import { auditService } from './audit'
import { serviceProblem } from './grpc/clients'
import { isUuid } from './ids'
import { log } from './log'
import { db } from './runtime'
import { displayNames } from './store/accounts'

// Reading a workspace's audit trail. Owners see everything that happened in
// the workspace; members see what they did, and what was done for them
// (by Jarvis, their phones and computers, and the services).

const AUDIT = 'The audit trail'
const PAGE_SIZE = 50

export const trailFilterSchema = z.object({
  category: z
    .enum(AUDIT_CATEGORIES.map((c) => c.id) as [string, ...string[]])
    .optional()
    .catch(undefined),
  /** Owners only: one person's events. */
  person: z.uuid().optional().catch(undefined),
  page: z
    .string()
    .regex(/^[A-Za-z0-9_=-]{1,512}$/)
    .optional()
    .catch(undefined),
})

export type TrailFilter = z.infer<typeof trailFilterSchema>

const KINDS: Record<ActorKind, AuditEventView['actorKind']> = {
  [ActorKind.UNSPECIFIED]: 'unknown',
  [ActorKind.USER]: 'user',
  [ActorKind.ASSISTANT]: 'assistant',
  [ActorKind.DEVICE]: 'device',
  [ActorKind.SERVICE]: 'service',
}

const OUTCOMES: Partial<Record<Outcome, AuditEventView['outcome']>> = {
  [Outcome.SUCCESS]: 'success',
  [Outcome.FAILURE]: 'failure',
  [Outcome.DENIED]: 'denied',
}

/** A page of the workspace's trail, newest first. */
export async function listTrail(access: Access, filter: TrailFilter): Promise<AuditPageView> {
  const owner = access.workspace.role === 'owner'
  const prefix = AUDIT_CATEGORIES.find((c) => c.id === filter.category)?.prefix ?? ''
  let response
  try {
    response = await auditService().listEvents({
      tenantId: access.workspace.workspaceId,
      userId: owner ? (filter.person ?? '') : access.session.userId,
      actionPrefix: prefix,
      pageSize: PAGE_SIZE,
      pageToken: filter.page ?? '',
    })
  } catch (error) {
    serviceProblem(error, AUDIT)
  }
  return { events: await views(response.events), nextPage: response.nextPageToken || null }
}

/** Checks the workspace's hash chain end to end (owners only). */
export async function verifyTrail(access: Access): Promise<ChainView> {
  let response
  try {
    response = await auditService().verifyChain({ tenantId: access.workspace.workspaceId })
  } catch (error) {
    serviceProblem(error, AUDIT)
  }
  const view: ChainView = {
    intact: response.intact,
    events: response.events.toString(),
    firstBrokenSequence: response.intact ? null : response.firstBrokenSequence.toString(),
    headHash: Buffer.from(response.headHash).toString('hex'),
  }
  if (!view.intact) {
    // Someone changed the stored trail: never expected.
    log.error(
      { workspaceId: access.workspace.workspaceId, firstBrokenSequence: view.firstBrokenSequence },
      'audit chain broken',
    )
  }
  return view
}

async function views(events: Event[]): Promise<AuditEventView[]> {
  const people = new Set<string>()
  for (const e of events) {
    if (e.actor?.kind === ActorKind.USER && isUuid(e.actor.id)) people.add(e.actor.id)
    if (isUuid(e.onBehalfOf)) people.add(e.onBehalfOf)
  }
  const names = await displayNames(db(), [...people])
  const name = (id: string) => names.get(id) ?? `Unknown person (${id.slice(0, 8)}…)`

  return events.map((e) => {
    const kind = KINDS[e.actor?.kind ?? ActorKind.UNSPECIFIED] ?? 'unknown'
    const id = e.actor?.id ?? ''
    return {
      eventId: e.eventId,
      sequence: e.sequence.toString(),
      occurTime: e.occurTime ? timestampDate(e.occurTime).toISOString() : '',
      actorKind: kind,
      actor: actorLabel(kind, id, name),
      onBehalfOf: e.onBehalfOf && !(kind === 'user' && e.onBehalfOf === id) ? name(e.onBehalfOf) : null,
      action: e.action,
      targetType: e.targetType,
      targetId: e.targetId,
      outcome: OUTCOMES[e.outcome] ?? 'failure',
      reason: e.reason,
      details: Object.entries(e.details).sort(([a], [b]) => a.localeCompare(b)),
      source: serviceLabel(e.source),
    }
  })
}

function actorLabel(kind: AuditEventView['actorKind'], id: string, name: (id: string) => string): string {
  switch (kind) {
    case 'user':
      return name(id)
    case 'assistant':
      return 'Jarvis'
    case 'device':
      return id.startsWith('app-session:') ? 'A paired phone' : `Computer “${id}”`
    case 'service':
      return serviceLabel(id)
    default:
      return id || 'Unknown'
  }
}

/** For the page: a filter from the URL's search params (bad values are ignored). */
export function parseTrailFilter(params: Record<string, string | string[] | undefined>): TrailFilter {
  const one = (v: string | string[] | undefined) => (Array.isArray(v) ? v[0] : v) || undefined
  return trailFilterSchema.parse({
    category: one(params.category),
    person: one(params.person),
    page: one(params.page),
  })
}
