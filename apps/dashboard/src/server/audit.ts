import 'server-only'

import { create } from '@bufbuild/protobuf'
import { timestampFromDate } from '@bufbuild/protobuf/wkt'
import { Code, ConnectError } from '@connectrpc/connect'
import {
  ActorKind,
  AuditService,
  EventSchema,
  Outcome,
  type Event,
} from '@jarvis/proto/jarvis/audit/v1/audit_pb'

import { config } from './config'
import { grpcClient } from './grpc/clients'
import { uuidv7 } from './ids'
import { log } from './log'
import { db } from './runtime'
import { listWorkspaces } from './store/workspaces'

// What people do in the dashboard, for the workspace's audit trail (the
// audit service). Recording never slows down or fails what it records: events
// wait in a bounded queue, go out in batches, and are retried while the audit
// service is unreachable. An event that cannot be delivered is logged
// ("audit event not delivered"), never dropped silently.

export { ActorKind, Outcome }

/** One audited action. Never put secrets (keys, tokens, codes) in it. */
export type AuditEntry = {
  tenantId: string
  actor: { kind: ActorKind; id: string }
  action: string
  onBehalfOf?: string
  targetType?: string
  targetId?: string
  /** Success when omitted. */
  outcome?: Outcome
  reason?: string
  details?: Record<string, string>
}

/** A person, by their user id. */
export const person = (userId: string) => ({ kind: ActorKind.USER, id: userId })

export type RecorderOptions = {
  queueSize?: number
  batchSize?: number
  flushMs?: number
  maxBackoffMs?: number
}

/** Delivers events through `send` (the audit service's Record) in the background. */
export class AuditRecorder {
  #queue: Event[] = []
  #timer: NodeJS.Timeout | undefined
  #backingOff = false
  #backoffMs = 1_000
  #dropped = 0
  // Sends run one at a time, in order.
  #chain: Promise<boolean> = Promise.resolve(true)
  readonly #opts: Required<RecorderOptions>

  constructor(
    private readonly send: (events: Event[]) => Promise<void>,
    options: RecorderOptions = {},
  ) {
    this.#opts = { queueSize: 10_000, batchSize: 200, flushMs: 500, maxBackoffMs: 30_000, ...options }
  }

  /** Queues an event; never blocks and never throws. */
  record(entry: AuditEntry): void {
    const event = create(EventSchema, {
      eventId: uuidv7(),
      tenantId: entry.tenantId,
      occurTime: timestampFromDate(new Date()),
      actor: entry.actor,
      onBehalfOf: entry.onBehalfOf ?? '',
      action: entry.action,
      targetType: entry.targetType ?? '',
      targetId: entry.targetId ?? '',
      outcome: entry.outcome ?? Outcome.SUCCESS,
      reason: entry.reason ?? '',
      details: entry.details ?? {},
    })
    if (this.#queue.length >= this.#opts.queueSize) {
      this.#undelivered(event, 'the audit queue is full')
      return
    }
    this.#queue.push(event)
    this.#schedule(this.#queue.length >= this.#opts.batchSize ? 0 : this.#opts.flushMs)
  }

  /** Events not delivered: queue full, or refused as malformed. */
  get dropped(): number {
    return this.#dropped
  }

  /** Events waiting to be sent. */
  get pending(): number {
    return this.#queue.length
  }

  /** Sends what is queued now; whether the queue was emptied (what failed stays queued). */
  flush(): Promise<boolean> {
    clearTimeout(this.#timer)
    this.#timer = undefined
    this.#backingOff = false
    return this.#run()
  }

  /** Logs whatever is still queued, when the process exits. */
  abandon(why: string): void {
    for (const event of this.#queue.splice(0)) this.#undelivered(event, why)
  }

  #schedule(ms: number): void {
    if (this.#backingOff) return // the retry sends it
    if (this.#timer !== undefined) {
      if (ms > 0) return
      clearTimeout(this.#timer)
    }
    this.#timer = setTimeout(() => {
      this.#timer = undefined
      void this.#run()
    }, ms)
    this.#timer.unref() // never keeps the process alive
  }

  #run(): Promise<boolean> {
    this.#chain = this.#chain.then(() => this.#drain())
    return this.#chain
  }

  async #drain(): Promise<boolean> {
    while (this.#queue.length > 0) {
      const batch = this.#queue.slice(0, this.#opts.batchSize)
      try {
        await this.#deliver(batch)
      } catch (error) {
        log.warn(
          { err: ConnectError.from(error).message, events: this.#queue.length, backoffMs: this.#backoffMs },
          'cannot record audit events; retrying',
        )
        this.#backingOff = true
        clearTimeout(this.#timer)
        this.#timer = setTimeout(() => {
          this.#timer = undefined
          this.#backingOff = false
          void this.#run()
        }, this.#backoffMs)
        this.#timer.unref()
        this.#backoffMs = Math.min(this.#backoffMs * 2, this.#opts.maxBackoffMs)
        return false
      }
      this.#queue.splice(0, batch.length)
      this.#backoffMs = 1_000
    }
    return true
  }

  /** A batch refused as malformed goes again one event at a time, so one bad event loses no others. */
  async #deliver(batch: Event[]): Promise<void> {
    try {
      await this.send(batch)
      return
    } catch (error) {
      if (ConnectError.from(error).code !== Code.InvalidArgument) throw error
    }
    for (const event of batch) {
      try {
        await this.send([event])
      } catch (error) {
        const e = ConnectError.from(error)
        if (e.code !== Code.InvalidArgument) throw error
        log.error({ err: e.rawMessage }, 'the audit service refused an event (a bug in the dashboard)')
        this.#undelivered(event, 'refused as malformed')
      }
    }
  }

  #undelivered(e: Event, why: string): void {
    this.#dropped++
    log.warn(
      {
        why,
        eventId: e.eventId,
        tenantId: e.tenantId,
        action: e.action,
        actorKind: ActorKind[e.actor?.kind ?? ActorKind.UNSPECIFIED],
        actorId: e.actor?.id,
        onBehalfOf: e.onBehalfOf,
        targetType: e.targetType,
        targetId: e.targetId,
        outcome: Outcome[e.outcome],
        reason: e.reason,
        details: e.details,
      },
      'audit event not delivered',
    )
  }
}

const globals = globalThis as typeof globalThis & { __jarvisAudit?: AuditRecorder }

/** The audit service's client (dashboard-api over mTLS). */
export function auditService() {
  return grpcClient(AuditService, config().auditAddr)
}

/** This process's recorder. */
export function recorder(): AuditRecorder {
  if (!globals.__jarvisAudit) {
    const client = auditService()
    const r = new AuditRecorder(async (events) => {
      await client.record({ events })
    })
    process.once('exit', () => r.abandon('the dashboard stopped before they were sent'))
    globals.__jarvisAudit = r
  }
  return globals.__jarvisAudit
}

/** Records an event in a workspace's audit trail. */
export function audit(entry: AuditEntry): void {
  try {
    recorder().record(entry)
  } catch (error) {
    log.error({ err: error, action: entry.action }, 'audit event not recorded')
  }
}

/**
 * Records an account event (sign-in, passkeys) in the trail of every
 * workspace the user belongs to: accounts are not tied to one workspace.
 */
export async function auditAccount(
  userId: string,
  entry: Omit<AuditEntry, 'tenantId' | 'actor'>,
): Promise<void> {
  try {
    for (const w of await listWorkspaces(db(), userId)) {
      audit({ ...entry, tenantId: w.workspaceId, actor: person(userId) })
    }
  } catch (error) {
    log.error({ err: error, userId, action: entry.action }, 'audit event not recorded')
  }
}

/** A new workspace, in its own trail. */
export function auditWorkspaceCreated(userId: string, workspaceId: string, name: string): void {
  audit({
    tenantId: workspaceId,
    actor: person(userId),
    action: 'workspace.created',
    targetType: 'workspace',
    targetId: workspaceId,
    details: { name },
  })
}

/** Someone joined a workspace with an invitation. */
export function auditJoined(
  userId: string,
  joined: { workspaceId: string; role: string; invitationId: string },
): void {
  audit({
    tenantId: joined.workspaceId,
    actor: person(userId),
    action: 'workspace.member_joined',
    targetType: 'invitation',
    targetId: joined.invitationId,
    details: { role: joined.role },
  })
}
