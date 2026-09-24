import { Code, ConnectError } from '@connectrpc/connect'
import type { Event } from '@jarvis/proto/jarvis/audit/v1/audit_pb'
import { afterEach, describe, expect, it, vi } from 'vitest'

import { ActorKind, AuditRecorder, Outcome, person } from '@/server/audit'
import { log } from '@/server/log'

// The dashboard's audit recorder against a fake Record: batching, retries
// while the audit service is down, one bad event not losing the others, and a
// bounded queue. Recording never throws and never waits.

const tenant = '0199e2e0-0000-7000-8000-00000000abcd'
const ana = '0199e2e0-0000-7000-8000-0000000000aa'

function fakeAudit() {
  const fake = {
    stored: new Map<string, Event>(),
    calls: [] as number[],
    failures: 0,
    gate: undefined as Promise<void> | undefined,
    async send(events: Event[]) {
      fake.calls.push(events.length)
      await fake.gate
      if (fake.failures > 0) {
        fake.failures--
        throw new ConnectError('down', Code.Unavailable)
      }
      if (events.some((e) => e.action === 'bad')) {
        throw new ConnectError('event 0: action is malformed', Code.InvalidArgument)
      }
      for (const e of events) fake.stored.set(e.eventId, e)
    },
  }
  return fake
}

const entry = (action = 'key.stored') => ({
  tenantId: tenant,
  actor: person(ana),
  action,
  targetType: 'provider_key',
  targetId: 'k1',
  details: { provider: 'openai' },
})

afterEach(() => {
  vi.useRealTimers()
  vi.restoreAllMocks()
})

describe('audit recorder', () => {
  it('sends events in batches, with ids and times', async () => {
    const fake = fakeAudit()
    const recorder = new AuditRecorder(fake.send, { batchSize: 10, flushMs: 5 })
    const before = Date.now()
    for (let i = 0; i < 25; i++) recorder.record(entry())
    await vi.waitFor(() => expect(fake.stored.size).toBe(25))
    expect(fake.calls.length).toBeLessThanOrEqual(4)
    expect(Math.max(...fake.calls)).toBe(10)
    for (const e of fake.stored.values()) {
      expect(e.eventId).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/)
      expect(Number(e.occurTime!.seconds) * 1000).toBeGreaterThanOrEqual(before - 1000)
      expect(e).toMatchObject({
        tenantId: tenant,
        actor: { kind: ActorKind.USER, id: ana },
        action: 'key.stored',
        outcome: Outcome.SUCCESS,
        details: { provider: 'openai' },
      })
    }
    expect(recorder.pending).toBe(0)
  })

  it('keeps retrying, with backoff, while the audit service is down', async () => {
    vi.useFakeTimers()
    const fake = fakeAudit()
    fake.failures = 2
    const warn = vi.spyOn(log, 'warn')
    const recorder = new AuditRecorder(fake.send, { flushMs: 5 })
    for (let i = 0; i < 3; i++) recorder.record(entry())

    await vi.advanceTimersByTimeAsync(5) // first attempt fails; retry in 1s
    expect(fake.calls).toHaveLength(1)
    await vi.advanceTimersByTimeAsync(999)
    expect(fake.calls).toHaveLength(1)
    await vi.advanceTimersByTimeAsync(1) // second fails; retry in 2s
    expect(fake.calls).toHaveLength(2)
    recorder.record(entry()) // waits for the retry, no extra attempt
    await vi.advanceTimersByTimeAsync(1999)
    expect(fake.calls).toHaveLength(2)
    await vi.advanceTimersByTimeAsync(1)
    expect(fake.stored.size).toBe(4)
    expect(recorder.dropped).toBe(0)
    expect(warn).toHaveBeenCalledWith(expect.anything(), 'cannot record audit events; retrying')
  })

  it('does not lose good events to a malformed one', async () => {
    const fake = fakeAudit()
    const warn = vi.spyOn(log, 'warn')
    const recorder = new AuditRecorder(fake.send, { flushMs: 60_000 })
    recorder.record(entry('key.stored'))
    recorder.record(entry('bad'))
    recorder.record(entry('key.revoked'))
    expect(await recorder.flush()).toBe(true)
    expect([...fake.stored.values()].map((e) => e.action).sort()).toEqual(['key.revoked', 'key.stored'])
    expect(recorder.dropped).toBe(1)
    expect(warn).toHaveBeenCalledWith(
      expect.objectContaining({ why: 'refused as malformed', action: 'bad', tenantId: tenant }),
      'audit event not delivered',
    )
  })

  it('logs instead of growing without bound', async () => {
    const fake = fakeAudit()
    const warn = vi.spyOn(log, 'warn')
    const recorder = new AuditRecorder(fake.send, { queueSize: 3, flushMs: 60_000 })
    for (let i = 0; i < 5; i++) recorder.record(entry())
    expect(recorder.pending).toBe(3)
    expect(recorder.dropped).toBe(2)
    expect(warn).toHaveBeenCalledWith(
      expect.objectContaining({ why: 'the audit queue is full' }),
      'audit event not delivered',
    )
    await recorder.flush()
    expect(fake.stored.size).toBe(3)
  })

  it('keeps what a flush could not send, and logs what is left at exit', async () => {
    const fake = fakeAudit()
    fake.failures = 1
    const recorder = new AuditRecorder(fake.send, { flushMs: 60_000 })
    recorder.record(entry())
    recorder.record(entry())
    expect(await recorder.flush()).toBe(false)
    expect(recorder.pending).toBe(2)
    expect(await recorder.flush()).toBe(true)
    expect(fake.stored.size).toBe(2)

    fake.failures = 100
    const warn = vi.spyOn(log, 'warn')
    recorder.record(entry('key.read'))
    await recorder.flush()
    recorder.abandon('the dashboard stopped before they were sent')
    expect(recorder.pending).toBe(0)
    expect(recorder.dropped).toBe(1)
    expect(warn).toHaveBeenCalledWith(
      expect.objectContaining({ why: 'the dashboard stopped before they were sent', action: 'key.read' }),
      'audit event not delivered',
    )
  })

  it('never sends two batches at once, and sends what arrives meanwhile', async () => {
    const fake = fakeAudit()
    let open!: () => void
    fake.gate = new Promise((resolve) => (open = resolve))
    const recorder = new AuditRecorder(fake.send, { flushMs: 1 })
    recorder.record(entry('key.stored'))
    const first = recorder.flush()
    await vi.waitFor(() => expect(fake.calls).toEqual([1])) // in flight
    recorder.record(entry('key.revoked'))
    const second = recorder.flush()
    await new Promise((resolve) => setTimeout(resolve, 20))
    expect(fake.calls).toEqual([1]) // the second waits for the first
    open()
    expect(await first).toBe(true)
    expect(await second).toBe(true)
    expect(fake.calls).toEqual([1, 1])
    expect(fake.stored.size).toBe(2)
  })

  it('never throws at the caller', () => {
    const recorder = new AuditRecorder(() => Promise.reject(new Error('boom')), { flushMs: 1 })
    expect(() => recorder.record(entry())).not.toThrow()
  })
})
