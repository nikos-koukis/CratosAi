import type { Metadata, Route } from 'next'
import Form from 'next/form'
import Link from 'next/link'

import { VerifyTrail } from '@/components/audit'
import { LocalTime } from '@/components/local-time'
import { Alert, Badge, buttonClass, Card, Empty, PageHeader, Select } from '@/components/ui'
import { AUDIT_CATEGORIES, describeAction, describeTarget } from '@/lib/audit'
import type { AuditEventView, AuditPageView, MemberView } from '@/lib/types'
import { requireWorkspace } from '@/server/access'
import { listTrail, parseTrailFilter } from '@/server/audit-trail'
import { listMembers } from '@/server/members'
import { Problem } from '@/server/problem'

export const metadata: Metadata = { title: 'Audit trail' }

const OUTCOME = {
  success: null,
  failure: <Badge tone="bad">Failed</Badge>,
  denied: <Badge tone="bad">Denied</Badge>,
} as const

function Entry({ event }: { event: AuditEventView }) {
  const target = describeTarget(event)
  return (
    <li className="space-y-1 py-3" data-testid="audit-event" data-action={event.action}>
      <div className="flex flex-wrap items-baseline justify-between gap-2">
        <p>
          <span className="font-medium">{event.actor}</span>
          {event.onBehalfOf && <span className="text-zinc-500"> for {event.onBehalfOf}</span>}
          {' · '}
          {describeAction(event.action)} {OUTCOME[event.outcome]}
        </p>
        <span className="text-sm text-zinc-500">
          <LocalTime iso={event.occurTime} />
        </span>
      </div>
      <p className="flex flex-wrap gap-x-3 gap-y-1 text-xs text-zinc-500">
        {target && <span>{target}</span>}
        {event.reason && <span>reason: {event.reason.replaceAll('_', ' ')}</span>}
        {event.details.map(([k, v]) => (
          <span key={k}>
            {k.replaceAll('_', ' ')}: <span className="text-zinc-700 dark:text-zinc-300">{v}</span>
          </span>
        ))}
        <span title={`Event ${event.eventId}`}>
          #{event.sequence} · recorded by {event.source}
        </span>
      </p>
    </li>
  )
}

export default async function AuditPage(props: PageProps<'/w/[workspaceId]/audit'>) {
  const { workspaceId } = await props.params
  const access = await requireWorkspace(workspaceId)
  const owner = access.workspace.role === 'owner'
  const filter = parseTrailFilter(await props.searchParams)

  let page: AuditPageView = { events: [], nextPage: null }
  let unavailable: string | undefined
  let members: MemberView[] = []
  try {
    ;[page, members] = await Promise.all([listTrail(access, filter), owner ? listMembers(access) : []])
  } catch (error) {
    if (!(error instanceof Problem)) throw error
    unavailable = error.message
  }

  const base = `/w/${workspaceId}/audit`
  const query = (extra: Record<string, string | undefined>) => {
    const params = new URLSearchParams()
    for (const [k, v] of Object.entries({ category: filter.category, person: filter.person, ...extra })) {
      if (v) params.set(k, v)
    }
    const qs = params.toString()
    return (qs ? `${base}?${qs}` : base) as Route
  }

  return (
    <>
      <PageHeader
        title="Audit trail"
        description={
          owner
            ? 'Everything that happened in this workspace: what people did here, and what Jarvis, phones, computers and services did for them. Entries cannot be changed or removed.'
            : 'What you did in this workspace, and what Jarvis, your phones and computers did for you. Owners see everyone’s entries.'
        }
      />
      <div className="space-y-6">
        <Form action={base as Route} className="flex flex-wrap items-end gap-3" aria-label="Filter the trail">
          <label className="space-y-1 text-sm">
            <span className="block font-medium">Show</span>
            <Select name="category" defaultValue={filter.category ?? ''}>
              <option value="">Everything</option>
              {AUDIT_CATEGORIES.map((c) => (
                <option key={c.id} value={c.id}>
                  {c.label}
                </option>
              ))}
            </Select>
          </label>
          {owner && (
            <label className="space-y-1 text-sm">
              <span className="block font-medium">Person</span>
              <Select name="person" defaultValue={filter.person ?? ''}>
                <option value="">Everyone</option>
                {members.map((m) => (
                  <option key={m.userId} value={m.userId}>
                    {m.displayName}
                    {m.you ? ' (you)' : ''}
                  </option>
                ))}
              </Select>
            </label>
          )}
          <button type="submit" className={buttonClass('secondary')}>
            Apply
          </button>
        </Form>

        {unavailable && <Alert kind="error">{unavailable}</Alert>}
        <Card title={filter.page ? 'Older entries' : 'Latest entries'}>
          {page.events.length === 0 ? (
            <Empty>{unavailable ? 'The trail cannot be shown right now.' : 'Nothing recorded yet.'}</Empty>
          ) : (
            <ul className="divide-y divide-zinc-200 dark:divide-zinc-800" data-testid="audit-events">
              {page.events.map((e) => (
                <Entry key={e.eventId} event={e} />
              ))}
            </ul>
          )}
          <div className="mt-4 flex gap-4 text-sm">
            {filter.page && (
              <Link href={query({})} className="text-indigo-600 hover:underline dark:text-indigo-400">
                ← Latest
              </Link>
            )}
            {page.nextPage && (
              <Link
                href={query({ page: page.nextPage })}
                className="text-indigo-600 hover:underline dark:text-indigo-400"
              >
                Older →
              </Link>
            )}
          </div>
        </Card>

        {owner && (
          <Card
            title="Tamper check"
            description="Each entry is chained to the one before it with a SHA-256 hash. Checking recomputes the whole chain: a changed, removed or reordered entry breaks it."
          >
            <VerifyTrail workspaceId={workspaceId} />
          </Card>
        )}
      </div>
    </>
  )
}
