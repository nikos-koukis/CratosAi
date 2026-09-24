import type { Metadata } from 'next'

import {
  ConnectButton,
  CustomServerForm,
  DisconnectButton,
  ReconnectButton,
  TokenConnectForm,
} from '@/components/integrations'
import { LocalTime } from '@/components/local-time'
import { Alert, Badge, Card, Empty, PageHeader } from '@/components/ui'
import type { AuthorizationOutcome, CatalogServerView, IntegrationView, ToolsView } from '@/lib/types'
import { requireWorkspace } from '@/server/access'
import { listCatalog, listIntegrations, listTools } from '@/server/integrations'
import { Problem } from '@/server/problem'

export const metadata: Metadata = { title: 'Integrations' }

const RESULTS: Record<AuthorizationOutcome, { kind: 'success' | 'warning' | 'error'; text: string }> = {
  connected: { kind: 'success', text: 'Connected. Jarvis can use its tools when you talk to it.' },
  denied: { kind: 'warning', text: 'You did not allow access, so the server is not connected.' },
  failed: { kind: 'error', text: 'The connection did not complete. Try again, or sign in again below.' },
  expired: { kind: 'error', text: 'That sign-in expired. Start the connection again.' },
}

const STATUS = {
  connected: { tone: 'good', label: 'Connected' },
  pending: { tone: 'neutral', label: 'Waiting for sign-in' },
  needs_reauthorization: { tone: 'bad', label: 'Sign in again' },
} as const

/** Loads, turning an unreachable service into a message instead of an error page. */
async function load<T>(what: () => Promise<T>, fallback: T): Promise<[T, string | undefined]> {
  try {
    return [await what(), undefined]
  } catch (error) {
    if (!(error instanceof Problem)) throw error
    return [fallback, error.message]
  }
}

export default async function IntegrationsPage(props: PageProps<'/w/[workspaceId]/integrations'>) {
  const { workspaceId } = await props.params
  const { result } = await props.searchParams
  const access = await requireWorkspace(workspaceId)

  const [[catalog, catalogProblem], [integrations, listProblem], [tools, toolsProblem]] = await Promise.all([
    load<CatalogServerView[]>(listCatalog, []),
    load<IntegrationView[]>(() => listIntegrations(access), []),
    load<ToolsView>(() => listTools(access), { tools: [], unavailable: [] }),
  ])
  const outcome =
    typeof result === 'string' && result in RESULTS ? RESULTS[result as AuthorizationOutcome] : undefined
  const problem = listProblem ?? catalogProblem ?? toolsProblem

  return (
    <>
      <PageHeader
        title="Integrations"
        description="Connect your own accounts (Jira, Linear, Notion, GitHub…) so Jarvis can use their tools when you talk to it. Your connections are yours: nobody else in the workspace sees or uses them."
      />
      <div className="space-y-6">
        {outcome && <Alert kind={outcome.kind}>{outcome.text}</Alert>}
        {problem && <Alert kind="error">{problem}</Alert>}

        <Card title="Your connections">
          {integrations.length === 0 ? (
            <Empty>No connections yet. Connect a server below.</Empty>
          ) : (
            <ul className="divide-y divide-zinc-200 dark:divide-zinc-800" data-testid="integrations">
              {integrations.map((i) => {
                const own = tools.tools.filter((t) => t.integrationId === i.integrationId)
                const unreachable = tools.unavailable.find((u) => u.integrationId === i.integrationId)
                return (
                  <li key={i.integrationId} className="space-y-2 py-3">
                    <div className="flex flex-wrap items-center justify-between gap-3">
                      <div>
                        <p className="font-medium">
                          {i.name} <Badge tone={STATUS[i.status].tone}>{STATUS[i.status].label}</Badge>
                        </p>
                        <p className="text-sm break-all text-zinc-500">
                          {i.serverUrl} · added <LocalTime iso={i.createTime} />
                        </p>
                        {i.status !== 'connected' && i.statusDetail && (
                          <p className="text-sm text-zinc-600 dark:text-zinc-400">{i.statusDetail}</p>
                        )}
                      </div>
                      <div className="flex items-center gap-2">
                        {i.auth === 'oauth' && i.status !== 'connected' && (
                          <ReconnectButton workspaceId={workspaceId} integrationId={i.integrationId} />
                        )}
                        <DisconnectButton
                          workspaceId={workspaceId}
                          integrationId={i.integrationId}
                          name={i.name}
                        />
                      </div>
                    </div>
                    {i.status === 'connected' &&
                      (unreachable ? (
                        <p className="text-sm text-amber-700 dark:text-amber-300">
                          Its tools could not be listed: {unreachable.message}
                        </p>
                      ) : (
                        <details className="text-sm">
                          <summary className="cursor-pointer text-zinc-600 dark:text-zinc-400">
                            {own.length} {own.length === 1 ? 'tool' : 'tools'}
                          </summary>
                          <ul className="mt-2 space-y-1 pl-4">
                            {own.map((t) => (
                              <li key={t.name}>
                                <span className="font-mono">{t.name}</span>
                                {t.readOnly && (
                                  <>
                                    {' '}
                                    <Badge>read-only</Badge>
                                  </>
                                )}
                                {t.description && (
                                  <span className="text-zinc-500"> · {t.description.slice(0, 160)}</span>
                                )}
                              </li>
                            ))}
                          </ul>
                        </details>
                      ))}
                  </li>
                )
              })}
            </ul>
          )}
        </Card>

        <Card
          title="Connect a server"
          description="You sign in at the server; Jarvis never sees your password."
        >
          <ul className="grid gap-4 sm:grid-cols-2" data-testid="catalog">
            {catalog.map((s) => (
              <li key={s.slug} className="rounded-md p-3 ring-1 ring-zinc-200 dark:ring-zinc-800">
                <p className="font-medium">{s.name}</p>
                {s.notes && <p className="mt-1 text-xs text-zinc-500">{s.notes}</p>}
                <div className="mt-3">
                  {!s.available ? (
                    <p className="text-xs text-zinc-500">Not set up by whoever runs Jarvis yet.</p>
                  ) : s.auth === 'token' ? (
                    <TokenConnectForm workspaceId={workspaceId} slug={s.slug} name={s.name} />
                  ) : (
                    <ConnectButton workspaceId={workspaceId} slug={s.slug} name={s.name} />
                  )}
                </div>
              </li>
            ))}
          </ul>
        </Card>

        <Card
          title="Another MCP server"
          description="Any server that speaks the Model Context Protocol over https."
        >
          <CustomServerForm workspaceId={workspaceId} />
        </Card>
      </div>
    </>
  )
}
