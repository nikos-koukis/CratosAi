import type { Metadata } from 'next'

import { AddKeyForm, RevokeKeyButton } from '@/components/keys'
import { LocalTime } from '@/components/local-time'
import { Alert, Badge, Card, Empty, PageHeader } from '@/components/ui'
import { providerLabel, type KeyView } from '@/lib/types'
import { requireWorkspace } from '@/server/access'
import { listKeys } from '@/server/keys'
import { Problem } from '@/server/problem'

export const metadata: Metadata = { title: 'Provider keys' }

const REVOKED_BECAUSE = { user_requested: 'Removed', rotated: 'Replaced', compromised: 'Leaked' } as const

export default async function KeysPage(props: PageProps<'/w/[workspaceId]/keys'>) {
  const { workspaceId } = await props.params
  const access = await requireWorkspace(workspaceId)
  const owner = access.workspace.role === 'owner'

  let keys: KeyView[] = []
  let unavailable: string | undefined
  try {
    keys = await listKeys(access, true)
  } catch (error) {
    if (!(error instanceof Problem)) throw error
    unavailable = error.message
  }
  const active = keys.filter((k) => k.status === 'active')
  const revoked = keys.filter((k) => k.status === 'revoked')

  return (
    <>
      <PageHeader
        title="Provider keys"
        description="Jarvis uses your own API keys (bring your own key). Each provider has at most one active key; the vault encrypts it and only Jarvis’s services can use it."
      />
      <div className="space-y-6">
        {unavailable && <Alert kind="error">{unavailable}</Alert>}
        <Card title="Active keys">
          {active.length === 0 ? (
            <Empty>
              No keys yet. {owner ? 'Add one below to start talking to Jarvis.' : 'An owner can add one.'}
            </Empty>
          ) : (
            <ul className="divide-y divide-zinc-200 dark:divide-zinc-800" data-testid="active-keys">
              {active.map((key) => (
                <li key={key.keyId} className="flex flex-wrap items-center justify-between gap-3 py-3">
                  <div>
                    <p className="font-medium">
                      {providerLabel(key.provider)} <span className="text-zinc-500">· {key.label}</span>
                    </p>
                    <p className="text-sm text-zinc-500">
                      <span className="font-mono">••••{key.hint}</span> · added{' '}
                      <LocalTime iso={key.createTime} />
                    </p>
                  </div>
                  {owner && <RevokeKeyButton workspaceId={workspaceId} keyId={key.keyId} label={key.label} />}
                </li>
              ))}
            </ul>
          )}
        </Card>

        {owner ? (
          <Card
            title="Add a key"
            description="Adding a key for a provider that has one asks whether to replace it."
          >
            <AddKeyForm workspaceId={workspaceId} activeProviders={active.map((k) => k.provider)} />
          </Card>
        ) : (
          <Alert kind="info">Only owners of the workspace can add or revoke keys.</Alert>
        )}

        {revoked.length > 0 && (
          <Card title="Revoked keys" description="Kept for the record; their secrets were destroyed.">
            <ul className="divide-y divide-zinc-200 text-sm dark:divide-zinc-800">
              {revoked.map((key) => (
                <li key={key.keyId} className="flex flex-wrap items-center justify-between gap-3 py-2">
                  <span>
                    {providerLabel(key.provider)} · {key.label}{' '}
                    <span className="font-mono text-zinc-500">••••{key.hint}</span>
                  </span>
                  <span className="flex items-center gap-2 text-zinc-500">
                    <Badge tone={key.revocationReason === 'compromised' ? 'bad' : 'neutral'}>
                      {key.revocationReason ? REVOKED_BECAUSE[key.revocationReason] : 'Revoked'}
                    </Badge>
                    <LocalTime iso={key.revokeTime} />
                  </span>
                </li>
              ))}
            </ul>
          </Card>
        )}
      </div>
    </>
  )
}
