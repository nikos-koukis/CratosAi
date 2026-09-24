import type { Metadata } from 'next'
import Link from 'next/link'

import { signOut } from '@/actions/auth'
import { LocalTime } from '@/components/local-time'
import {
  AddPasskeyForm,
  NewRecoveryCodes,
  RemovePasskeyButton,
  SignOutOthersButton,
} from '@/components/passkeys'
import { Alert, Badge, Button, Card, PageHeader } from '@/components/ui'
import { passkeys, recoveryCodesLeft } from '@/server/account'
import { requireSession } from '@/server/auth/session'

export const metadata: Metadata = { title: 'Account' }

export default async function AccountPage() {
  const session = await requireSession({ allowRecovered: true })

  if (session.recovered) {
    return (
      <main className="mx-auto max-w-2xl space-y-6 p-6">
        <PageHeader title={`Welcome back, ${session.displayName}`} />
        <Alert kind="warning">
          You signed in with a recovery code. Add a new passkey on this device to continue.
        </Alert>
        <Card title="Add a passkey">
          <AddPasskeyForm recovered />
        </Card>
      </main>
    )
  }

  const [keys, codesLeft] = await Promise.all([passkeys(session), recoveryCodesLeft(session)])
  return (
    <main className="mx-auto max-w-2xl space-y-6 p-6">
      <div className="flex items-center justify-between">
        <PageHeader title="Account" description={session.displayName} />
        <Link href="/" className="text-sm text-zinc-600 hover:underline dark:text-zinc-400">
          Back to Jarvis
        </Link>
      </div>

      <Card title="Passkeys" description="Any of them signs you in. Add one on each device you use.">
        <ul className="mb-4 divide-y divide-zinc-200 dark:divide-zinc-800" data-testid="passkeys">
          {keys.map((k) => (
            <li key={k.credentialId} className="flex flex-wrap items-center justify-between gap-3 py-3">
              <div>
                <p className="font-medium">
                  {k.name} {k.synced && <Badge tone="good">synced</Badge>}
                </p>
                <p className="text-sm text-zinc-500">
                  added <LocalTime iso={k.createTime} /> · last used <LocalTime iso={k.lastUseTime} />
                </p>
              </div>
              {keys.length > 1 && <RemovePasskeyButton credentialId={k.credentialId} />}
            </li>
          ))}
        </ul>
        <AddPasskeyForm />
      </Card>

      <Card
        title="Recovery codes"
        description={`${codesLeft} unused ${codesLeft === 1 ? 'code' : 'codes'} left. Each signs you in once if you lose your passkeys.`}
      >
        {codesLeft < 3 && (
          <Alert kind="warning">You are running out of recovery codes. Create new ones.</Alert>
        )}
        <div className="mt-3">
          <NewRecoveryCodes />
        </div>
      </Card>

      <Card title="Sessions">
        <div className="flex flex-wrap gap-3">
          <SignOutOthersButton />
          <form action={signOut}>
            <Button type="submit" variant="secondary">
              Sign out
            </Button>
          </form>
        </div>
      </Card>
    </main>
  )
}
