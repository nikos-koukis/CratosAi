import type { Metadata } from 'next'
import Link from 'next/link'

import { NewWorkspaceForm } from '@/components/members'
import { Card, PageHeader } from '@/components/ui'
import { requireSession } from '@/server/auth/session'

export const metadata: Metadata = { title: 'New workspace' }

export default async function NewWorkspacePage() {
  await requireSession()
  return (
    <main className="mx-auto max-w-xl p-6">
      <PageHeader
        title="New workspace"
        description="A workspace has its own provider keys, members and devices. You will be its owner."
      />
      <Card>
        <NewWorkspaceForm />
      </Card>
      <p className="mt-4 text-sm">
        <Link href="/" className="text-zinc-600 hover:underline dark:text-zinc-400">
          Cancel
        </Link>
      </p>
    </main>
  )
}
