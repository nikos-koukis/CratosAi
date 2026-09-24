import type { Route } from 'next'
import { redirect } from 'next/navigation'

import { requireSession } from '@/server/auth/session'
import { db } from '@/server/runtime'
import { listWorkspaces } from '@/server/store/workspaces'

/** Sends the user to their first workspace (or to create one). */
export default async function Home() {
  const session = await requireSession()
  const [first] = await listWorkspaces(db(), session.userId)
  redirect(first ? (`/w/${first.workspaceId}/keys` as Route) : '/workspaces/new')
}
