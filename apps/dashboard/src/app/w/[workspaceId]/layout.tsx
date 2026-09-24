import type { Route } from 'next'
import Link from 'next/link'

import { signOut } from '@/actions/auth'
import { NavLink, WorkspaceSwitcher } from '@/components/nav'
import { Button } from '@/components/ui'
import { requireWorkspace } from '@/server/access'
import { db } from '@/server/runtime'
import { listWorkspaces } from '@/server/store/workspaces'

export default async function WorkspaceLayout(props: LayoutProps<'/w/[workspaceId]'>) {
  const { workspaceId } = await props.params
  const { session, workspace } = await requireWorkspace(workspaceId)
  const workspaces = await listWorkspaces(db(), session.userId)
  const base = `/w/${workspace.workspaceId}`

  return (
    <div className="flex min-h-dvh flex-col md:flex-row">
      <aside className="flex flex-col gap-6 border-b border-zinc-200 p-4 md:w-64 md:border-r md:border-b-0 dark:border-zinc-800">
        <Link href="/" className="text-lg font-semibold tracking-tight">
          Jarvis
        </Link>
        <WorkspaceSwitcher current={workspace.workspaceId} workspaces={workspaces} />
        <nav className="space-y-1" aria-label="Workspace">
          <NavLink href={`${base}/keys` as Route}>Provider keys</NavLink>
          <NavLink href={`${base}/devices` as Route}>Devices</NavLink>
          <NavLink href={`${base}/integrations` as Route}>Integrations</NavLink>
          <NavLink href={`${base}/members` as Route}>Members</NavLink>
          <NavLink href={`${base}/audit` as Route}>Audit trail</NavLink>
        </nav>
        <div className="mt-auto space-y-2 border-t border-zinc-200 pt-4 text-sm dark:border-zinc-800">
          <p className="truncate font-medium" title={session.displayName}>
            {session.displayName}
          </p>
          <p className="text-xs text-zinc-500">{workspace.role === 'owner' ? 'Owner' : 'Member'}</p>
          <div className="flex gap-2">
            <Link href="/account" className="text-zinc-600 hover:underline dark:text-zinc-400">
              Account
            </Link>
            <form action={signOut}>
              <Button type="submit" variant="ghost" className="px-0 py-0">
                Sign out
              </Button>
            </form>
          </div>
        </div>
      </aside>
      <main className="flex-1 p-6 md:p-10">
        <div className="mx-auto max-w-4xl">{props.children}</div>
      </main>
    </div>
  )
}
