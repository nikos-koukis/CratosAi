import 'server-only'

import { notFound } from 'next/navigation'
import { cache } from 'react'

import { actionSession, requireSession, type Session } from './auth/session'
import { isUuid } from './ids'
import { Problem } from './problem'
import { db } from './runtime'
import { getMembership, type Role, type WorkspaceSummary } from './store/workspaces'

export type Access = { session: Session; workspace: WorkspaceSummary }

/**
 * For pages: the signed-in user's membership in the workspace. Someone who is
 * not a member sees "not found", so workspace ids cannot be probed.
 */
export const requireWorkspace = cache(async (workspaceId: string): Promise<Access> => {
  const session = await requireSession()
  if (!isUuid(workspaceId)) notFound()
  const workspace = await getMembership(db(), workspaceId, session.userId)
  if (!workspace) notFound()
  return { session, workspace }
})

/** For server actions: the membership, with at least `role` (owner: owners only). */
export async function actionWorkspace(workspaceId: unknown, role?: Role): Promise<Access> {
  const session = await actionSession()
  const workspace = isUuid(workspaceId) ? await getMembership(db(), workspaceId, session.userId) : undefined
  if (!workspace) throw new Problem('not_found', 'No such workspace.')
  if (role === 'owner' && workspace.role !== 'owner') {
    throw new Problem('forbidden', 'Only owners of the workspace can do this.')
  }
  return { session, workspace }
}
