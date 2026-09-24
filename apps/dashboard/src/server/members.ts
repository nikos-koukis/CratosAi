import 'server-only'

import { z } from 'zod'

import type { InvitationView, MemberView } from '@/lib/types'

import { auditDenied, type Access } from './access'
import { audit, auditJoined, auditWorkspaceCreated, person } from './audit'
import { newInvitationToken, workspaceNameSchema } from './auth/passkeys'
import type { Session } from './auth/session'
import { config } from './config'
import { withTx } from './db/db'
import { sha256, uuidv7 } from './ids'
import { log } from './log'
import { Problem } from './problem'
import { db } from './runtime'
import * as store from './store/workspaces'

// Workspaces, their members and invitations.

const INVITATION_TTL_MS = 7 * 24 * 60 * 60 * 1000

export async function listMembers(access: Access): Promise<MemberView[]> {
  const members = await store.listMembers(db(), access.workspace.workspaceId)
  return members.map((m) => ({
    userId: m.userId,
    displayName: m.displayName,
    role: m.role,
    joinTime: m.joinTime.toISOString(),
    you: m.userId === access.session.userId,
  }))
}

export async function listInvitations(access: Access): Promise<InvitationView[]> {
  const invitations = await store.listPendingInvitations(db(), access.workspace.workspaceId)
  return invitations.map((i) => ({
    invitationId: i.invitationId,
    role: i.role,
    invitedBy: i.invitedBy,
    createTime: i.createTime.toISOString(),
    expireTime: i.expireTime.toISOString(),
  }))
}

export const roleSchema = z.enum(['owner', 'member'])

/** An invitation link (owners only): single use, valid for 7 days. The link is shown once. */
export async function createInvitation(
  access: Access,
  role: z.infer<typeof roleSchema>,
): Promise<{ url: string; expireTime: string }> {
  const { token, hash } = newInvitationToken()
  const invitationId = uuidv7()
  await store.createInvitation(db(), {
    tokenHash: hash,
    invitationId,
    workspaceId: access.workspace.workspaceId,
    role,
    createdBy: access.session.userId,
    ttlMs: INVITATION_TTL_MS,
  })
  log.info(
    { userId: access.session.userId, workspaceId: access.workspace.workspaceId, role },
    'invitation created',
  )
  audit({
    tenantId: access.workspace.workspaceId,
    actor: person(access.session.userId),
    action: 'workspace.member_invited',
    targetType: 'invitation',
    targetId: invitationId,
    details: { role },
  })
  return {
    url: new URL(`/invite/${token}`, config().origin).toString(),
    expireTime: new Date(Date.now() + INVITATION_TTL_MS).toISOString(),
  }
}

export async function revokeInvitation(access: Access, invitationId: string): Promise<void> {
  await store.revokeInvitation(db(), access.workspace.workspaceId, invitationId)
  log.info(
    { userId: access.session.userId, workspaceId: access.workspace.workspaceId, invitationId },
    'invitation revoked',
  )
  audit({
    tenantId: access.workspace.workspaceId,
    actor: person(access.session.userId),
    action: 'workspace.invitation_revoked',
    targetType: 'invitation',
    targetId: invitationId,
  })
}

/** Changes a member's role (owners only); the workspace always keeps an owner. */
export async function changeRole(
  access: Access,
  userId: string,
  role: z.infer<typeof roleSchema>,
): Promise<void> {
  await withTx(db(), (tx) => store.setRole(tx, access.workspace.workspaceId, userId, role))
  log.info(
    { userId: access.session.userId, workspaceId: access.workspace.workspaceId, memberId: userId, role },
    'member role changed',
  )
  audit({
    tenantId: access.workspace.workspaceId,
    actor: person(access.session.userId),
    action: 'workspace.member_role_changed',
    targetType: 'user',
    targetId: userId,
    details: { role },
  })
}

/**
 * Removes a member: owners remove anyone, members only themselves (leaving).
 * The last owner cannot leave.
 */
export async function removeMember(access: Access, userId: string): Promise<void> {
  if (access.workspace.role !== 'owner' && userId !== access.session.userId) {
    auditDenied(access, 'owner_required')
    throw new Problem('forbidden', 'Only owners of the workspace can remove members.')
  }
  await withTx(db(), (tx) => store.removeMember(tx, access.workspace.workspaceId, userId))
  const left = userId === access.session.userId
  log.info(
    { userId: access.session.userId, workspaceId: access.workspace.workspaceId, memberId: userId },
    left ? 'member left' : 'member removed',
  )
  audit({
    tenantId: access.workspace.workspaceId,
    actor: person(access.session.userId),
    action: left ? 'workspace.member_left' : 'workspace.member_removed',
    targetType: 'user',
    targetId: userId,
  })
}

/** A new workspace owned by the user. */
export async function createWorkspace(session: Session, name: string): Promise<string> {
  const workspaceId = uuidv7()
  const workspaceName = workspaceNameSchema.parse(name)
  await withTx(db(), (tx) =>
    store.createWorkspace(tx, { workspaceId, name: workspaceName, ownerId: session.userId }),
  )
  log.info({ userId: session.userId, workspaceId }, 'workspace created')
  auditWorkspaceCreated(session.userId, workspaceId, workspaceName)
  return workspaceId
}

/** The signed-in user joins the workspace of an invitation. */
export async function joinWithInvitation(session: Session, token: string): Promise<string> {
  const joined = await withTx(db(), (tx) => store.acceptInvitation(tx, sha256(token), session.userId))
  const { workspaceId } = joined
  log.info({ userId: session.userId, workspaceId }, 'joined a workspace by invitation')
  auditJoined(session.userId, joined)
  return workspaceId
}

/** What an invitation link offers, for its page; undefined if the link is not valid. */
export async function invitationFor(token: string): Promise<store.Invitation | undefined> {
  if (!/^[A-Za-z0-9_-]{20,100}$/.test(token)) return undefined
  return store.findInvitation(db(), sha256(token))
}
