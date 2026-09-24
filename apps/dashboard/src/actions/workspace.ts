'use server'

import { refresh } from 'next/cache'
import { z } from 'zod'

import type { ActionResult, ChainView, KeyView, PairingView } from '@/lib/types'
import { actionWorkspace } from '@/server/access'
import { runAction } from '@/server/action'
import { verifyTrail } from '@/server/audit-trail'
import { actionSession } from '@/server/auth/session'
import { createPairing, revokeDevice, revokeDeviceSchema } from '@/server/devices'
import { connect, connectSchema, disconnect, reconnect } from '@/server/integrations'
import { addKey, addKeySchema, revokeKey, revokeKeySchema } from '@/server/keys'
import {
  changeRole,
  createInvitation,
  createWorkspace,
  joinWithInvitation,
  removeMember,
  revokeInvitation,
  roleSchema,
} from '@/server/members'

// Everything a workspace page can change. Each action checks the session and
// the caller's role in the workspace itself: the pages hiding a button is not
// a security boundary.

export async function addKeyAction(
  workspaceId: string,
  input: unknown,
): Promise<ActionResult<KeyView | undefined>> {
  return runAction('keys.add', async () => {
    const access = await actionWorkspace(workspaceId, 'owner')
    const key = await addKey(access, addKeySchema.parse(input))
    refresh()
    return key
  })
}

export async function revokeKeyAction(workspaceId: string, input: unknown): Promise<ActionResult> {
  return runAction('keys.revoke', async () => {
    await revokeKey(await actionWorkspace(workspaceId, 'owner'), revokeKeySchema.parse(input))
    refresh()
    return null
  })
}

export async function pairAction(workspaceId: string): Promise<ActionResult<PairingView>> {
  return runAction('devices.pair', async () => createPairing(await actionWorkspace(workspaceId)))
}

export async function revokeDeviceAction(workspaceId: string, sessionId: unknown): Promise<ActionResult> {
  return runAction('devices.revoke', async () => {
    await revokeDevice(await actionWorkspace(workspaceId), revokeDeviceSchema.parse({ sessionId }))
    refresh()
    return null
  })
}

export async function inviteAction(
  workspaceId: string,
  role: unknown,
): Promise<ActionResult<{ url: string; expireTime: string }>> {
  return runAction('members.invite', async () => {
    const result = await createInvitation(await actionWorkspace(workspaceId, 'owner'), roleSchema.parse(role))
    refresh()
    return result
  })
}

export async function revokeInvitationAction(
  workspaceId: string,
  invitationId: unknown,
): Promise<ActionResult> {
  return runAction('members.invitation.revoke', async () => {
    await revokeInvitation(await actionWorkspace(workspaceId, 'owner'), z.uuid().parse(invitationId))
    refresh()
    return null
  })
}

export async function changeRoleAction(
  workspaceId: string,
  userId: unknown,
  role: unknown,
): Promise<ActionResult> {
  return runAction('members.role', async () => {
    await changeRole(
      await actionWorkspace(workspaceId, 'owner'),
      z.uuid().parse(userId),
      roleSchema.parse(role),
    )
    refresh()
    return null
  })
}

/** Removes a member, or (for your own id) leaves the workspace. */
export async function removeMemberAction(
  workspaceId: string,
  userId: unknown,
): Promise<ActionResult<{ left: boolean }>> {
  return runAction('members.remove', async () => {
    const access = await actionWorkspace(workspaceId)
    const id = z.uuid().parse(userId)
    await removeMember(access, id)
    const left = id === access.session.userId
    if (!left) refresh()
    return { left }
  })
}

export async function createWorkspaceAction(name: unknown): Promise<ActionResult<string>> {
  return runAction('workspaces.create', async () =>
    createWorkspace(await actionSession(), z.string().max(200).parse(name)),
  )
}

export async function joinAction(token: unknown): Promise<ActionResult<string>> {
  return runAction('workspaces.join', async () =>
    joinWithInvitation(await actionSession(), z.string().min(1).max(100).parse(token)),
  )
}

/** Connects an MCP server for the signed-in user (every member manages their own). */
export async function connectAction(
  workspaceId: string,
  input: unknown,
): Promise<ActionResult<{ authorizationUrl: string | null; name: string }>> {
  return runAction('integrations.connect', async () => {
    const result = await connect(await actionWorkspace(workspaceId), connectSchema.parse(input))
    if (!result.authorizationUrl) refresh()
    return result
  })
}

export async function reconnectAction(
  workspaceId: string,
  integrationId: unknown,
): Promise<ActionResult<string>> {
  return runAction('integrations.reconnect', async () =>
    reconnect(await actionWorkspace(workspaceId), z.uuid().parse(integrationId)),
  )
}

export async function disconnectAction(workspaceId: string, integrationId: unknown): Promise<ActionResult> {
  return runAction('integrations.disconnect', async () => {
    await disconnect(await actionWorkspace(workspaceId), z.uuid().parse(integrationId))
    refresh()
    return null
  })
}

/** Checks the workspace's audit trail for tampering (owners only). */
export async function verifyTrailAction(workspaceId: string): Promise<ActionResult<ChainView>> {
  return runAction('audit.verify', async () => verifyTrail(await actionWorkspace(workspaceId, 'owner')))
}
