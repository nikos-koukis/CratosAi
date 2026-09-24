import 'server-only'

import type pg from 'pg'

import type { Queryable } from '../db/db'
import { Problem } from '../problem'

// Workspaces (tenants), their members, and invitations to join them.

export type Role = 'owner' | 'member'

export type WorkspaceSummary = { workspaceId: string; name: string; role: Role }

export async function createWorkspace(
  tx: pg.PoolClient,
  w: { workspaceId: string; name: string; ownerId: string },
): Promise<void> {
  await tx.query('INSERT INTO workspaces (workspace_id, name) VALUES ($1, $2)', [w.workspaceId, w.name])
  await tx.query("INSERT INTO memberships (workspace_id, user_id, role) VALUES ($1, $2, 'owner')", [
    w.workspaceId,
    w.ownerId,
  ])
}

export async function listWorkspaces(q: Queryable, userId: string): Promise<WorkspaceSummary[]> {
  const { rows } = await q.query<{ workspace_id: string; name: string; role: Role }>(
    `SELECT w.workspace_id, w.name, m.role FROM memberships m JOIN workspaces w USING (workspace_id)
      WHERE m.user_id = $1 ORDER BY w.name, w.workspace_id`,
    [userId],
  )
  return rows.map((r) => ({ workspaceId: r.workspace_id, name: r.name, role: r.role }))
}

/** The user's membership in a workspace, or undefined if they are not a member. */
export async function getMembership(
  q: Queryable,
  workspaceId: string,
  userId: string,
): Promise<WorkspaceSummary | undefined> {
  const { rows } = await q.query<{ name: string; role: Role }>(
    `SELECT w.name, m.role FROM memberships m JOIN workspaces w USING (workspace_id)
      WHERE m.workspace_id = $1 AND m.user_id = $2`,
    [workspaceId, userId],
  )
  const row = rows[0]
  return row && { workspaceId, name: row.name, role: row.role }
}

export type Member = { userId: string; displayName: string; role: Role; joinTime: Date }

export async function listMembers(q: Queryable, workspaceId: string): Promise<Member[]> {
  const { rows } = await q.query<{ user_id: string; display_name: string; role: Role; create_time: Date }>(
    `SELECT m.user_id, u.display_name, m.role, m.create_time FROM memberships m JOIN users u USING (user_id)
      WHERE m.workspace_id = $1 ORDER BY m.role DESC, u.display_name, m.user_id`,
    [workspaceId],
  )
  return rows.map((r) => ({
    userId: r.user_id,
    displayName: r.display_name,
    role: r.role,
    joinTime: r.create_time,
  }))
}

/**
 * Locks the workspace's memberships and checks that, after the change, it
 * still has an owner. `userId` is the member affected and `newRole` their
 * new role (undefined: removed).
 */
async function keepAnOwner(
  tx: pg.PoolClient,
  workspaceId: string,
  userId: string,
  newRole: Role | undefined,
): Promise<void> {
  const { rows } = await tx.query<{ user_id: string; role: Role }>(
    'SELECT user_id, role FROM memberships WHERE workspace_id = $1 FOR UPDATE',
    [workspaceId],
  )
  if (!rows.some((r) => r.user_id === userId)) throw new Problem('not_found', 'No such member.')
  const owners = rows.filter((r) => (r.user_id === userId ? newRole : r.role) === 'owner')
  if (owners.length === 0) {
    throw new Problem('last_owner', 'A workspace needs an owner. Make someone else an owner first.')
  }
}

export async function setRole(
  tx: pg.PoolClient,
  workspaceId: string,
  userId: string,
  role: Role,
): Promise<void> {
  await keepAnOwner(tx, workspaceId, userId, role)
  await tx.query('UPDATE memberships SET role = $3 WHERE workspace_id = $1 AND user_id = $2', [
    workspaceId,
    userId,
    role,
  ])
}

export async function removeMember(tx: pg.PoolClient, workspaceId: string, userId: string): Promise<void> {
  await keepAnOwner(tx, workspaceId, userId, undefined)
  await tx.query('DELETE FROM memberships WHERE workspace_id = $1 AND user_id = $2', [workspaceId, userId])
}

export type PendingInvitation = {
  invitationId: string
  role: Role
  invitedBy: string | null
  createTime: Date
  expireTime: Date
}

export async function createInvitation(
  q: Queryable,
  i: {
    tokenHash: Buffer
    invitationId: string
    workspaceId: string
    role: Role
    createdBy: string
    ttlMs: number
  },
): Promise<void> {
  await q.query(
    `INSERT INTO invitations (token_hash, invitation_id, workspace_id, role, created_by, expire_time)
     VALUES ($1, $2, $3, $4, $5, now() + $6 * interval '1 millisecond')`,
    [i.tokenHash, i.invitationId, i.workspaceId, i.role, i.createdBy, i.ttlMs],
  )
}

export async function listPendingInvitations(
  q: Queryable,
  workspaceId: string,
): Promise<PendingInvitation[]> {
  const { rows } = await q.query<{
    invitation_id: string
    role: Role
    display_name: string | null
    create_time: Date
    expire_time: Date
  }>(
    `SELECT i.invitation_id, i.role, u.display_name, i.create_time, i.expire_time
       FROM invitations i LEFT JOIN users u ON u.user_id = i.created_by
      WHERE i.workspace_id = $1 AND i.accept_time IS NULL AND i.revoke_time IS NULL AND i.expire_time > now()
      ORDER BY i.create_time DESC`,
    [workspaceId],
  )
  return rows.map((r) => ({
    invitationId: r.invitation_id,
    role: r.role,
    invitedBy: r.display_name,
    createTime: r.create_time,
    expireTime: r.expire_time,
  }))
}

export async function revokeInvitation(
  q: Queryable,
  workspaceId: string,
  invitationId: string,
): Promise<void> {
  const { rowCount } = await q.query(
    `UPDATE invitations SET revoke_time = now()
      WHERE workspace_id = $1 AND invitation_id = $2 AND accept_time IS NULL AND revoke_time IS NULL`,
    [workspaceId, invitationId],
  )
  if (!rowCount) throw new Problem('not_found', 'No such pending invitation.')
}

export type InvitationState = 'pending' | 'expired' | 'used' | 'revoked'

export type Invitation = {
  invitationId: string
  workspaceId: string
  workspaceName: string
  role: Role
  invitedBy: string | null
  state: InvitationState
}

export async function findInvitation(q: Queryable, tokenHash: Buffer): Promise<Invitation | undefined> {
  const { rows } = await q.query<{
    invitation_id: string
    workspace_id: string
    name: string
    role: Role
    display_name: string | null
    state: InvitationState
  }>(
    `SELECT i.invitation_id, i.workspace_id, w.name, i.role, u.display_name,
            CASE WHEN i.revoke_time IS NOT NULL THEN 'revoked'
                 WHEN i.accept_time IS NOT NULL THEN 'used'
                 WHEN i.expire_time <= now() THEN 'expired'
                 ELSE 'pending' END AS state
       FROM invitations i JOIN workspaces w USING (workspace_id)
       LEFT JOIN users u ON u.user_id = i.created_by
      WHERE i.token_hash = $1`,
    [tokenHash],
  )
  const r = rows[0]
  return (
    r && {
      invitationId: r.invitation_id,
      workspaceId: r.workspace_id,
      workspaceName: r.name,
      role: r.role,
      invitedBy: r.display_name,
      state: r.state,
    }
  )
}

const INVITATION_UNUSABLE: Record<Exclude<InvitationState, 'pending'>, string> = {
  expired: 'This invitation has expired. Ask for a new one.',
  used: 'This invitation has already been used.',
  revoked: 'This invitation was withdrawn.',
}

/** Uses an invitation (once): the user joins its workspace with its role. */
export async function acceptInvitation(
  tx: pg.PoolClient,
  tokenHash: Buffer,
  userId: string,
): Promise<{ workspaceId: string; role: Role }> {
  const { rows } = await tx.query<{
    workspace_id: string
    role: Role
    state: InvitationState
  }>(
    `SELECT workspace_id, role,
            CASE WHEN revoke_time IS NOT NULL THEN 'revoked'
                 WHEN accept_time IS NOT NULL THEN 'used'
                 WHEN expire_time <= now() THEN 'expired'
                 ELSE 'pending' END AS state
       FROM invitations WHERE token_hash = $1 FOR UPDATE`,
    [tokenHash],
  )
  const invitation = rows[0]
  if (!invitation) throw new Problem('not_found', 'This invitation link is not valid.')
  if (invitation.state !== 'pending') throw new Problem('expired', INVITATION_UNUSABLE[invitation.state])
  const joined = await tx.query(
    `INSERT INTO memberships (workspace_id, user_id, role) VALUES ($1, $2, $3)
     ON CONFLICT (workspace_id, user_id) DO NOTHING`,
    [invitation.workspace_id, userId, invitation.role],
  )
  if (!joined.rowCount) throw new Problem('conflict', 'You are already a member of this workspace.')
  await tx.query('UPDATE invitations SET accept_time = now(), accepted_by = $2 WHERE token_hash = $1', [
    tokenHash,
    userId,
  ])
  return { workspaceId: invitation.workspace_id, role: invitation.role }
}
