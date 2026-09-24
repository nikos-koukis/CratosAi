import 'server-only'

import type { Queryable } from '../db/db'

// OAuth authorizations of MCP servers that a user started from the dashboard.

export async function saveAuthorization(
  q: Queryable,
  a: { stateHash: Buffer; userId: string; workspaceId: string; integrationId: string; ttlMs: number },
): Promise<void> {
  await q.query(
    `INSERT INTO mcp_authorizations (state_hash, user_id, workspace_id, integration_id, expire_time)
     VALUES ($1, $2, $3, $4, now() + $5 * interval '1 millisecond')`,
    [a.stateHash, a.userId, a.workspaceId, a.integrationId, a.ttlMs],
  )
}

/**
 * Takes (single use) the user's unexpired authorization with this state;
 * undefined if there is none, or it belongs to someone else (then it stays).
 */
export async function takeAuthorization(
  q: Queryable,
  stateHash: Buffer,
  userId: string,
): Promise<{ workspaceId: string; integrationId: string } | undefined> {
  const { rows } = await q.query<{ workspace_id: string; integration_id: string; live: boolean }>(
    `DELETE FROM mcp_authorizations WHERE state_hash = $1 AND user_id = $2
     RETURNING workspace_id, integration_id, expire_time > now() AS live`,
    [stateHash, userId],
  )
  const row = rows[0]
  return row?.live ? { workspaceId: row.workspace_id, integrationId: row.integration_id } : undefined
}
