import 'server-only'

import type pg from 'pg'

import type { Queryable } from '../db/db'
import { Problem } from '../problem'

// Users, their passkeys and recovery codes, sessions and WebAuthn challenges.

export type User = { userId: string; displayName: string; webauthnUserId: Buffer }

export async function createUser(q: Queryable, user: User): Promise<void> {
  await q.query('INSERT INTO users (user_id, display_name, webauthn_user_id) VALUES ($1, $2, $3)', [
    user.userId,
    user.displayName,
    user.webauthnUserId,
  ])
}

export async function getUser(q: Queryable, userId: string): Promise<User | undefined> {
  const { rows } = await q.query<{ user_id: string; display_name: string; webauthn_user_id: Buffer }>(
    'SELECT user_id, display_name, webauthn_user_id FROM users WHERE user_id = $1',
    [userId],
  )
  const row = rows[0]
  return row && { userId: row.user_id, displayName: row.display_name, webauthnUserId: row.webauthn_user_id }
}

export type Passkey = {
  credentialId: string
  userId: string
  publicKey: Buffer
  counter: number
  transports: string[]
  deviceType: 'singleDevice' | 'multiDevice'
  backedUp: boolean
  name: string
  createTime: Date
  lastUseTime: Date | null
}

type PasskeyRow = {
  credential_id: string
  user_id: string
  public_key: Buffer
  counter: string
  transports: string[]
  device_type: 'singleDevice' | 'multiDevice'
  backed_up: boolean
  name: string
  create_time: Date
  last_use_time: Date | null
}

const PASSKEY_COLUMNS =
  'credential_id, user_id, public_key, counter, transports, device_type, backed_up, name, create_time, last_use_time'

function passkey(row: PasskeyRow): Passkey {
  return {
    credentialId: row.credential_id,
    userId: row.user_id,
    publicKey: row.public_key,
    counter: Number(row.counter),
    transports: row.transports,
    deviceType: row.device_type,
    backedUp: row.backed_up,
    name: row.name,
    createTime: row.create_time,
    lastUseTime: row.last_use_time,
  }
}

export async function addPasskey(
  q: Queryable,
  p: Omit<Passkey, 'createTime' | 'lastUseTime'>,
): Promise<void> {
  await q.query(
    `INSERT INTO passkeys (credential_id, user_id, public_key, counter, transports, device_type, backed_up, name)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
    [p.credentialId, p.userId, p.publicKey, p.counter, p.transports, p.deviceType, p.backedUp, p.name],
  )
}

export async function findPasskey(q: Queryable, credentialId: string): Promise<Passkey | undefined> {
  const { rows } = await q.query<PasskeyRow>(
    `SELECT ${PASSKEY_COLUMNS} FROM passkeys WHERE credential_id = $1`,
    [credentialId],
  )
  return rows[0] && passkey(rows[0])
}

export async function listPasskeys(q: Queryable, userId: string): Promise<Passkey[]> {
  const { rows } = await q.query<PasskeyRow>(
    `SELECT ${PASSKEY_COLUMNS} FROM passkeys WHERE user_id = $1 ORDER BY create_time`,
    [userId],
  )
  return rows.map(passkey)
}

export async function recordPasskeyUse(q: Queryable, credentialId: string, counter: number): Promise<void> {
  await q.query('UPDATE passkeys SET counter = $2, last_use_time = now() WHERE credential_id = $1', [
    credentialId,
    counter,
  ])
}

/** Removes a passkey of the user; the last one cannot be removed. */
export async function removePasskey(tx: pg.PoolClient, userId: string, credentialId: string): Promise<void> {
  const { rows } = await tx.query<{ credential_id: string }>(
    'SELECT credential_id FROM passkeys WHERE user_id = $1 FOR UPDATE',
    [userId],
  )
  if (!rows.some((r) => r.credential_id === credentialId)) throw new Problem('not_found', 'No such passkey.')
  if (rows.length === 1) {
    throw new Problem('last_passkey', 'This is your only passkey. Add another one before removing it.')
  }
  await tx.query('DELETE FROM passkeys WHERE user_id = $1 AND credential_id = $2', [userId, credentialId])
}

/** Replaces all of the user's recovery codes. */
export async function replaceRecoveryCodes(
  tx: pg.PoolClient,
  userId: string,
  hashes: Buffer[],
): Promise<void> {
  await tx.query('DELETE FROM recovery_codes WHERE user_id = $1', [userId])
  await tx.query('INSERT INTO recovery_codes (code_hash, user_id) SELECT unnest($1::bytea[]), $2', [
    hashes,
    userId,
  ])
}

/** Uses up a recovery code; returns its user, or undefined if no such unused code. */
export async function redeemRecoveryCode(q: Queryable, hash: Buffer): Promise<string | undefined> {
  const { rows } = await q.query<{ user_id: string }>(
    'DELETE FROM recovery_codes WHERE code_hash = $1 RETURNING user_id',
    [hash],
  )
  return rows[0]?.user_id
}

export async function countRecoveryCodes(q: Queryable, userId: string): Promise<number> {
  const { rows } = await q.query<{ n: string }>(
    'SELECT count(*) AS n FROM recovery_codes WHERE user_id = $1',
    [userId],
  )
  return Number(rows[0]?.n ?? 0)
}

export type Session = {
  sessionId: string
  userId: string
  displayName: string
  recovered: boolean
  lastSeenTime: Date
}

export async function createSession(
  q: Queryable,
  s: {
    tokenHash: Buffer
    sessionId: string
    userId: string
    recovered: boolean
    userAgent: string
    lifetimeMs: number
  },
): Promise<void> {
  await q.query(
    `INSERT INTO sessions (token_hash, session_id, user_id, recovered, user_agent, expire_time)
     VALUES ($1, $2, $3, $4, $5, now() + $6 * interval '1 millisecond')`,
    [s.tokenHash, s.sessionId, s.userId, s.recovered, s.userAgent.slice(0, 256), s.lifetimeMs],
  )
}

/** The live session with this token: not past its lifetime, and used within idleMs. */
export async function findSession(
  q: Queryable,
  tokenHash: Buffer,
  idleMs: number,
): Promise<Session | undefined> {
  const { rows } = await q.query<{
    session_id: string
    user_id: string
    display_name: string
    recovered: boolean
    last_seen_time: Date
  }>(
    `SELECT s.session_id, s.user_id, u.display_name, s.recovered, s.last_seen_time
       FROM sessions s JOIN users u USING (user_id)
      WHERE s.token_hash = $1 AND s.expire_time > now()
        AND s.last_seen_time > now() - $2 * interval '1 millisecond'`,
    [tokenHash, idleMs],
  )
  const row = rows[0]
  return (
    row && {
      sessionId: row.session_id,
      userId: row.user_id,
      displayName: row.display_name,
      recovered: row.recovered,
      lastSeenTime: row.last_seen_time,
    }
  )
}

/** Records use of a session (at most once a minute, to spare writes). */
export async function touchSession(q: Queryable, sessionId: string): Promise<void> {
  await q.query(
    `UPDATE sessions SET last_seen_time = now()
      WHERE session_id = $1 AND last_seen_time < now() - interval '1 minute'`,
    [sessionId],
  )
}

export async function deleteSession(q: Queryable, sessionId: string): Promise<void> {
  await q.query('DELETE FROM sessions WHERE session_id = $1', [sessionId])
}

/** Ends the user's other sessions (all of them if keep is undefined). */
export async function deleteUserSessions(q: Queryable, userId: string, keep?: string): Promise<number> {
  const { rowCount } = await q.query(
    'DELETE FROM sessions WHERE user_id = $1 AND session_id IS DISTINCT FROM $2::uuid',
    [userId, keep ?? null],
  )
  return rowCount ?? 0
}

export async function clearRecovered(q: Queryable, sessionId: string): Promise<void> {
  await q.query('UPDATE sessions SET recovered = false WHERE session_id = $1', [sessionId])
}

export type ChallengePurpose = 'sign_up' | 'sign_in' | 'add_passkey'

export async function saveChallenge(
  q: Queryable,
  c: {
    challengeId: string
    challenge: string
    purpose: ChallengePurpose
    userId?: string
    pending?: unknown
    ttlMs: number
  },
): Promise<void> {
  await q.query(
    `INSERT INTO webauthn_challenges (challenge_id, challenge, purpose, user_id, pending, expire_time)
     VALUES ($1, $2, $3, $4, $5, now() + $6 * interval '1 millisecond')`,
    [
      c.challengeId,
      c.challenge,
      c.purpose,
      c.userId ?? null,
      c.pending === undefined ? null : c.pending,
      c.ttlMs,
    ],
  )
}

/** Takes (single use) an unexpired challenge of this purpose. */
export async function takeChallenge(
  q: Queryable,
  challengeId: string,
  purpose: ChallengePurpose,
): Promise<{ challenge: string; userId: string | null; pending: unknown } | undefined> {
  const { rows } = await q.query<{
    challenge: string
    user_id: string | null
    pending: unknown
    live: boolean
  }>(
    `DELETE FROM webauthn_challenges WHERE challenge_id = $1 AND purpose = $2
     RETURNING challenge, user_id, pending, expire_time > now() AS live`,
    [challengeId, purpose],
  )
  const row = rows[0]
  return row?.live ? { challenge: row.challenge, userId: row.user_id, pending: row.pending } : undefined
}

/** Deletes what has expired; run periodically. */
export async function purgeExpired(q: Queryable): Promise<void> {
  await q.query("DELETE FROM sessions WHERE expire_time < now() - interval '1 day'")
  await q.query('DELETE FROM webauthn_challenges WHERE expire_time < now()')
  await q.query('DELETE FROM mcp_authorizations WHERE expire_time < now()')
  await q.query(
    `DELETE FROM invitations
      WHERE (accept_time IS NOT NULL OR revoke_time IS NOT NULL OR expire_time < now())
        AND create_time < now() - interval '30 days'`,
  )
}

/** Names of the users with these ids (members past and present). */
export async function displayNames(q: Queryable, userIds: string[]): Promise<Map<string, string>> {
  if (userIds.length === 0) return new Map()
  const { rows } = await q.query<{ user_id: string; display_name: string }>(
    'SELECT user_id, display_name FROM users WHERE user_id = ANY($1::uuid[])',
    [userIds],
  )
  return new Map(rows.map((r) => [r.user_id, r.display_name]))
}
