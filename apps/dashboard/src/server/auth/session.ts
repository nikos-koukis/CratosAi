import 'server-only'

import { cookies } from 'next/headers'
import { redirect } from 'next/navigation'
import { cache } from 'react'

import { auditAccount } from '../audit'
import { config } from '../config'
import { randomToken, sha256, uuidv7 } from '../ids'
import { Problem } from '../problem'
import { userAgent } from '../request'
import { db } from '../runtime'
import {
  createSession,
  deleteSession,
  deleteUserSessions,
  findSession,
  touchSession,
  type Session,
} from '../store/accounts'

export type { Session }

/**
 * Cookie names: __Host- prefixed (Secure, host-only, path /) over https. Plain
 * names only for http://localhost in development.
 */
export function cookieName(name: 'session' | 'challenge'): string {
  return config().secureCookies ? `__Host-jarvis-${name}` : `jarvis-${name}`
}

/**
 * Deletes a cookie. A __Host- cookie is only replaced by one with the same
 * attributes (Secure, Path=/), so a bare delete would be ignored.
 */
export async function clearCookie(name: string): Promise<void> {
  ;(await cookies()).set(name, '', {
    httpOnly: true,
    secure: config().secureCookies,
    sameSite: 'lax',
    path: '/',
    maxAge: 0,
  })
}

/** The signed-in session of this request, if any (looked up once per request). */
export const currentSession = cache(async (): Promise<Session | undefined> => {
  const token = (await cookies()).get(cookieName('session'))?.value
  if (!token || token.length > 64) return undefined
  const session = await findSession(db(), sha256(token), config().sessionIdleMs)
  if (session) await touchSession(db(), session.sessionId)
  return session
})

/**
 * For pages: the session, or a redirect to sign in. A session opened with a
 * recovery code goes to the account page until a new passkey is added.
 */
export async function requireSession(options: { allowRecovered?: boolean } = {}): Promise<Session> {
  const session = await currentSession()
  if (!session) redirect('/sign-in')
  if (session.recovered && !options.allowRecovered) redirect('/account')
  return session
}

/** For server actions: the session, or an unauthenticated Problem. */
export async function actionSession(options: { allowRecovered?: boolean } = {}): Promise<Session> {
  const session = await currentSession()
  if (!session) throw new Problem('unauthenticated', 'Your session has ended. Sign in again.')
  if (session.recovered && !options.allowRecovered) {
    throw new Problem('forbidden', 'Add a new passkey first.')
  }
  return session
}

/** Signs the browser in as the user with a fresh session token. */
export async function startSession(userId: string, recovered: boolean): Promise<void> {
  const cfg = config()
  const jar = await cookies()
  // Never keep a token from before sign-in (session fixation).
  const previous = jar.get(cookieName('session'))?.value
  if (previous && previous.length <= 64) {
    const old = await findSession(db(), sha256(previous), cfg.sessionIdleMs)
    if (old) await deleteSession(db(), old.sessionId)
  }
  const token = randomToken(32)
  await createSession(db(), {
    tokenHash: sha256(token),
    sessionId: uuidv7(),
    userId,
    recovered,
    userAgent: await userAgent(),
    lifetimeMs: cfg.sessionLifetimeMs,
  })
  jar.set(cookieName('session'), token, {
    httpOnly: true,
    secure: cfg.secureCookies,
    sameSite: 'lax',
    path: '/',
    maxAge: Math.floor(cfg.sessionLifetimeMs / 1000),
  })
}

/** Signs out this browser. */
export async function endSession(): Promise<void> {
  const session = await currentSession()
  if (session) {
    await deleteSession(db(), session.sessionId)
    await auditAccount(session.userId, { action: 'account.signed_out' })
  }
  await clearCookie(cookieName('session'))
}

/** Signs out every other browser of the user; returns how many. */
export async function endOtherSessions(session: Session): Promise<number> {
  const ended = await deleteUserSessions(db(), session.userId, session.sessionId)
  await auditAccount(session.userId, {
    action: 'account.signed_out_elsewhere',
    details: { sessions: String(ended) },
  })
  return ended
}
