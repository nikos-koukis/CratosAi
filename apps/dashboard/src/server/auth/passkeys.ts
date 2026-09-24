import 'server-only'

import { randomBytes } from 'node:crypto'

import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
  type AuthenticationResponseJSON,
  type PublicKeyCredentialCreationOptionsJSON,
  type PublicKeyCredentialRequestOptionsJSON,
  type RegistrationResponseJSON,
} from '@simplewebauthn/server'
import { cookies } from 'next/headers'
import { z } from 'zod'

import { auditAccount, auditJoined, auditWorkspaceCreated, Outcome } from '../audit'
import { config } from '../config'
import { withTx } from '../db/db'
import { isUuid, normalizeRecoveryCode, randomToken, recoveryCode, sha256, uuidv7 } from '../ids'
import { log } from '../log'
import { Problem } from '../problem'
import { ceremonyLimit, recoveryLimit } from '../ratelimit'
import { clientAddress } from '../request'
import { db } from '../runtime'
import {
  addPasskey,
  clearRecovered,
  createUser,
  findPasskey,
  getUser,
  listPasskeys,
  recordPasskeyUse,
  redeemRecoveryCode,
  replaceRecoveryCodes,
  saveChallenge,
  takeChallenge,
  type ChallengePurpose,
} from '../store/accounts'
import { acceptInvitation, createWorkspace, findInvitation } from '../store/workspaces'
import { clearCookie, cookieName, type Session, startSession } from './session'

const CHALLENGE_TTL_MS = 5 * 60_000
const RECOVERY_CODES = 10

/** A person's or workspace's name: 1 to 64 characters, no control characters. */
export function nameSchema(missing: string) {
  return z
    .string()
    .trim()
    .min(1, missing)
    .max(64, 'At most 64 characters.')
    .refine((s) => !/\p{Cc}/u.test(s), 'No control characters.')
}
export const displayNameSchema = nameSchema('Enter your name.')
export const workspaceNameSchema = nameSchema('Name the workspace.')
export const passkeyNameSchema = z.string().trim().min(1).max(64).catch('Passkey')

async function newChallenge(
  purpose: ChallengePurpose,
  challenge: string,
  extra: { userId?: string; pending?: unknown },
) {
  const challengeId = uuidv7()
  await saveChallenge(db(), { challengeId, challenge, purpose, ttlMs: CHALLENGE_TTL_MS, ...extra })
  ;(await cookies()).set(cookieName('challenge'), challengeId, {
    httpOnly: true,
    secure: config().secureCookies,
    sameSite: 'strict',
    path: '/',
    maxAge: CHALLENGE_TTL_MS / 1000,
  })
}

/** Takes this browser's pending challenge (single use). */
async function ownChallenge(purpose: ChallengePurpose) {
  const id = (await cookies()).get(cookieName('challenge'))?.value
  await clearCookie(cookieName('challenge'))
  const taken = isUuid(id) ? await takeChallenge(db(), id, purpose) : undefined
  if (!taken) throw new Problem('expired', 'That took too long. Please try again.')
  return taken
}

function registrationOptions(user: { name: string; webauthnUserId: Buffer }, exclude: string[] = []) {
  const cfg = config()
  return generateRegistrationOptions({
    rpName: cfg.rpName,
    rpID: cfg.rpID,
    userName: user.name,
    userDisplayName: user.name,
    userID: new Uint8Array(user.webauthnUserId),
    attestationType: 'none',
    // Discoverable, so signing in needs no user name; always with Face ID / PIN.
    authenticatorSelection: { residentKey: 'required', userVerification: 'required' },
    excludeCredentials: exclude.map((id) => ({ id })),
  })
}

async function verifyRegistration(response: RegistrationResponseJSON, expectedChallenge: string) {
  const cfg = config()
  try {
    const result = await verifyRegistrationResponse({
      response,
      expectedChallenge,
      expectedOrigin: cfg.origin.origin,
      expectedRPID: cfg.rpID,
      requireUserVerification: true,
    })
    if (result.verified) return result.registrationInfo
  } catch (error) {
    log.warn({ err: (error as Error).message }, 'passkey registration did not verify')
  }
  throw new Problem('invalid', 'The passkey could not be verified. Please try again.')
}

const pendingSignUp = z.object({
  displayName: z.string(),
  workspaceName: z.string().optional(),
  inviteToken: z.string().optional(),
  webauthnUserId: z.string(),
})

/**
 * Starts creating an account: a new user with a new workspace, or joining
 * the workspace of an invitation.
 */
export async function beginSignUp(input: {
  displayName: string
  workspaceName?: string
  inviteToken?: string
}): Promise<PublicKeyCredentialCreationOptionsJSON> {
  ceremonyLimit.hit(`sign-up:${await clientAddress()}`)
  const displayName = displayNameSchema.parse(input.displayName)
  let workspaceName: string | undefined
  if (input.inviteToken) {
    const invitation = await findInvitation(db(), sha256(input.inviteToken))
    if (invitation?.state !== 'pending')
      throw new Problem('expired', 'This invitation can no longer be used.')
  } else {
    workspaceName = workspaceNameSchema.parse(input.workspaceName ?? '')
  }
  const webauthnUserId = randomBytes(32)
  const options = await registrationOptions({ name: displayName, webauthnUserId })
  await newChallenge('sign_up', options.challenge, {
    pending: {
      displayName,
      workspaceName,
      inviteToken: input.inviteToken,
      webauthnUserId: webauthnUserId.toString('base64url'),
    } satisfies z.infer<typeof pendingSignUp>,
  })
  return options
}

/** Finishes creating an account; returns its workspace and recovery codes (shown once). */
export async function finishSignUp(
  response: RegistrationResponseJSON,
): Promise<{ workspaceId: string; recoveryCodes: string[] }> {
  const challenge = await ownChallenge('sign_up')
  const pending = pendingSignUp.parse(challenge.pending)
  const info = await verifyRegistration(response, challenge.challenge)
  const userId = uuidv7()
  const codes = Array.from({ length: RECOVERY_CODES }, recoveryCode)
  const joined = await withTx(db(), async (tx) => {
    await createUser(tx, {
      userId,
      displayName: pending.displayName,
      webauthnUserId: Buffer.from(pending.webauthnUserId, 'base64url'),
    })
    await addPasskey(tx, {
      credentialId: info.credential.id,
      userId,
      publicKey: Buffer.from(info.credential.publicKey),
      counter: info.credential.counter,
      transports: info.credential.transports ?? [],
      deviceType: info.credentialDeviceType,
      backedUp: info.credentialBackedUp,
      name: 'Passkey',
    })
    await replaceRecoveryCodes(tx, userId, codes.map(sha256))
    if (pending.inviteToken) return acceptInvitation(tx, sha256(pending.inviteToken), userId)
    const id = uuidv7()
    await createWorkspace(tx, { workspaceId: id, name: pending.workspaceName!, ownerId: userId })
    return id
  })
  const workspaceId = typeof joined === 'string' ? joined : joined.workspaceId
  await startSession(userId, false)
  log.info({ userId, workspaceId, invited: Boolean(pending.inviteToken) }, 'account created')
  await auditAccount(userId, { action: 'account.signed_up' })
  if (typeof joined === 'string') auditWorkspaceCreated(userId, workspaceId, pending.workspaceName!)
  else auditJoined(userId, joined)
  return { workspaceId, recoveryCodes: codes }
}

/** Starts signing in with any passkey of this site (no user name needed). */
export async function beginSignIn(): Promise<PublicKeyCredentialRequestOptionsJSON> {
  ceremonyLimit.hit(`sign-in:${await clientAddress()}`)
  const options = await generateAuthenticationOptions({ rpID: config().rpID, userVerification: 'required' })
  await newChallenge('sign_in', options.challenge, {})
  return options
}

export async function finishSignIn(response: AuthenticationResponseJSON): Promise<void> {
  const challenge = await ownChallenge('sign_in')
  const passkey = await findPasskey(db(), response.id)
  const failed = new Problem('unauthenticated', 'This passkey could not sign you in. Is it for this site?')
  if (!passkey) throw failed
  const user = await getUser(db(), passkey.userId)
  if (!user) throw failed
  const refused = async (reason: string) => {
    await auditAccount(passkey.userId, { action: 'account.sign_in_failed', outcome: Outcome.DENIED, reason })
    return failed
  }
  // The authenticator names the account it signed for; it must be the passkey's.
  if (
    response.response.userHandle &&
    response.response.userHandle !== user.webauthnUserId.toString('base64url')
  ) {
    throw await refused('wrong_account')
  }
  const cfg = config()
  let verified
  try {
    verified = await verifyAuthenticationResponse({
      response,
      expectedChallenge: challenge.challenge,
      expectedOrigin: cfg.origin.origin,
      expectedRPID: cfg.rpID,
      credential: {
        id: passkey.credentialId,
        publicKey: new Uint8Array(passkey.publicKey),
        counter: passkey.counter,
        transports: passkey.transports,
      },
      requireUserVerification: true,
    })
  } catch (error) {
    log.warn({ userId: passkey.userId, err: (error as Error).message }, 'passkey sign-in did not verify')
    throw await refused('passkey_not_verified')
  }
  if (!verified.verified) throw await refused('passkey_not_verified')
  await recordPasskeyUse(db(), passkey.credentialId, verified.authenticationInfo.newCounter)
  await startSession(passkey.userId, false)
  log.info({ userId: passkey.userId }, 'signed in')
  await auditAccount(passkey.userId, { action: 'account.signed_in' })
}

/** Starts adding a passkey to the signed-in user (also after a recovery sign-in). */
export async function beginAddPasskey(session: Session): Promise<PublicKeyCredentialCreationOptionsJSON> {
  const user = await getUser(db(), session.userId)
  if (!user) throw new Problem('unauthenticated', 'Sign in again.')
  const existing = await listPasskeys(db(), user.userId)
  const options = await registrationOptions(
    { name: user.displayName, webauthnUserId: user.webauthnUserId },
    existing.map((p) => p.credentialId),
  )
  await newChallenge('add_passkey', options.challenge, { userId: user.userId })
  return options
}

export async function finishAddPasskey(session: Session, response: RegistrationResponseJSON, name: string) {
  const challenge = await ownChallenge('add_passkey')
  if (challenge.userId !== session.userId) throw new Problem('expired', 'Please try again.')
  const info = await verifyRegistration(response, challenge.challenge)
  await addPasskey(db(), {
    credentialId: info.credential.id,
    userId: session.userId,
    publicKey: Buffer.from(info.credential.publicKey),
    counter: info.credential.counter,
    transports: info.credential.transports ?? [],
    deviceType: info.credentialDeviceType,
    backedUp: info.credentialBackedUp,
    name: passkeyNameSchema.parse(name),
  })
  if (session.recovered) await clearRecovered(db(), session.sessionId)
  log.info({ userId: session.userId }, 'passkey added')
  await auditAccount(session.userId, {
    action: 'account.passkey_added',
    details: { name: passkeyNameSchema.parse(name), synced: String(info.credentialBackedUp) },
  })
}

/**
 * Signs in with a recovery code (single use). The session may only add a
 * passkey until it has one again.
 */
export async function signInWithRecoveryCode(input: string): Promise<void> {
  recoveryLimit.hit(`recovery:${await clientAddress()}`)
  const code = normalizeRecoveryCode(input)
  const userId = code ? await redeemRecoveryCode(db(), sha256(code)) : undefined
  if (!userId) throw new Problem('unauthenticated', 'That recovery code is not valid, or was already used.')
  await startSession(userId, true)
  log.info({ userId }, 'signed in with a recovery code')
  await auditAccount(userId, { action: 'account.recovery_code_used' })
}

/** New recovery codes for the user; the old ones stop working. */
export async function regenerateRecoveryCodes(session: Session): Promise<string[]> {
  const codes = Array.from({ length: RECOVERY_CODES }, recoveryCode)
  await withTx(db(), (tx) => replaceRecoveryCodes(tx, session.userId, codes.map(sha256)))
  log.info({ userId: session.userId }, 'recovery codes replaced')
  await auditAccount(session.userId, { action: 'account.recovery_codes_replaced' })
  return codes
}

/** A random invitation token and what is stored of it. */
export function newInvitationToken(): { token: string; hash: Buffer } {
  const token = randomToken(32)
  return { token, hash: sha256(token) }
}
