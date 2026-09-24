'use server'

import type {
  AuthenticationResponseJSON,
  PublicKeyCredentialCreationOptionsJSON,
  PublicKeyCredentialRequestOptionsJSON,
  RegistrationResponseJSON,
} from '@simplewebauthn/server'
import { redirect } from 'next/navigation'
import { z } from 'zod'

import type { ActionResult } from '@/lib/types'
import { runAction } from '@/server/action'
import { deletePasskey } from '@/server/account'
import {
  beginAddPasskey,
  beginSignIn,
  beginSignUp,
  finishAddPasskey,
  finishSignIn,
  finishSignUp,
  regenerateRecoveryCodes,
  signInWithRecoveryCode,
} from '@/server/auth/passkeys'
import { actionSession, endOtherSessions, endSession } from '@/server/auth/session'

// The shape of a WebAuthn response from the browser; the WebAuthn library
// checks the rest (and the signature).
const credential = z.looseObject({
  id: z.string().min(1).max(1024),
  rawId: z.string().min(1).max(1024),
  type: z.literal('public-key'),
  response: z.looseObject({}),
  clientExtensionResults: z.looseObject({}),
})

export async function signInOptions(): Promise<ActionResult<PublicKeyCredentialRequestOptionsJSON>> {
  return runAction('sign-in.begin', beginSignIn)
}

export async function signIn(response: unknown): Promise<ActionResult> {
  return runAction('sign-in.finish', async () => {
    await finishSignIn(credential.parse(response) as unknown as AuthenticationResponseJSON)
    return null
  })
}

const signUpInput = z.object({
  displayName: z.string().max(200),
  workspaceName: z.string().max(200).optional(),
  inviteToken: z.string().max(100).optional(),
})

export async function signUpOptions(
  input: unknown,
): Promise<ActionResult<PublicKeyCredentialCreationOptionsJSON>> {
  return runAction('sign-up.begin', () => beginSignUp(signUpInput.parse(input)))
}

export async function signUp(
  response: unknown,
): Promise<ActionResult<{ workspaceId: string; recoveryCodes: string[] }>> {
  return runAction('sign-up.finish', () =>
    finishSignUp(credential.parse(response) as unknown as RegistrationResponseJSON),
  )
}

export async function recover(code: unknown): Promise<ActionResult> {
  return runAction('recover', async () => {
    await signInWithRecoveryCode(z.string().max(100).parse(code))
    return null
  })
}

export async function addPasskeyOptions(): Promise<ActionResult<PublicKeyCredentialCreationOptionsJSON>> {
  return runAction('passkey.add.begin', async () =>
    beginAddPasskey(await actionSession({ allowRecovered: true })),
  )
}

export async function addPasskey(response: unknown, name: unknown): Promise<ActionResult> {
  return runAction('passkey.add.finish', async () => {
    const session = await actionSession({ allowRecovered: true })
    await finishAddPasskey(
      session,
      credential.parse(response) as unknown as RegistrationResponseJSON,
      z.string().max(200).catch('Passkey').parse(name),
    )
    return null
  })
}

export async function removePasskey(credentialId: unknown): Promise<ActionResult> {
  return runAction('passkey.remove', async () => {
    await deletePasskey(await actionSession(), z.string().min(1).max(1024).parse(credentialId))
    return null
  })
}

export async function newRecoveryCodes(): Promise<ActionResult<string[]>> {
  return runAction('recovery-codes.replace', async () => regenerateRecoveryCodes(await actionSession()))
}

export async function signOutOthers(): Promise<ActionResult<number>> {
  return runAction('sign-out.others', async () =>
    endOtherSessions(await actionSession({ allowRecovered: true })),
  )
}

/** Form action: signs out this browser. */
export async function signOut(): Promise<void> {
  await endSession()
  redirect('/sign-in')
}
