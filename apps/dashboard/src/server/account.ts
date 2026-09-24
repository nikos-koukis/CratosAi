import 'server-only'

import type { PasskeyView } from '@/lib/types'

import { auditAccount } from './audit'
import type { Session } from './auth/session'
import { withTx } from './db/db'
import { log } from './log'
import { db } from './runtime'
import { countRecoveryCodes, listPasskeys, removePasskey } from './store/accounts'

export async function passkeys(session: Session): Promise<PasskeyView[]> {
  return (await listPasskeys(db(), session.userId)).map((p) => ({
    credentialId: p.credentialId,
    name: p.name,
    synced: p.backedUp,
    createTime: p.createTime.toISOString(),
    lastUseTime: p.lastUseTime?.toISOString() ?? null,
  }))
}

export async function recoveryCodesLeft(session: Session): Promise<number> {
  return countRecoveryCodes(db(), session.userId)
}

/** Removes one of the user's passkeys; never the last one. */
export async function deletePasskey(session: Session, credentialId: string): Promise<void> {
  await withTx(db(), (tx) => removePasskey(tx, session.userId, credentialId))
  log.info({ userId: session.userId }, 'passkey removed')
  await auditAccount(session.userId, { action: 'account.passkey_removed' })
}
