import 'server-only'

import { Code, ConnectError } from '@connectrpc/connect'
import { timestampDate, type Timestamp } from '@bufbuild/protobuf/wkt'
import { Provider } from '@jarvis/proto/jarvis/common/v1/provider_pb'
import { KeyStatus, RevocationReason, type KeyMetadata } from '@jarvis/proto/jarvis/vault/v1/vault_pb'
import { z } from 'zod'

import { PROVIDERS, providerLabel, type KeyView, type ProviderId } from '@/lib/types'

import type { Access } from './access'
import { audit, person } from './audit'
import { nameSchema } from './auth/passkeys'
import { serviceProblem, vault } from './grpc/clients'
import { uuidv7 } from './ids'
import { log } from './log'
import { Problem } from './problem'

// The workspace's provider API keys, kept by the Vault. The dashboard never
// reads a key back: it stores, lists (metadata only) and revokes.

const VAULT = 'The key vault'

const toProvider: Record<ProviderId, Provider> = {
  openai: Provider.OPENAI,
  xai: Provider.XAI,
  anthropic: Provider.ANTHROPIC,
  google: Provider.GOOGLE,
}

function fromProvider(p: Provider): ProviderId | undefined {
  return (Object.entries(toProvider) as [ProviderId, Provider][]).find(([, v]) => v === p)?.[0]
}

const REASONS: Partial<Record<RevocationReason, NonNullable<KeyView['revocationReason']>>> = {
  [RevocationReason.USER_REQUESTED]: 'user_requested',
  [RevocationReason.ROTATED]: 'rotated',
  [RevocationReason.COMPROMISED]: 'compromised',
}

const iso = (t: Timestamp | undefined) => (t ? timestampDate(t).toISOString() : null)

function view(key: KeyMetadata): KeyView | undefined {
  const provider = fromProvider(key.provider)
  if (!provider) return undefined // a provider this dashboard does not know yet
  return {
    keyId: key.keyId,
    provider,
    label: key.label,
    hint: key.keyHint,
    status: key.status === KeyStatus.ACTIVE ? 'active' : 'revoked',
    createTime: iso(key.createTime) ?? '',
    revokeTime: iso(key.revokeTime),
    revocationReason: REASONS[key.revocationReason] ?? null,
  }
}

export async function listKeys(access: Access, includeRevoked: boolean): Promise<KeyView[]> {
  try {
    const { keys } = await vault().listKeys({ tenantId: access.workspace.workspaceId, includeRevoked })
    return keys.map(view).filter((k): k is KeyView => k !== undefined)
  } catch (error) {
    serviceProblem(error, VAULT)
  }
}

export const addKeySchema = z.object({
  provider: z.enum(PROVIDERS.map((p) => p.id) as [ProviderId, ...ProviderId[]], {
    error: 'Choose a provider.',
  }),
  label: nameSchema('Give the key a label.'),
  // The Vault's rule: 16 to 8192 printable ASCII characters.
  secret: z
    .string()
    .trim()
    .regex(/^[\x21-\x7e]{16,8192}$/, 'Paste the whole API key (at least 16 characters, no spaces).'),
  replace: z.boolean(),
})

/**
 * Stores a key for the workspace (owners only). With `replace`, it replaces
 * the provider's active key at once, without a gap.
 */
export async function addKey(
  access: Access,
  input: z.infer<typeof addKeySchema>,
): Promise<KeyView | undefined> {
  const secret = Buffer.from(input.secret, 'utf8')
  try {
    const { key, replacedKey } = await vault().createKey({
      tenantId: access.workspace.workspaceId,
      provider: toProvider[input.provider],
      label: input.label,
      secret,
      replaceActive: input.replace,
      requestId: uuidv7(),
    })
    log.info(
      {
        userId: access.session.userId,
        workspaceId: access.workspace.workspaceId,
        keyId: key?.keyId,
        replacedKeyId: replacedKey?.keyId,
        provider: input.provider,
      },
      'provider key stored',
    )
    audit({
      tenantId: access.workspace.workspaceId,
      actor: person(access.session.userId),
      action: 'key.stored',
      targetType: 'provider_key',
      targetId: key?.keyId,
      details: {
        provider: input.provider,
        label: input.label,
        ...(replacedKey ? { replaced_key: replacedKey.keyId } : {}),
      },
    })
    return key && view(key)
  } catch (error) {
    if (ConnectError.from(error).code === Code.AlreadyExists && !input.replace) {
      throw new Problem(
        'conflict',
        `The workspace already has an active ${providerLabel(input.provider)} key. Replace it, or revoke it first.`,
      )
    }
    serviceProblem(error, VAULT)
  } finally {
    secret.fill(0) // the request was serialized; drop our copy
  }
}

export const revokeKeySchema = z.object({
  keyId: z.uuid(),
  reason: z.enum(['user_requested', 'compromised']),
})

/** Revokes a key (owners only): its ciphertext is destroyed; irreversible. */
export async function revokeKey(access: Access, input: z.infer<typeof revokeKeySchema>): Promise<void> {
  try {
    await vault().revokeKey({
      tenantId: access.workspace.workspaceId,
      keyId: input.keyId,
      reason: input.reason === 'compromised' ? RevocationReason.COMPROMISED : RevocationReason.USER_REQUESTED,
    })
    log.info(
      {
        userId: access.session.userId,
        workspaceId: access.workspace.workspaceId,
        keyId: input.keyId,
        reason: input.reason,
      },
      'provider key revoked',
    )
    audit({
      tenantId: access.workspace.workspaceId,
      actor: person(access.session.userId),
      action: 'key.revoked',
      targetType: 'provider_key',
      targetId: input.keyId,
      details: { reason: input.reason },
    })
  } catch (error) {
    serviceProblem(error, VAULT)
  }
}
