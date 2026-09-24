// Types shared by the server and the browser: only what pages render.

export const PROVIDERS = [
  { id: 'openai', label: 'OpenAI' },
  { id: 'xai', label: 'xAI' },
  { id: 'anthropic', label: 'Anthropic' },
  { id: 'google', label: 'Google Gemini' },
] as const

export type ProviderId = (typeof PROVIDERS)[number]['id']

export function providerLabel(id: ProviderId): string {
  return PROVIDERS.find((p) => p.id === id)?.label ?? id
}

export type Role = 'owner' | 'member'

export type KeyView = {
  keyId: string
  provider: ProviderId
  label: string
  /** Last four characters, for recognizing the key. */
  hint: string
  status: 'active' | 'revoked'
  createTime: string
  revokeTime: string | null
  revocationReason: 'user_requested' | 'rotated' | 'compromised' | null
}

export type DeviceView = {
  sessionId: string
  deviceName: string
  deviceModel: string
  createTime: string
  lastUseTime: string | null
}

export type PairingView = {
  code: string
  /** jarvis://pair?server=…&code=…, as a QR code (SVG data URL). */
  qrDataUrl: string
  pairingUrl: string
  expireTime: string
}

export type MemberView = { userId: string; displayName: string; role: Role; joinTime: string; you: boolean }

export type InvitationView = {
  invitationId: string
  role: Role
  invitedBy: string | null
  createTime: string
  expireTime: string
}

export type PasskeyView = {
  credentialId: string
  name: string
  synced: boolean
  createTime: string
  lastUseTime: string | null
}

/** What a server action returns to the browser. */
export type ActionResult<T = null> = { ok: true; data: T } | { ok: false; error: string; code?: string }
