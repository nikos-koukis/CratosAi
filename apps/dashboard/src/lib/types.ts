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

export type CatalogServerView = {
  slug: string
  name: string
  /** oauth: sign in at the server; token: paste an API token. */
  auth: 'oauth' | 'token'
  /** False when whoever runs Jarvis has not set it up (OAuth client credentials). */
  available: boolean
  notes: string
}

export type IntegrationView = {
  integrationId: string
  name: string
  serverUrl: string
  catalogSlug: string | null
  auth: 'oauth' | 'token'
  status: 'connected' | 'pending' | 'needs_reauthorization'
  statusDetail: string
  createTime: string
}

export type ToolView = {
  integrationId: string
  name: string
  title: string
  description: string
  readOnly: boolean
}

export type ToolsView = {
  tools: ToolView[]
  /** Connections whose tools could not be listed, and why. */
  unavailable: { integrationId: string; message: string }[]
}

/** How an OAuth authorization came back to the dashboard. */
export type AuthorizationOutcome = 'connected' | 'denied' | 'failed' | 'expired'

/** One entry of a workspace's audit trail, ready to show. */
export type AuditEventView = {
  eventId: string
  sequence: string
  occurTime: string
  actorKind: 'user' | 'assistant' | 'device' | 'service' | 'unknown'
  /** Who did it: a member's name, "Jarvis", a phone, a computer or a service. */
  actor: string
  /** The person an assistant, device or service acted for. */
  onBehalfOf: string | null
  action: string
  targetType: string
  targetId: string
  outcome: 'success' | 'failure' | 'denied'
  reason: string
  details: [string, string][]
  /** The service that recorded it. */
  source: string
}

export type AuditPageView = {
  events: AuditEventView[]
  /** Opaque; the next (older) page, if any. */
  nextPage: string | null
}

export type ChainView = {
  intact: boolean
  events: string
  firstBrokenSequence: string | null
  headHash: string
}
