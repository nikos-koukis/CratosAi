import type { AuditEventView } from './types'

// How the audit trail reads: categories to filter by (action prefixes) and a
// sentence for each action. Unknown actions show as they are.

export const AUDIT_CATEGORIES = [
  { id: 'account', label: 'Sign-ins and account', prefix: 'account.' },
  { id: 'workspace', label: 'Workspace and members', prefix: 'workspace.' },
  { id: 'key', label: 'Provider keys', prefix: 'key.' },
  { id: 'device', label: 'Phones', prefix: 'device.' },
  { id: 'integration', label: 'Integrations', prefix: 'integration.' },
  { id: 'tool', label: 'Tool calls', prefix: 'tool.' },
  { id: 'task', label: 'Background tasks', prefix: 'task.' },
  { id: 'action', label: 'Confirmations', prefix: 'action.' },
  { id: 'command', label: 'Computer commands', prefix: 'command.' },
] as const

export type AuditCategory = (typeof AUDIT_CATEGORIES)[number]['id']

const ACTIONS: Record<string, string> = {
  'account.signed_up': 'Created an account',
  'account.signed_in': 'Signed in',
  'account.sign_in_failed': 'Failed to sign in',
  'account.recovery_code_used': 'Signed in with a recovery code',
  'account.signed_out': 'Signed out',
  'account.signed_out_elsewhere': 'Signed out other browsers',
  'account.passkey_added': 'Added a passkey',
  'account.passkey_removed': 'Removed a passkey',
  'account.recovery_codes_replaced': 'Replaced the recovery codes',
  'workspace.created': 'Created the workspace',
  'workspace.access_denied': 'Tried something only owners may do',
  'workspace.member_invited': 'Invited someone',
  'workspace.invitation_revoked': 'Withdrew an invitation',
  'workspace.member_joined': 'Joined the workspace',
  'workspace.member_role_changed': 'Changed a member’s role',
  'workspace.member_removed': 'Removed a member',
  'workspace.member_left': 'Left the workspace',
  'key.stored': 'Stored a provider key',
  'key.created': 'Stored a provider key',
  'key.revoked': 'Revoked a provider key',
  'key.read': 'Used a provider key',
  'device.pairing_code_issued': 'Created a pairing code',
  'device.paired': 'Paired a phone',
  'device.signed_out': 'Signed a phone out',
  'device.token_reused': 'Reused an old sign-in token (possible theft)',
  'integration.created': 'Added an integration',
  'integration.connected': 'Connected an integration',
  'integration.authorization_failed': 'Failed to authorize an integration',
  'integration.deleted': 'Removed an integration',
  'integration.needs_reauthorization': 'An integration needs signing in again',
  'tool.called': 'Called a tool',
  'task.started': 'Started a background task',
  'task.finished': 'Finished a background task',
  'task.cancelled': 'Cancelled a background task',
  'action.confirmation_requested': 'Asked for confirmation',
  'action.confirmed': 'Confirmed an action',
  'action.declined': 'Declined an action',
  'action.confirmation_blocked': 'Stopped an action nobody confirmed',
  'command.approval_requested': 'Asked to approve a command',
  'command.approval_submitted': 'Answered a command approval',
  'command.ran': 'Ran a command',
  'command.not_run': 'Did not run a command',
}

/** A sentence for an action, e.g. "Stored a provider key". */
export function describeAction(action: string): string {
  return ACTIONS[action] ?? action
}

/** The event's thing, e.g. "provider key 0199e2e0…". */
export function describeTarget(e: Pick<AuditEventView, 'targetType' | 'targetId'>): string | null {
  if (!e.targetType && !e.targetId) return null
  const type = e.targetType.replaceAll('_', ' ')
  const id = e.targetId.length > 13 ? `${e.targetId.slice(0, 8)}…` : e.targetId
  return [type, id].filter(Boolean).join(' ')
}

const SERVICES: Record<string, string> = {
  'dashboard-api': 'Dashboard',
  vault: 'Key vault',
  'app-api': 'App service',
  'mcp-router': 'Integrations service',
  orchestrator: 'Orchestrator',
  'voice-gateway': 'Voice service',
}

/** A service's name for people, from its name or identity (spiffe://jarvis.local/<name>). */
export function serviceLabel(name: string): string {
  const short = name.slice(name.lastIndexOf('/') + 1)
  return SERVICES[short] ?? short
}
