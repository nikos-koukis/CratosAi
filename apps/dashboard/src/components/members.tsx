'use client'

import type { Route } from 'next'
import { useRouter } from 'next/navigation'
import { useState } from 'react'

import {
  changeRoleAction,
  createWorkspaceAction,
  inviteAction,
  joinAction,
  removeMemberAction,
  revokeInvitationAction,
} from '@/actions/workspace'
import type { Role } from '@/lib/types'

import { Alert, Button, Field, Input, Select } from './ui'
import { useAction } from './use-action'

export function InviteForm({ workspaceId }: { workspaceId: string }) {
  const { run, pending, error } = useAction()
  const [role, setRole] = useState<Role>('member')
  const [link, setLink] = useState<string>()
  const [copied, setCopied] = useState(false)

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-end gap-2">
        <Field label="Role" htmlFor="invite-role">
          <Select
            id="invite-role"
            value={role}
            onChange={(e) => setRole(e.target.value as Role)}
            className="w-auto"
          >
            <option value="member">Member: uses Jarvis, sees the keys</option>
            <option value="owner">Owner: also manages keys and members</option>
          </Select>
        </Field>
        <Button
          disabled={pending}
          onClick={async () => {
            setCopied(false)
            const invitation = await run(() => inviteAction(workspaceId, role))
            if (invitation) setLink(invitation.url)
          }}
        >
          Create invitation link
        </Button>
      </div>
      {link && (
        <div className="space-y-2">
          <Alert kind="info">
            Send this link to the person you invite. It works once, for 7 days, and is shown only now.
          </Alert>
          <div className="flex gap-2">
            <Input
              readOnly
              value={link}
              className="font-mono text-xs"
              aria-label="Invitation link"
              data-testid="invitation-link"
            />
            <Button
              variant="secondary"
              onClick={async () => {
                await navigator.clipboard.writeText(link)
                setCopied(true)
              }}
            >
              {copied ? 'Copied' : 'Copy'}
            </Button>
          </div>
        </div>
      )}
      {error && <Alert kind="error">{error}</Alert>}
    </div>
  )
}

export function RevokeInvitationButton({
  workspaceId,
  invitationId,
}: {
  workspaceId: string
  invitationId: string
}) {
  const { run, pending, error } = useAction()
  return (
    <span className="flex items-center justify-end gap-2">
      {error && <span className="text-sm text-red-600 dark:text-red-400">{error}</span>}
      <Button
        variant="ghost"
        disabled={pending}
        onClick={() => run(() => revokeInvitationAction(workspaceId, invitationId))}
      >
        Withdraw
      </Button>
    </span>
  )
}

export function RoleSelect({
  workspaceId,
  userId,
  role,
}: {
  workspaceId: string
  userId: string
  role: Role
}) {
  const { run, pending, error } = useAction()
  return (
    <span className="flex items-center justify-end gap-2">
      {error && <span className="text-sm text-red-600 dark:text-red-400">{error}</span>}
      <Select
        aria-label="Role"
        value={role}
        disabled={pending}
        className="w-auto"
        onChange={(e) => run(() => changeRoleAction(workspaceId, userId, e.target.value))}
      >
        <option value="member">Member</option>
        <option value="owner">Owner</option>
      </Select>
    </span>
  )
}

export function RemoveMemberButton({
  workspaceId,
  userId,
  name,
  self,
}: {
  workspaceId: string
  userId: string
  name: string
  self: boolean
}) {
  const router = useRouter()
  const { run, pending, error } = useAction()
  const [confirming, setConfirming] = useState(false)
  async function remove() {
    const result = await run(() => removeMemberAction(workspaceId, userId))
    setConfirming(false)
    if (result?.left) router.replace('/')
  }
  return (
    <span className="flex items-center justify-end gap-2">
      {error && <span className="text-sm text-red-600 dark:text-red-400">{error}</span>}
      {confirming ? (
        <>
          <Button variant="danger" onClick={remove} disabled={pending}>
            {self ? 'Leave' : 'Remove'}
          </Button>
          <Button variant="ghost" onClick={() => setConfirming(false)}>
            Cancel
          </Button>
        </>
      ) : (
        <Button
          variant="ghost"
          onClick={() => setConfirming(true)}
          aria-label={self ? 'Leave workspace' : `Remove ${name}`}
        >
          {self ? 'Leave…' : 'Remove…'}
        </Button>
      )}
    </span>
  )
}

export function JoinButton({ token }: { token: string }) {
  const router = useRouter()
  const { run, pending, error } = useAction()
  return (
    <div className="space-y-3">
      <Button
        className="w-full"
        disabled={pending}
        onClick={async () => {
          const workspaceId = await run(() => joinAction(token))
          if (workspaceId) router.replace(`/w/${workspaceId}/keys` as Route)
        }}
      >
        Join workspace
      </Button>
      {error && <Alert kind="error">{error}</Alert>}
    </div>
  )
}

export function NewWorkspaceForm() {
  const router = useRouter()
  const { run, pending, error } = useAction()
  async function submit(form: FormData) {
    const workspaceId = await run(() => createWorkspaceAction(form.get('name')))
    if (workspaceId) router.replace(`/w/${workspaceId}/keys` as Route)
  }
  return (
    <form action={submit} className="space-y-4">
      <Field label="Workspace name" htmlFor="name">
        <Input id="name" name="name" required maxLength={64} />
      </Field>
      <Button type="submit" disabled={pending}>
        Create workspace
      </Button>
      {error && <Alert kind="error">{error}</Alert>}
    </form>
  )
}
