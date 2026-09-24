import type { Metadata, Route } from 'next'
import Link from 'next/link'

import { JoinButton } from '@/components/members'
import { SignUpForm } from '@/components/passkeys'
import { Alert } from '@/components/ui'
import { currentSession } from '@/server/auth/session'
import { invitationFor } from '@/server/members'
import { db } from '@/server/runtime'
import { getMembership } from '@/server/store/workspaces'

export const metadata: Metadata = { title: 'Invitation', referrer: 'no-referrer' }

const UNUSABLE = {
  expired: 'This invitation has expired. Ask for a new one.',
  used: 'This invitation has already been used.',
  revoked: 'This invitation was withdrawn.',
}

export default async function InvitePage(props: PageProps<'/invite/[token]'>) {
  const { token } = await props.params
  const invitation = await invitationFor(token)
  if (!invitation) return <Alert kind="error">This invitation link is not valid.</Alert>
  if (invitation.state !== 'pending') return <Alert kind="error">{UNUSABLE[invitation.state]}</Alert>

  const session = await currentSession()
  const intro = (
    <div>
      <h1 className="text-lg font-semibold">Join {invitation.workspaceName}</h1>
      <p className="mt-1 text-sm text-zinc-600 dark:text-zinc-400">
        {invitation.invitedBy ?? 'Someone'} invited you as{' '}
        {invitation.role === 'owner' ? 'an owner' : 'a member'}.
      </p>
    </div>
  )

  if (session) {
    const member = await getMembership(db(), invitation.workspaceId, session.userId)
    return (
      <div className="space-y-6">
        {intro}
        {member ? (
          <Alert kind="info">
            You are already a member.{' '}
            <Link className="underline" href={`/w/${invitation.workspaceId}/keys` as Route}>
              Open the workspace
            </Link>
          </Alert>
        ) : (
          <>
            <p className="text-sm">Signed in as {session.displayName}.</p>
            <JoinButton token={token} />
          </>
        )}
      </div>
    )
  }
  return (
    <div className="space-y-6">
      {intro}
      <SignUpForm inviteToken={token} workspaceName={invitation.workspaceName} />
      <p className="text-sm text-zinc-600 dark:text-zinc-400">
        Already have an account?{' '}
        <Link
          href={`/sign-in?next=${encodeURIComponent(`/invite/${token}`)}` as Route}
          className="text-indigo-600 hover:underline dark:text-indigo-400"
        >
          Sign in
        </Link>{' '}
        and you will come back here.
      </p>
    </div>
  )
}
