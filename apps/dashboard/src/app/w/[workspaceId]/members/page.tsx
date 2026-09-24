import type { Metadata } from 'next'

import { LocalTime } from '@/components/local-time'
import { InviteForm, RemoveMemberButton, RevokeInvitationButton, RoleSelect } from '@/components/members'
import { Badge, Card, Empty, PageHeader } from '@/components/ui'
import { requireWorkspace } from '@/server/access'
import { listInvitations, listMembers } from '@/server/members'

export const metadata: Metadata = { title: 'Members' }

export default async function MembersPage(props: PageProps<'/w/[workspaceId]/members'>) {
  const { workspaceId } = await props.params
  const access = await requireWorkspace(workspaceId)
  const owner = access.workspace.role === 'owner'
  const [members, invitations] = await Promise.all([
    listMembers(access),
    owner ? listInvitations(access) : Promise.resolve([]),
  ])

  return (
    <>
      <PageHeader
        title="Members"
        description="Owners manage keys and members. Members use Jarvis with the workspace’s keys."
      />
      <div className="space-y-6">
        <Card title={`${members.length} ${members.length === 1 ? 'member' : 'members'}`}>
          <ul className="divide-y divide-zinc-200 dark:divide-zinc-800" data-testid="members">
            {members.map((m) => (
              <li key={m.userId} className="flex flex-wrap items-center justify-between gap-3 py-3">
                <div>
                  <p className="font-medium">
                    {m.displayName} {m.you && <Badge tone="accent">you</Badge>}
                  </p>
                  <p className="text-sm text-zinc-500">
                    joined <LocalTime iso={m.joinTime} />
                  </p>
                </div>
                <div className="flex items-center gap-2">
                  {owner ? (
                    <RoleSelect workspaceId={workspaceId} userId={m.userId} role={m.role} />
                  ) : (
                    <Badge>{m.role === 'owner' ? 'Owner' : 'Member'}</Badge>
                  )}
                  {(owner || m.you) && (
                    <RemoveMemberButton
                      workspaceId={workspaceId}
                      userId={m.userId}
                      name={m.displayName}
                      self={m.you}
                    />
                  )}
                </div>
              </li>
            ))}
          </ul>
        </Card>

        {owner && (
          <Card
            title="Invite someone"
            description="They open the link, and sign in or create an account with a passkey."
          >
            <InviteForm workspaceId={workspaceId} />
            <h3 className="mt-6 mb-2 text-sm font-semibold">Pending invitations</h3>
            {invitations.length === 0 ? (
              <Empty>None.</Empty>
            ) : (
              <ul className="divide-y divide-zinc-200 text-sm dark:divide-zinc-800">
                {invitations.map((i) => (
                  <li key={i.invitationId} className="flex flex-wrap items-center justify-between gap-3 py-2">
                    <span>
                      {i.role === 'owner' ? 'Owner' : 'Member'} · by {i.invitedBy ?? 'a former member'} ·
                      expires <LocalTime iso={i.expireTime} />
                    </span>
                    <RevokeInvitationButton workspaceId={workspaceId} invitationId={i.invitationId} />
                  </li>
                ))}
              </ul>
            )}
          </Card>
        )}
      </div>
    </>
  )
}
