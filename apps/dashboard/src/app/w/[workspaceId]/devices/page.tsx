import type { Metadata } from 'next'

import { PairPhone, RevokeDeviceButton } from '@/components/devices'
import { LocalTime } from '@/components/local-time'
import { Alert, Card, Empty, PageHeader } from '@/components/ui'
import type { DeviceView } from '@/lib/types'
import { requireWorkspace } from '@/server/access'
import { listDevices } from '@/server/devices'
import { Problem } from '@/server/problem'

export const metadata: Metadata = { title: 'Devices' }

export default async function DevicesPage(props: PageProps<'/w/[workspaceId]/devices'>) {
  const { workspaceId } = await props.params
  const access = await requireWorkspace(workspaceId)

  let devices: DeviceView[] = []
  let unavailable: string | undefined
  try {
    devices = await listDevices(access)
  } catch (error) {
    if (!(error instanceof Problem)) throw error
    unavailable = error.message
  }

  return (
    <>
      <PageHeader
        title="Devices"
        description={`Your phones with the Jarvis app, signed in to ${access.workspace.name}. Only you see them.`}
      />
      <div className="space-y-6">
        {unavailable && <Alert kind="error">{unavailable}</Alert>}
        <Card title="Pair an iPhone" description="Pairing signs the app in as you, in this workspace.">
          <PairPhone workspaceId={workspaceId} />
        </Card>
        <Card title="Signed-in phones">
          {devices.length === 0 ? (
            <Empty>No phones yet.</Empty>
          ) : (
            <ul className="divide-y divide-zinc-200 dark:divide-zinc-800" data-testid="devices">
              {devices.map((d) => (
                <li key={d.sessionId} className="flex flex-wrap items-center justify-between gap-3 py-3">
                  <div>
                    <p className="font-medium">{d.deviceName || 'iPhone'}</p>
                    <p className="text-sm text-zinc-500">
                      {d.deviceModel} · paired <LocalTime iso={d.createTime} /> · last used{' '}
                      <LocalTime iso={d.lastUseTime} />
                    </p>
                  </div>
                  <RevokeDeviceButton
                    workspaceId={workspaceId}
                    sessionId={d.sessionId}
                    name={d.deviceName || 'iPhone'}
                  />
                </li>
              ))}
            </ul>
          )}
        </Card>
      </div>
    </>
  )
}
