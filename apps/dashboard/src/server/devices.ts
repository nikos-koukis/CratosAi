import 'server-only'

import { timestampDate } from '@bufbuild/protobuf/wkt'
import QRCode from 'qrcode'
import { z } from 'zod'

import type { DeviceView, PairingView } from '@/lib/types'

import type { Access } from './access'
import { audit, person } from './audit'
import { appAdmin, serviceProblem } from './grpc/clients'
import { log } from './log'

// The signed-in user's phones in this workspace: pairing codes and the app
// sessions they became (the app API keeps them).

const APP_API = 'The app service'

/** A one-time code (and its QR) that pairs the Jarvis app with this user and workspace. */
export async function createPairing(access: Access): Promise<PairingView> {
  let response
  try {
    response = await appAdmin().createPairingCode({
      tenantId: access.workspace.workspaceId,
      userId: access.session.userId,
    })
  } catch (error) {
    serviceProblem(error, APP_API)
  }
  const svg = await QRCode.toString(response.pairingUrl, {
    type: 'svg',
    errorCorrectionLevel: 'M',
    margin: 1,
  })
  log.info(
    { userId: access.session.userId, workspaceId: access.workspace.workspaceId },
    'pairing code issued',
  )
  audit({
    tenantId: access.workspace.workspaceId,
    actor: person(access.session.userId),
    action: 'device.pairing_code_issued',
  })
  return {
    code: response.code,
    pairingUrl: response.pairingUrl,
    qrDataUrl: `data:image/svg+xml;base64,${Buffer.from(svg).toString('base64')}`,
    expireTime: response.expireTime ? timestampDate(response.expireTime).toISOString() : '',
  }
}

export async function listDevices(access: Access): Promise<DeviceView[]> {
  try {
    const { sessions } = await appAdmin().listSessions({
      tenantId: access.workspace.workspaceId,
      userId: access.session.userId,
    })
    return sessions.map((s) => ({
      sessionId: s.sessionId,
      deviceName: s.deviceName,
      deviceModel: s.deviceModel,
      createTime: s.createTime ? timestampDate(s.createTime).toISOString() : '',
      lastUseTime: s.lastUseTime ? timestampDate(s.lastUseTime).toISOString() : null,
    }))
  } catch (error) {
    serviceProblem(error, APP_API)
  }
}

export const revokeDeviceSchema = z.object({ sessionId: z.uuid() })

/** Signs a phone out: its tokens stop working at once (voice within 15 minutes). */
export async function revokeDevice(access: Access, input: z.infer<typeof revokeDeviceSchema>): Promise<void> {
  try {
    await appAdmin().revokeSession({
      tenantId: access.workspace.workspaceId,
      userId: access.session.userId,
      sessionId: input.sessionId,
    })
    log.info(
      {
        userId: access.session.userId,
        workspaceId: access.workspace.workspaceId,
        sessionId: input.sessionId,
      },
      'app session revoked',
    )
    audit({
      tenantId: access.workspace.workspaceId,
      actor: person(access.session.userId),
      action: 'device.signed_out',
      targetType: 'app_session',
      targetId: input.sessionId,
    })
  } catch (error) {
    serviceProblem(error, APP_API)
  }
}
