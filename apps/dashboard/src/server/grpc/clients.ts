import 'server-only'

import type { DescService } from '@bufbuild/protobuf'
import { Code, ConnectError, createClient, type Client, type Interceptor } from '@connectrpc/connect'
import { createGrpcTransport } from '@connectrpc/connect-node'
import { AppAdminService } from '@jarvis/proto/jarvis/app/v1/admin_pb'
import { VaultService } from '@jarvis/proto/jarvis/vault/v1/vault_pb'

import { config } from '../config'
import { uuidv7 } from '../ids'
import { log } from '../log'
import { Problem } from '../problem'

/**
 * Adds an x-request-id to every call (the services audit it with the caller)
 * and logs failures. Requests are never logged: some carry secrets.
 */
export const requestIds: Interceptor = (next) => async (req) => {
  const requestId = uuidv7()
  req.header.set('x-request-id', requestId)
  const started = performance.now()
  try {
    return await next(req)
  } catch (error) {
    const code = ConnectError.from(error).code
    log.warn(
      {
        rpc: `${req.service.typeName}/${req.method.name}`,
        code: Code[code],
        requestId,
        ms: Math.round(performance.now() - started),
      },
      'rpc failed',
    )
    throw error
  }
}

/** A gRPC client over mTLS, as spiffe://jarvis.local/dashboard-api. */
export function grpcClient<S extends DescService>(
  service: S,
  address: string,
  tls = config().tls,
): Client<S> {
  const transport = createGrpcTransport({
    baseUrl: `https://${address}`,
    nodeOptions: { ca: tls.ca, cert: tls.cert, key: tls.key },
    interceptors: [requestIds],
    defaultTimeoutMs: 10_000,
  })
  return createClient(service, transport)
}

const globals = globalThis as typeof globalThis & {
  __jarvisVault?: Client<typeof VaultService>
  __jarvisAppAdmin?: Client<typeof AppAdminService>
}

export function vault(): Client<typeof VaultService> {
  globals.__jarvisVault ??= grpcClient(VaultService, config().vaultAddr)
  return globals.__jarvisVault
}

export function appAdmin(): Client<typeof AppAdminService> {
  globals.__jarvisAppAdmin ??= grpcClient(AppAdminService, config().appAdminAddr)
  return globals.__jarvisAppAdmin
}

/**
 * Turns a service error into a Problem for the user. `what` names the
 * service in messages ("The key vault"). Unexpected codes are rethrown.
 */
export function serviceProblem(error: unknown, what: string): never {
  const e = ConnectError.from(error)
  switch (e.code) {
    case Code.Unavailable:
    case Code.DeadlineExceeded:
    case Code.Canceled:
      throw new Problem('unavailable', `${what} is not reachable right now. Try again in a moment.`)
    case Code.PermissionDenied:
    case Code.Unauthenticated:
      // The dashboard's own identity was refused: a deployment mistake.
      log.error({ code: Code[e.code], service: what }, 'the dashboard is not allowed to call this service')
      throw new Problem('unavailable', `${what} refused the dashboard. Check its access policy.`)
    case Code.InvalidArgument:
      throw new Problem('invalid', e.rawMessage)
    case Code.NotFound:
      throw new Problem('not_found', 'It does not exist, or no longer.')
    case Code.AlreadyExists:
      throw new Problem('conflict', e.rawMessage)
    case Code.FailedPrecondition:
      throw new Problem('conflict', e.rawMessage)
    default:
      throw error
  }
}
