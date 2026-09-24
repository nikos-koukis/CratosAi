import { log } from '@/server/log'
import { db } from '@/server/runtime'

/** Readiness: the dashboard serves and reaches its database. */
export async function GET(): Promise<Response> {
  try {
    await db().query('SELECT 1')
    return Response.json({ status: 'ok' }, { headers: { 'cache-control': 'no-store' } })
  } catch (error) {
    log.warn({ err: (error as Error).message }, 'health check: database unreachable')
    return Response.json({ status: 'unavailable' }, { status: 503, headers: { 'cache-control': 'no-store' } })
  }
}
