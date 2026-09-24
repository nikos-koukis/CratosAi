import type { Instrumentation } from 'next'

/** Runs once when the server starts, before it takes requests. */
export async function register(): Promise<void> {
  if (process.env.NEXT_RUNTIME === 'nodejs') {
    const { start } = await import('./server/runtime')
    await start()
  }
}

/** Server errors Next.js caught (in rendering, actions or route handlers). */
export const onRequestError: Instrumentation.onRequestError = async (error, request, context) => {
  if (process.env.NEXT_RUNTIME !== 'nodejs') return
  const { log } = await import('./server/log')
  const digest =
    typeof error === 'object' && error !== null && 'digest' in error ? String(error.digest) : undefined
  // The route pattern, not the path: invitation links carry their token in it.
  log.error({ err: error, digest, method: request.method, route: context.routePath }, 'request failed')
}
