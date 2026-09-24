import 'server-only'

import { AsyncLocalStorage } from 'node:async_hooks'

import { unstable_rethrow } from 'next/navigation'
import { ZodError } from 'zod'

import type { ActionResult } from '@/lib/types'

import { log } from './log'
import { Problem } from './problem'

const running = new AsyncLocalStorage<string>()

/** The name of the server action being run, if any (for the audit trail). */
export function currentAction(): string | undefined {
  return running.getStore()
}

/**
 * Runs a server action's body. Expected failures (Problem, invalid input)
 * become messages for the user; anything else is logged with a short
 * reference the user can quote, and never reaches the browser.
 */
export async function runAction<T>(name: string, body: () => Promise<T>): Promise<ActionResult<T>> {
  try {
    return { ok: true, data: await running.run(name, body) }
  } catch (error) {
    unstable_rethrow(error) // redirect(), notFound(): Next.js control flow, not failures
    if (error instanceof Problem) return { ok: false, error: error.message, code: error.code }
    if (error instanceof ZodError) {
      return { ok: false, error: error.issues[0]?.message ?? 'Check what you entered.', code: 'invalid' }
    }
    const ref = Math.random().toString(36).slice(2, 10)
    log.error({ err: error, action: name, ref }, 'action failed')
    return { ok: false, error: `Something went wrong (ref ${ref}). Please try again.` }
  }
}
