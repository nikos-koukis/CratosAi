'use client'

import { useCallback, useState, useTransition } from 'react'

import type { ActionResult } from '@/lib/types'

/**
 * Runs server actions from event handlers: tracks pending state and the
 * error message to show. `run` resolves to the data, or undefined on failure.
 */
export function useAction() {
  const [pending, startTransition] = useTransition()
  const [error, setError] = useState<string>()
  const [code, setCode] = useState<string>()

  const run = useCallback(<T>(action: () => Promise<ActionResult<T>>): Promise<T | undefined> => {
    return new Promise((resolve) => {
      startTransition(async () => {
        setError(undefined)
        setCode(undefined)
        try {
          const result = await action()
          if (result.ok) {
            resolve(result.data)
          } else {
            setError(result.error)
            setCode(result.code)
            resolve(undefined)
          }
        } catch {
          // The request itself failed (offline, server restarted with a new build).
          setError('Could not reach the dashboard. Check your connection and reload the page.')
          resolve(undefined)
        }
      })
    })
  }, [])

  return { run, pending, error, code, setError }
}
