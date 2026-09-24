'use client'

import { Button } from '@/components/ui'

/** Shown when rendering a page fails. Details are in the server log, under the digest. */
export default function ErrorPage({
  error,
  reset,
}: {
  error: Error & { digest?: string }
  reset: () => void
}) {
  return (
    <main className="flex min-h-dvh flex-col items-center justify-center gap-3 p-6 text-center">
      <h1 className="text-xl font-semibold">Something went wrong</h1>
      <p className="text-sm text-zinc-600 dark:text-zinc-400">
        Please try again.
        {error.digest && (
          <>
            {' '}
            Reference: <code>{error.digest}</code>
          </>
        )}
      </p>
      <Button onClick={reset}>Try again</Button>
    </main>
  )
}
