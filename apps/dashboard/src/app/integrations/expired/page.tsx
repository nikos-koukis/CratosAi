import type { Metadata } from 'next'
import Link from 'next/link'

export const metadata: Metadata = { title: 'Connection not completed' }

/** An authorization callback that was not started by this user, or took too long. */
export default function AuthorizationExpired() {
  return (
    <main className="flex min-h-dvh flex-col items-center justify-center gap-3 p-6 text-center">
      <h1 className="text-xl font-semibold">Connection not completed</h1>
      <p className="max-w-md text-sm text-zinc-600 dark:text-zinc-400">
        This sign-in link was not started from your account in this browser, or it expired. Start the
        connection again from Integrations.
      </p>
      <Link href="/" className="text-sm text-indigo-600 hover:underline dark:text-indigo-400">
        Go to your workspaces
      </Link>
    </main>
  )
}
