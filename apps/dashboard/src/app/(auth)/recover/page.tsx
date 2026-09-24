import type { Metadata } from 'next'
import Link from 'next/link'

import { RecoverForm } from '@/components/passkeys'

export const metadata: Metadata = { title: 'Use a recovery code' }

export default function RecoverPage() {
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-lg font-semibold">Use a recovery code</h1>
        <p className="mt-1 text-sm text-zinc-600 dark:text-zinc-400">
          Each code works once. After signing in, add a new passkey.
        </p>
      </div>
      <RecoverForm />
      <p className="text-sm">
        <Link href="/sign-in" className="text-indigo-600 hover:underline dark:text-indigo-400">
          Back to sign in
        </Link>
      </p>
    </div>
  )
}
