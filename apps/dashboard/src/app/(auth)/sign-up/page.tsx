import type { Metadata } from 'next'
import Link from 'next/link'
import { redirect } from 'next/navigation'

import { SignUpForm } from '@/components/passkeys'
import { currentSession } from '@/server/auth/session'

export const metadata: Metadata = { title: 'Create an account' }

export default async function SignUpPage() {
  if (await currentSession()) redirect('/')
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-lg font-semibold">Create an account</h1>
        <p className="mt-1 text-sm text-zinc-600 dark:text-zinc-400">
          No password: you sign in with a passkey, using Face ID, Touch ID or your device’s PIN.
        </p>
      </div>
      <SignUpForm />
      <p className="text-sm">
        <Link href="/sign-in" className="text-indigo-600 hover:underline dark:text-indigo-400">
          I already have an account
        </Link>
      </p>
    </div>
  )
}
