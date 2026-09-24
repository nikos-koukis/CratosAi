import type { Metadata } from 'next'
import Link from 'next/link'
import { redirect } from 'next/navigation'

import { SignInWithPasskey } from '@/components/passkeys'
import { safeNext } from '@/lib/next'
import { currentSession } from '@/server/auth/session'

export const metadata: Metadata = { title: 'Sign in' }

export default async function SignInPage(props: PageProps<'/sign-in'>) {
  const { next } = await props.searchParams
  // Signed in (also right after signing in here): go where the user was headed.
  if (await currentSession()) redirect(safeNext(next))
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-lg font-semibold">Sign in</h1>
        <p className="mt-1 text-sm text-zinc-600 dark:text-zinc-400">
          With the passkey you created for Jarvis.
        </p>
      </div>
      <SignInWithPasskey next={typeof next === 'string' ? next : undefined} />
      <div className="flex justify-between text-sm">
        <Link href="/sign-up" className="text-indigo-600 hover:underline dark:text-indigo-400">
          Create an account
        </Link>
        <Link href="/recover" className="text-zinc-600 hover:underline dark:text-zinc-400">
          Lost your passkey?
        </Link>
      </div>
    </div>
  )
}
