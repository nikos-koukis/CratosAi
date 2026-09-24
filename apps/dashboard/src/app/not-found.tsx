import Link from 'next/link'

export default function NotFound() {
  return (
    <main className="flex min-h-dvh flex-col items-center justify-center gap-3 p-6 text-center">
      <h1 className="text-xl font-semibold">Not found</h1>
      <p className="text-sm text-zinc-600 dark:text-zinc-400">
        This page does not exist, or you do not have access to it.
      </p>
      <Link href="/" className="text-sm text-indigo-600 hover:underline dark:text-indigo-400">
        Go to your workspaces
      </Link>
    </main>
  )
}
