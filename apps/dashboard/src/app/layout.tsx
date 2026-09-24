import type { Metadata } from 'next'
import { connection } from 'next/server'

import { RecoveryCodesHost } from '@/components/passkeys'

import './globals.css'

export const metadata: Metadata = {
  title: { default: 'Jarvis', template: '%s · Jarvis' },
  description: 'Manage your Jarvis workspaces, provider keys and devices.',
  robots: { index: false, follow: false },
}

export default async function RootLayout({ children }: LayoutProps<'/'>) {
  // Render every page per request, so each gets its own CSP nonce (src/proxy.ts).
  await connection()
  return (
    <html lang="en">
      <body className="min-h-dvh bg-zinc-50 font-sans text-zinc-900 antialiased dark:bg-zinc-950 dark:text-zinc-100">
        {children}
        <RecoveryCodesHost />
      </body>
    </html>
  )
}
