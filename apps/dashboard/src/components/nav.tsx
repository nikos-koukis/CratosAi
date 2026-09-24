'use client'

import type { Route } from 'next'
import Link from 'next/link'
import { usePathname, useRouter } from 'next/navigation'

import { Select } from './ui'

export function NavLink({ href, children }: { href: Route; children: React.ReactNode }) {
  const active = usePathname().startsWith(href)
  return (
    <Link
      href={href}
      aria-current={active ? 'page' : undefined}
      className={`block rounded-md px-3 py-2 text-sm font-medium ${
        active
          ? 'bg-zinc-200 text-zinc-900 dark:bg-zinc-800 dark:text-white'
          : 'text-zinc-600 hover:bg-zinc-100 dark:text-zinc-400 dark:hover:bg-zinc-900'
      }`}
    >
      {children}
    </Link>
  )
}

export function WorkspaceSwitcher({
  current,
  workspaces,
}: {
  current: string
  workspaces: { workspaceId: string; name: string }[]
}) {
  const router = useRouter()
  return (
    <Select
      aria-label="Workspace"
      value={current}
      onChange={(e) => {
        const id = e.target.value
        router.push((id === 'new' ? '/workspaces/new' : `/w/${id}/keys`) as Route)
      }}
    >
      {workspaces.map((w) => (
        <option key={w.workspaceId} value={w.workspaceId}>
          {w.name}
        </option>
      ))}
      <option value="new">+ New workspace…</option>
    </Select>
  )
}
