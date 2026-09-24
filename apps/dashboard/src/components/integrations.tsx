'use client'

import { useRouter } from 'next/navigation'
import { useState } from 'react'

import { connectAction, disconnectAction, reconnectAction } from '@/actions/workspace'

import { Alert, Button, Field, Input } from './ui'
import { useAction } from './use-action'

/** Connects a catalog server that signs in with OAuth: off to the server, then back. */
export function ConnectButton({
  workspaceId,
  slug,
  name,
}: {
  workspaceId: string
  slug: string
  name: string
}) {
  const { run, pending, error } = useAction()
  return (
    <div className="space-y-2">
      <Button
        variant="secondary"
        disabled={pending}
        aria-label={`Connect ${name}`}
        onClick={async () => {
          const result = await run(() => connectAction(workspaceId, { slug }))
          if (result?.authorizationUrl) window.location.assign(result.authorizationUrl)
        }}
      >
        {pending ? 'Opening…' : 'Connect'}
      </Button>
      {error && <Alert kind="error">{error}</Alert>}
    </div>
  )
}

/** Connects a catalog server that takes an API token (e.g. a GitHub personal access token). */
export function TokenConnectForm({
  workspaceId,
  slug,
  name,
}: {
  workspaceId: string
  slug: string
  name: string
}) {
  const { run, pending, error } = useAction()
  const [open, setOpen] = useState(false)
  if (!open) {
    return (
      <Button variant="secondary" onClick={() => setOpen(true)} aria-label={`Connect ${name}`}>
        Connect…
      </Button>
    )
  }
  return (
    <form
      autoComplete="off"
      className="space-y-2"
      action={async (form) => {
        const result = await run(() =>
          connectAction(workspaceId, { slug, token: String(form.get('token') ?? '') }),
        )
        if (result) setOpen(false)
      }}
    >
      <Field label={`${name} token`} htmlFor={`token-${slug}`} hint="Stored encrypted; never shown again.">
        <Input
          id={`token-${slug}`}
          name="token"
          type="password"
          required
          autoComplete="off"
          spellCheck={false}
        />
      </Field>
      <div className="flex gap-2">
        <Button type="submit" disabled={pending}>
          Connect
        </Button>
        <Button variant="ghost" onClick={() => setOpen(false)}>
          Cancel
        </Button>
      </div>
      {error && <Alert kind="error">{error}</Alert>}
    </form>
  )
}

/** Any MCP server by URL; it signs in with OAuth unless a token is given. */
export function CustomServerForm({ workspaceId }: { workspaceId: string }) {
  const { run, pending, error } = useAction()
  return (
    <form
      autoComplete="off"
      className="space-y-4"
      action={async (form) => {
        const token = String(form.get('token') ?? '').trim()
        const result = await run(() =>
          connectAction(workspaceId, {
            url: String(form.get('url') ?? '').trim(),
            name: String(form.get('name') ?? '').trim() || undefined,
            token: token || undefined,
          }),
        )
        if (result?.authorizationUrl) window.location.assign(result.authorizationUrl)
      }}
    >
      <div className="grid gap-4 sm:grid-cols-2">
        <Field
          label="Server URL"
          htmlFor="server-url"
          hint="The server’s MCP endpoint, e.g. https://mcp.example.com/mcp"
        >
          <Input id="server-url" name="url" type="url" required spellCheck={false} />
        </Field>
        <Field label="Name" htmlFor="server-name" hint="Optional, e.g. “Work tracker”.">
          <Input id="server-name" name="name" maxLength={64} />
        </Field>
      </div>
      <Field
        label="API token"
        htmlFor="server-token"
        hint="Only if the server uses a token instead of signing in."
      >
        <Input id="server-token" name="token" type="password" autoComplete="off" spellCheck={false} />
      </Field>
      <Button type="submit" disabled={pending}>
        {pending ? 'Connecting…' : 'Connect server'}
      </Button>
      {error && <Alert kind="error">{error}</Alert>}
    </form>
  )
}

export function ReconnectButton({
  workspaceId,
  integrationId,
}: {
  workspaceId: string
  integrationId: string
}) {
  const { run, pending, error } = useAction()
  return (
    <span className="flex items-center justify-end gap-2">
      {error && <span className="text-sm text-red-600 dark:text-red-400">{error}</span>}
      <Button
        variant="secondary"
        disabled={pending}
        onClick={async () => {
          const url = await run(() => reconnectAction(workspaceId, integrationId))
          if (url) window.location.assign(url)
        }}
      >
        Sign in again
      </Button>
    </span>
  )
}

export function DisconnectButton({
  workspaceId,
  integrationId,
  name,
}: {
  workspaceId: string
  integrationId: string
  name: string
}) {
  const router = useRouter()
  const { run, pending, error } = useAction()
  const [confirming, setConfirming] = useState(false)
  return (
    <span className="flex items-center justify-end gap-2">
      {error && <span className="text-sm text-red-600 dark:text-red-400">{error}</span>}
      {confirming ? (
        <>
          <Button
            variant="danger"
            disabled={pending}
            onClick={async () => {
              if ((await run(() => disconnectAction(workspaceId, integrationId))) !== undefined)
                router.refresh()
              setConfirming(false)
            }}
          >
            Disconnect
          </Button>
          <Button variant="ghost" onClick={() => setConfirming(false)}>
            Cancel
          </Button>
        </>
      ) : (
        <Button variant="ghost" onClick={() => setConfirming(true)} aria-label={`Disconnect ${name}`}>
          Disconnect…
        </Button>
      )}
    </span>
  )
}
