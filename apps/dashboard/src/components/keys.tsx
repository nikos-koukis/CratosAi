'use client'

import { useRef, useState } from 'react'

import { addKeyAction, revokeKeyAction } from '@/actions/workspace'
import { PROVIDERS, providerLabel, type ProviderId } from '@/lib/types'

import { Alert, Button, Field, Input, Select } from './ui'
import { useAction } from './use-action'

export function AddKeyForm({
  workspaceId,
  activeProviders,
}: {
  workspaceId: string
  activeProviders: ProviderId[]
}) {
  const form = useRef<HTMLFormElement>(null)
  const { run, pending, error } = useAction()
  const [provider, setProvider] = useState<ProviderId>('openai')
  const [stored, setStored] = useState<string>()
  const replacing = activeProviders.includes(provider)

  async function submit(data: FormData) {
    setStored(undefined)
    const key = await run(() =>
      addKeyAction(workspaceId, {
        provider,
        label: String(data.get('label') ?? ''),
        secret: String(data.get('secret') ?? ''),
        replace: replacing && data.get('replace') === 'on',
      }),
    )
    if (key !== undefined) {
      form.current?.reset() // the secret leaves the page
      setStored(`${providerLabel(provider)} key stored.`)
    }
  }

  return (
    <form ref={form} action={submit} className="space-y-4" autoComplete="off">
      <div className="grid gap-4 sm:grid-cols-2">
        <Field label="Provider" htmlFor="provider">
          <Select id="provider" value={provider} onChange={(e) => setProvider(e.target.value as ProviderId)}>
            {PROVIDERS.map((p) => (
              <option key={p.id} value={p.id}>
                {p.label}
              </option>
            ))}
          </Select>
        </Field>
        <Field label="Label" htmlFor="label" hint="For you, e.g. “Production”.">
          <Input id="label" name="label" required maxLength={64} />
        </Field>
      </div>
      <Field
        label="API key"
        htmlFor="secret"
        hint="Sent once to the vault, which encrypts it. Nobody can read it back here, including you."
      >
        <Input
          id="secret"
          name="secret"
          type="password"
          required
          minLength={16}
          autoComplete="off"
          spellCheck={false}
          className="font-mono"
        />
      </Field>
      {replacing && (
        <label className="flex items-start gap-2 text-sm">
          <input type="checkbox" name="replace" className="mt-0.5" />
          <span>
            Replace the active {providerLabel(provider)} key. Jarvis switches to the new key at once, and the
            old one is revoked.
          </span>
        </label>
      )}
      <Button type="submit" disabled={pending}>
        {pending ? 'Storing…' : 'Store key'}
      </Button>
      {error && <Alert kind="error">{error}</Alert>}
      {stored && <Alert kind="success">{stored}</Alert>}
    </form>
  )
}

export function RevokeKeyButton({
  workspaceId,
  keyId,
  label,
}: {
  workspaceId: string
  keyId: string
  label: string
}) {
  const { run, pending, error } = useAction()
  const [confirming, setConfirming] = useState(false)
  const [reason, setReason] = useState<'user_requested' | 'compromised'>('user_requested')

  if (!confirming) {
    return (
      <Button variant="ghost" onClick={() => setConfirming(true)} aria-label={`Revoke ${label}`}>
        Revoke…
      </Button>
    )
  }
  return (
    <div className="flex flex-wrap items-center justify-end gap-2">
      <Select
        aria-label="Why"
        value={reason}
        onChange={(e) => setReason(e.target.value as typeof reason)}
        className="w-auto"
      >
        <option value="user_requested">No longer needed</option>
        <option value="compromised">Leaked or suspected leaked</option>
      </Select>
      <Button
        variant="danger"
        disabled={pending}
        onClick={async () => {
          if ((await run(() => revokeKeyAction(workspaceId, { keyId, reason }))) !== undefined)
            setConfirming(false)
        }}
      >
        Revoke for good
      </Button>
      <Button variant="ghost" onClick={() => setConfirming(false)}>
        Cancel
      </Button>
      {error && <Alert kind="error">{error}</Alert>}
    </div>
  )
}
