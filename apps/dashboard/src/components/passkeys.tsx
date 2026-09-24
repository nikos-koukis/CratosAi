'use client'

import {
  browserSupportsWebAuthn,
  startAuthentication,
  startRegistration,
  WebAuthnError,
} from '@simplewebauthn/browser'
import type { Route } from 'next'
import { useRouter } from 'next/navigation'
import { useState, useSyncExternalStore } from 'react'

import {
  addPasskey,
  addPasskeyOptions,
  newRecoveryCodes,
  recover,
  removePasskey,
  signIn,
  signInOptions,
  signOutOthers,
  signUp,
  signUpOptions,
} from '@/actions/auth'

import { safeNext } from '@/lib/next'

import { Alert, Button, Field, Input } from './ui'
import { useAction } from './use-action'

/** What went wrong in the browser's passkey prompt, in words. */
function passkeyError(error: unknown): string {
  const code = error instanceof WebAuthnError ? error.code : undefined
  const name = error instanceof Error ? error.name : undefined
  if (code === 'ERROR_CEREMONY_ABORTED' || name === 'NotAllowedError' || name === 'AbortError') {
    return 'The passkey prompt was cancelled or timed out.'
  }
  if (code === 'ERROR_AUTHENTICATOR_PREVIOUSLY_REGISTERED' || name === 'InvalidStateError') {
    return 'This device already has a passkey for your account.'
  }
  return 'Your browser could not use a passkey here.'
}

const never = () => () => {}

/** Whether the browser can use passkeys; undefined while rendering on the server. */
function useWebAuthnSupport(): boolean | undefined {
  return useSyncExternalStore(never, browserSupportsWebAuthn, () => undefined)
}

function Unsupported() {
  return (
    <Alert kind="error">
      This browser does not support passkeys. Use a current Safari, Chrome, Edge or Firefox.
    </Alert>
  )
}

export function SignInWithPasskey({ next }: { next?: string }) {
  const router = useRouter()
  const supported = useWebAuthnSupport()
  const { run, pending, error, setError } = useAction()

  async function go() {
    const options = await run(signInOptions)
    if (!options) return
    let response
    try {
      response = await startAuthentication({ optionsJSON: options })
    } catch (e) {
      setError(passkeyError(e))
      return
    }
    if ((await run(() => signIn(response))) !== undefined) router.replace(safeNext(next))
  }

  if (supported === false) return <Unsupported />
  return (
    <div className="space-y-3">
      <Button className="w-full" onClick={go} disabled={pending || !supported}>
        {pending ? 'Waiting for your passkey…' : 'Sign in with a passkey'}
      </Button>
      {error && <Alert kind="error">{error}</Alert>}
    </div>
  )
}

// New recovery codes waiting to be saved. They live outside the page that
// created them: signing up sets the session cookie, which re-renders that
// page (it redirects signed-in users), and the codes must survive it.
let pendingCodes: { codes: string[]; next: Route } | undefined
const codeListeners = new Set<() => void>()

function showRecoveryCodes(codes: string[], next: Route): void {
  pendingCodes = { codes, next }
  codeListeners.forEach((listener) => listener())
}

function subscribeToCodes(listener: () => void): () => void {
  codeListeners.add(listener)
  return () => codeListeners.delete(listener)
}

/** In the root layout: shows new recovery codes over any page until they are saved. */
export function RecoveryCodesHost() {
  const router = useRouter()
  const pending = useSyncExternalStore(
    subscribeToCodes,
    () => pendingCodes,
    () => undefined,
  )
  if (!pending) return null
  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-labelledby="recovery-codes-title"
      className="fixed inset-0 z-50 flex items-center justify-center bg-zinc-950/60 p-4"
    >
      <div className="w-full max-w-md space-y-4 rounded-lg bg-white p-6 shadow-xl dark:bg-zinc-900">
        <h2 id="recovery-codes-title" className="text-lg font-semibold">
          Your account is ready
        </h2>
        <RecoveryCodes
          codes={pending.codes}
          onDone={() => {
            pendingCodes = undefined
            codeListeners.forEach((listener) => listener())
            router.replace(pending.next)
          }}
        />
      </div>
    </div>
  )
}

/** Recovery codes, shown once, with a way to keep them. */
export function RecoveryCodes({ codes, onDone }: { codes: string[]; onDone: () => void }) {
  const [saved, setSaved] = useState(false)
  const text = `Jarvis recovery codes (each works once):\n\n${codes.join('\n')}\n`
  return (
    <div className="space-y-4">
      <Alert kind="warning">
        Keep these recovery codes somewhere safe, such as your password manager. Each one signs you in once if
        you lose your passkeys. They are shown only now.
      </Alert>
      <ol
        className="grid grid-cols-2 gap-2 rounded-md bg-zinc-100 p-3 font-mono text-sm dark:bg-zinc-800"
        data-testid="recovery-codes"
      >
        {codes.map((c) => (
          <li key={c}>{c}</li>
        ))}
      </ol>
      <div className="flex flex-wrap gap-2">
        <Button variant="secondary" onClick={() => void navigator.clipboard.writeText(text)}>
          Copy
        </Button>
        <a
          className="inline-flex items-center rounded-md px-3 py-2 text-sm font-medium ring-1 ring-zinc-300 dark:ring-zinc-700"
          href={`data:text/plain;charset=utf-8,${encodeURIComponent(text)}`}
          download="jarvis-recovery-codes.txt"
        >
          Download
        </a>
      </div>
      <label className="flex items-center gap-2 text-sm">
        <input type="checkbox" checked={saved} onChange={(e) => setSaved(e.target.checked)} />I have saved my
        recovery codes
      </label>
      <Button className="w-full" disabled={!saved} onClick={onDone}>
        Continue
      </Button>
    </div>
  )
}

/**
 * Creates an account with a passkey: a new workspace, or (with an invitation
 * token) joining that invitation's workspace.
 */
export function SignUpForm({ inviteToken, workspaceName }: { inviteToken?: string; workspaceName?: string }) {
  const supported = useWebAuthnSupport()
  const { run, pending, error, setError } = useAction()

  async function submit(form: FormData) {
    const options = await run(() =>
      signUpOptions({
        displayName: String(form.get('displayName') ?? ''),
        workspaceName: inviteToken ? undefined : String(form.get('workspaceName') ?? ''),
        inviteToken,
      }),
    )
    if (!options) return
    let response
    try {
      response = await startRegistration({ optionsJSON: options })
    } catch (e) {
      setError(passkeyError(e))
      return
    }
    const account = await run(() => signUp(response))
    // Shown by the root layout: signing in re-renders (and redirects) this page.
    if (account) showRecoveryCodes(account.recoveryCodes, `/w/${account.workspaceId}/keys` as Route)
  }

  if (supported === false) return <Unsupported />
  return (
    <form action={submit} className="space-y-4">
      <Field label="Your name" htmlFor="displayName">
        <Input id="displayName" name="displayName" required maxLength={64} autoComplete="name" />
      </Field>
      {inviteToken ? (
        <p className="text-sm text-zinc-600 dark:text-zinc-400">
          You will join <strong>{workspaceName}</strong>.
        </p>
      ) : (
        <Field
          label="Workspace name"
          htmlFor="workspaceName"
          hint="Your team or project. You can create more later."
        >
          <Input id="workspaceName" name="workspaceName" required maxLength={64} />
        </Field>
      )}
      <Button type="submit" className="w-full" disabled={pending || !supported}>
        {pending ? 'Creating your passkey…' : 'Create account with a passkey'}
      </Button>
      {error && <Alert kind="error">{error}</Alert>}
    </form>
  )
}

export function RecoverForm() {
  const router = useRouter()
  const { run, pending, error } = useAction()
  async function submit(form: FormData) {
    if ((await run(() => recover(form.get('code')))) !== undefined) router.replace('/account')
  }
  return (
    <form action={submit} className="space-y-4">
      <Field
        label="Recovery code"
        htmlFor="code"
        hint="One of the codes you saved when you created your account."
      >
        <Input
          id="code"
          name="code"
          required
          autoComplete="one-time-code"
          placeholder="XXXX-XXXX-XXXX"
          className="font-mono uppercase"
        />
      </Field>
      <Button type="submit" className="w-full" disabled={pending}>
        Sign in
      </Button>
      {error && <Alert kind="error">{error}</Alert>}
    </form>
  )
}

export function AddPasskeyForm({ recovered = false }: { recovered?: boolean }) {
  const router = useRouter()
  const supported = useWebAuthnSupport()
  const { run, pending, error, setError } = useAction()
  const [added, setAdded] = useState(false)

  async function submit(form: FormData) {
    setAdded(false)
    const options = await run(addPasskeyOptions)
    if (!options) return
    let response
    try {
      response = await startRegistration({ optionsJSON: options })
    } catch (e) {
      setError(passkeyError(e))
      return
    }
    if ((await run(() => addPasskey(response, form.get('name')))) !== undefined) {
      setAdded(true)
      router.refresh()
      if (recovered) router.replace('/')
    }
  }

  if (supported === false) return <Unsupported />
  return (
    <form action={submit} className="flex flex-col gap-3 sm:flex-row sm:items-end">
      <div className="flex-1">
        <Field label="Name" htmlFor="passkey-name" hint="To recognize it later, e.g. “MacBook” or “iPhone”.">
          <Input id="passkey-name" name="name" maxLength={64} placeholder="Passkey" />
        </Field>
      </div>
      <Button type="submit" disabled={pending || !supported}>
        {pending ? 'Waiting for your passkey…' : 'Add a passkey'}
      </Button>
      {error && <Alert kind="error">{error}</Alert>}
      {added && <Alert kind="success">Passkey added.</Alert>}
    </form>
  )
}

export function RemovePasskeyButton({ credentialId }: { credentialId: string }) {
  const router = useRouter()
  const { run, pending, error } = useAction()
  const [confirming, setConfirming] = useState(false)
  async function remove() {
    if ((await run(() => removePasskey(credentialId))) !== undefined) router.refresh()
    setConfirming(false)
  }
  return (
    <span className="flex items-center gap-2">
      {error && <span className="text-sm text-red-600 dark:text-red-400">{error}</span>}
      {confirming ? (
        <>
          <Button variant="danger" onClick={remove} disabled={pending}>
            Remove
          </Button>
          <Button variant="ghost" onClick={() => setConfirming(false)}>
            Cancel
          </Button>
        </>
      ) : (
        <Button variant="ghost" onClick={() => setConfirming(true)}>
          Remove…
        </Button>
      )}
    </span>
  )
}

export function NewRecoveryCodes() {
  const router = useRouter()
  const { run, pending, error } = useAction()
  const [codes, setCodes] = useState<string[]>()
  if (codes) {
    return (
      <RecoveryCodes
        codes={codes}
        onDone={() => {
          setCodes(undefined)
          router.refresh()
        }}
      />
    )
  }
  return (
    <div className="space-y-2">
      <Button
        variant="secondary"
        disabled={pending}
        onClick={async () => setCodes(await run(newRecoveryCodes))}
      >
        Create new recovery codes
      </Button>
      <p className="text-xs text-zinc-500">Your current codes stop working.</p>
      {error && <Alert kind="error">{error}</Alert>}
    </div>
  )
}

export function SignOutOthersButton() {
  const { run, pending, error } = useAction()
  const [count, setCount] = useState<number>()
  return (
    <div className="space-y-2">
      <Button variant="secondary" disabled={pending} onClick={async () => setCount(await run(signOutOthers))}>
        Sign out other browsers
      </Button>
      {count !== undefined && <Alert kind="success">Signed out {count} other browser session(s).</Alert>}
      {error && <Alert kind="error">{error}</Alert>}
    </div>
  )
}
