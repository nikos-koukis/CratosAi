'use client'

import { useRouter } from 'next/navigation'
import { useEffect, useRef, useState } from 'react'

import { pairAction, revokeDeviceAction } from '@/actions/workspace'
import type { PairingView } from '@/lib/types'

import { Alert, Button } from './ui'
import { useAction } from './use-action'

function Countdown({ until, onExpired }: { until: string; onExpired: () => void }) {
  const [left, setLeft] = useState(() => Math.max(0, new Date(until).getTime() - Date.now()))
  const expired = useRef(onExpired)
  useEffect(() => {
    expired.current = onExpired
  }, [onExpired])
  useEffect(() => {
    const timer = setInterval(() => {
      const ms = Math.max(0, new Date(until).getTime() - Date.now())
      setLeft(ms)
      if (ms === 0) {
        clearInterval(timer)
        expired.current()
      }
    }, 1000)
    return () => clearInterval(timer)
  }, [until])
  const s = Math.ceil(left / 1000)
  return (
    <span>
      {Math.floor(s / 60)}:{String(s % 60).padStart(2, '0')}
    </span>
  )
}

/** Issues a pairing code and shows it as a QR code for the iPhone's camera. */
export function PairPhone({ workspaceId }: { workspaceId: string }) {
  const router = useRouter()
  const { run, pending, error } = useAction()
  const [pairing, setPairing] = useState<PairingView>()
  const [expired, setExpired] = useState(false)

  async function start() {
    setExpired(false)
    setPairing(await run(() => pairAction(workspaceId)))
  }

  if (!pairing) {
    return (
      <div className="space-y-3">
        <Button onClick={start} disabled={pending}>
          {pending ? 'Creating a code…' : 'Pair an iPhone'}
        </Button>
        {error && <Alert kind="error">{error}</Alert>}
      </div>
    )
  }
  return (
    <div className="flex flex-col gap-6 sm:flex-row sm:items-center">
      {/* eslint-disable-next-line @next/next/no-img-element -- a generated data URL, not an asset */}
      <img
        src={pairing.qrDataUrl}
        alt="Pairing QR code"
        width={208}
        height={208}
        className={`rounded-md bg-white p-2 ${expired ? 'opacity-20' : ''}`}
      />
      <div className="space-y-3 text-sm">
        <ol className="list-decimal space-y-1 pl-5">
          <li>Open the Camera on your iPhone and point it at the code.</li>
          <li>Tap the banner to open Jarvis, which pairs itself.</li>
        </ol>
        <p>
          Or type the code in the app:{' '}
          <strong className="font-mono text-base tracking-wider" data-testid="pairing-code">
            {pairing.code}
          </strong>
        </p>
        {expired ? (
          <Alert kind="warning">The code has expired.</Alert>
        ) : (
          <p className="text-zinc-500">
            Works once, for <Countdown until={pairing.expireTime} onExpired={() => setExpired(true)} />.
          </p>
        )}
        <div className="flex gap-2">
          <Button
            variant="secondary"
            onClick={() => {
              setPairing(undefined)
              router.refresh()
            }}
          >
            Done
          </Button>
          {expired && <Button onClick={start}>New code</Button>}
        </div>
      </div>
    </div>
  )
}

export function RevokeDeviceButton({
  workspaceId,
  sessionId,
  name,
}: {
  workspaceId: string
  sessionId: string
  name: string
}) {
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
              await run(() => revokeDeviceAction(workspaceId, sessionId))
              setConfirming(false)
            }}
          >
            Sign out
          </Button>
          <Button variant="ghost" onClick={() => setConfirming(false)}>
            Cancel
          </Button>
        </>
      ) : (
        <Button variant="ghost" onClick={() => setConfirming(true)} aria-label={`Sign out ${name}`}>
          Sign out…
        </Button>
      )}
    </span>
  )
}
