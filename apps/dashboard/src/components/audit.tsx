'use client'

import { useState } from 'react'

import { verifyTrailAction } from '@/actions/workspace'
import type { ChainView } from '@/lib/types'

import { Alert, Button } from './ui'
import { useAction } from './use-action'

/** Recomputes the workspace's hash chain at the audit service and says whether it holds. */
export function VerifyTrail({ workspaceId }: { workspaceId: string }) {
  const { run, pending, error } = useAction()
  const [result, setResult] = useState<ChainView>()

  return (
    <div className="space-y-3">
      <Button
        variant="secondary"
        disabled={pending}
        onClick={async () => setResult(await run(() => verifyTrailAction(workspaceId)))}
      >
        {pending ? 'Checking…' : 'Verify the trail'}
      </Button>
      {error && <Alert kind="error">{error}</Alert>}
      {result &&
        (result.intact ? (
          <Alert kind="success">
            Intact: all {result.events} events are unchanged and in order.
            {result.headHash && (
              <span className="mt-1 block font-mono text-xs break-all opacity-80">
                Latest hash {result.headHash}
              </span>
            )}
          </Alert>
        ) : (
          <Alert kind="error">
            The trail was altered: the chain breaks at event #{result.firstBrokenSequence}. Report this to
            whoever runs Jarvis.
          </Alert>
        ))}
    </div>
  )
}
