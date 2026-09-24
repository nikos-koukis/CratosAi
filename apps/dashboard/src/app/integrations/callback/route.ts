import type { NextRequest } from 'next/server'

import { currentSession } from '@/server/auth/session'
import { config } from '@/server/config'
import { finishAuthorization } from '@/server/integrations'

// Where MCP servers send the browser back after the user allowed (or denied)
// access: MCP_OAUTH_REDIRECT_URI of the router points here.

function redirect(path: string): Response {
  return Response.redirect(new URL(path, config().origin), 303)
}

const param = (url: URL, name: string, max: number) => (url.searchParams.get(name) ?? '').slice(0, max)

export async function GET(request: NextRequest): Promise<Response> {
  const url = new URL(request.url)
  const session = await currentSession()
  if (!session) {
    // Sign in, then come back here (the authorization stays valid for minutes).
    return redirect(`/sign-in?next=${encodeURIComponent(url.pathname + url.search)}`)
  }
  const { workspaceId, outcome } = await finishAuthorization(session, {
    state: param(url, 'state', 1024),
    code: param(url, 'code', 4096),
    iss: param(url, 'iss', 2048),
    error: param(url, 'error', 256),
  })
  return redirect(workspaceId ? `/w/${workspaceId}/integrations?result=${outcome}` : '/integrations/expired')
}
