import type { Route } from 'next'
import { redirect } from 'next/navigation'

export default async function WorkspaceHome(props: PageProps<'/w/[workspaceId]'>) {
  const { workspaceId } = await props.params
  redirect(`/w/${workspaceId}/keys` as Route)
}
