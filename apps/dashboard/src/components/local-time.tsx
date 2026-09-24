'use client'

import { useSyncExternalStore } from 'react'

const never = () => () => {}

function utc(iso: string): string {
  return `${iso.slice(0, 16).replace('T', ' ')} UTC`
}

/**
 * A time in the viewer's time zone. The server renders UTC, and the browser
 * switches to local time once hydrated (so both first renders match).
 */
export function LocalTime({ iso }: { iso: string | null }) {
  const text = useSyncExternalStore(
    never,
    () => (iso ? new Date(iso).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' }) : '—'),
    () => (iso ? utc(iso) : '—'),
  )
  return iso ? <time dateTime={iso}>{text}</time> : <span>—</span>
}
