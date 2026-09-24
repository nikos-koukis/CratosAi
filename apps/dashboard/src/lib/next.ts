import type { Route } from 'next'

/**
 * Where to go after signing in: only a path inside the dashboard, never
 * another site (no "//host" or "/\host", which browsers treat as absolute).
 */
export function safeNext(next: unknown): Route {
  return (typeof next === 'string' && /^\/(?![/\\])/.test(next) ? next : '/') as Route
}
