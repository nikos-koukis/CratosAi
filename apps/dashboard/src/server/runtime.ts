import 'server-only'

import type pg from 'pg'

import { config } from './config'
import { createPool, migrate } from './db/db'
import { log } from './log'
import { purgeExpired } from './store/accounts'

// Process-wide resources. Kept on globalThis so that development reloads
// reuse them instead of opening new pools.
const globals = globalThis as typeof globalThis & { __jarvisDashboardPool?: pg.Pool }

/** The database pool of this process. */
export function db(): pg.Pool {
  globals.__jarvisDashboardPool ??= createPool(config().databaseUrl)
  return globals.__jarvisDashboardPool
}

/** Startup: check the configuration, migrate, and schedule housekeeping. */
export async function start(): Promise<void> {
  const cfg = config() // throws, and stops the server, if the configuration is wrong
  const applied = await migrate(db())
  log.info(
    { origin: cfg.origin.origin, rpID: cfg.rpID, vault: cfg.vaultAddr, appAdmin: cfg.appAdminAddr, applied },
    'dashboard ready',
  )
  const housekeeping = setInterval(
    () => {
      purgeExpired(db()).catch((error: unknown) => log.warn({ err: error }, 'purging expired records failed'))
    },
    60 * 60 * 1000,
  )
  housekeeping.unref()
}
