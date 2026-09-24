import { PostgreSqlContainer, type StartedPostgreSqlContainer } from '@testcontainers/postgresql'
import type pg from 'pg'

import { createPool, migrate } from '@/server/db/db'

export type TestDatabase = { container: StartedPostgreSqlContainer; pool: pg.Pool; url: string }

/** A throwaway PostgreSQL (the version compose runs), migrated. Needs Docker. */
export async function startPostgres(): Promise<TestDatabase> {
  const container = await new PostgreSqlContainer('postgres:18.6-alpine').start()
  const url = container.getConnectionUri()
  const pool = createPool(url)
  await migrate(pool)
  return { container, pool, url }
}

export async function stopPostgres(db: TestDatabase | undefined): Promise<void> {
  await db?.pool.end()
  await db?.container.stop()
}
