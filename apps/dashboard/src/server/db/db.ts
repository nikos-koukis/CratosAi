import 'server-only'

import pg from 'pg'

import { migrations } from './migrations'

/** Anything that runs queries: the pool, or a client inside a transaction. */
export type Queryable = Pick<pg.Pool, 'query'>

export function createPool(connectionString: string): pg.Pool {
  const pool = new pg.Pool({
    connectionString,
    max: 10,
    idleTimeoutMillis: 30_000,
    connectionTimeoutMillis: 5_000,
    // A runaway query must not hold a request forever.
    statement_timeout: 10_000,
    application_name: 'dashboard',
  })
  return pool
}

/** Runs fn in a transaction; commits if it returns, rolls back if it throws. */
export async function withTx<T>(pool: pg.Pool, fn: (client: pg.PoolClient) => Promise<T>): Promise<T> {
  const client = await pool.connect()
  try {
    await client.query('BEGIN')
    const result = await fn(client)
    await client.query('COMMIT')
    return result
  } catch (error) {
    await client.query('ROLLBACK').catch(() => undefined)
    throw error
  } finally {
    client.release()
  }
}

// Any fixed number: serializes migrations across dashboard instances.
const MIGRATION_LOCK = 7_345_120_931

/** Applies the migrations not yet applied, each in its own transaction. */
export async function migrate(pool: pg.Pool): Promise<string[]> {
  const client = await pool.connect()
  const applied: string[] = []
  try {
    await client.query('SELECT pg_advisory_lock($1)', [MIGRATION_LOCK])
    await client.query(`CREATE TABLE IF NOT EXISTS schema_migrations (
      version text PRIMARY KEY, apply_time timestamptz NOT NULL DEFAULT now())`)
    const { rows } = await client.query<{ version: string }>('SELECT version FROM schema_migrations')
    const done = new Set(rows.map((r) => r.version))
    for (const migration of migrations) {
      if (done.has(migration.version)) continue
      await client.query('BEGIN')
      try {
        await client.query(migration.sql)
        await client.query('INSERT INTO schema_migrations (version) VALUES ($1)', [migration.version])
        await client.query('COMMIT')
      } catch (error) {
        await client.query('ROLLBACK').catch(() => undefined)
        throw new Error(`migration ${migration.version} failed`, { cause: error })
      }
      applied.push(migration.version)
    }
  } finally {
    await client.query('SELECT pg_advisory_unlock($1)', [MIGRATION_LOCK]).catch(() => undefined)
    client.release()
  }
  return applied
}
