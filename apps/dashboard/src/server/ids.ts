import 'server-only'

import { createHash, randomBytes } from 'node:crypto'

/**
 * A UUIDv7 (RFC 9562): 48-bit Unix milliseconds, then randomness. Time-ordered,
 * like the ids the other services create.
 */
export function uuidv7(now: number = Date.now()): string {
  const bytes = randomBytes(16)
  bytes.writeUIntBE(now, 0, 6)
  bytes[6] = (bytes[6]! & 0x0f) | 0x70 // version 7
  bytes[8] = (bytes[8]! & 0x3f) | 0x80 // variant 10
  const hex = bytes.toString('hex')
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/

/** Whether a string is a lowercase canonical UUID. */
export function isUuid(value: unknown): value is string {
  return typeof value === 'string' && UUID.test(value)
}

/** A random bearer token: `bytes` of entropy, base64url. */
export function randomToken(bytes = 32): string {
  return randomBytes(bytes).toString('base64url')
}

/** What the database keeps of a bearer token. */
export function sha256(value: string): Buffer {
  return createHash('sha256').update(value, 'utf8').digest()
}

// Crockford base32 without I, L, O, U: easy to read aloud and type.
const CROCKFORD = '0123456789ABCDEFGHJKMNPQRSTVWXYZ'

/** A recovery code: 60 random bits as XXXX-XXXX-XXXX. */
export function recoveryCode(): string {
  const random = randomBytes(8).readBigUInt64BE() >> 4n // 60 bits
  let chars = ''
  for (let i = 11; i >= 0; i--) chars += CROCKFORD[Number((random >> BigInt(i * 5)) & 31n)]
  return `${chars.slice(0, 4)}-${chars.slice(4, 8)}-${chars.slice(8)}`
}

/**
 * Normalizes what a user typed as a recovery code (case, spaces, dashes, and
 * the letters Crockford reads as digits); undefined if it cannot be one.
 */
export function normalizeRecoveryCode(input: string): string | undefined {
  const chars = input.toUpperCase().replace(/[\s-]/g, '').replace(/O/g, '0').replace(/[IL]/g, '1')
  if (chars.length !== 12 || [...chars].some((c) => !CROCKFORD.includes(c))) return undefined
  return `${chars.slice(0, 4)}-${chars.slice(4, 8)}-${chars.slice(8)}`
}
