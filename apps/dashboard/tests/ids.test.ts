import { describe, expect, it } from 'vitest'

import { isUuid, normalizeRecoveryCode, randomToken, recoveryCode, sha256, uuidv7 } from '@/server/ids'

describe('uuidv7', () => {
  it('is a canonical version 7 UUID carrying the time', () => {
    const now = Date.UTC(2026, 8, 24, 12, 0, 0)
    const id = uuidv7(now)
    expect(isUuid(id)).toBe(true)
    expect(id[14]).toBe('7')
    expect('89ab').toContain(id[19])
    expect(parseInt(id.replace(/-/g, '').slice(0, 12), 16)).toBe(now)
  })

  it('sorts by time', () => {
    const ids = [3, 1, 2].map((t) => uuidv7(1_700_000_000_000 + t))
    expect([...ids].sort()).toEqual([ids[1], ids[2], ids[0]])
  })

  it('is random within a millisecond', () => {
    const ids = new Set(Array.from({ length: 1000 }, () => uuidv7(1)))
    expect(ids.size).toBe(1000)
  })
})

describe('tokens', () => {
  it('have 256 bits and are stored hashed', () => {
    const token = randomToken()
    expect(Buffer.from(token, 'base64url')).toHaveLength(32)
    expect(sha256(token)).toHaveLength(32)
    expect(sha256(token).equals(sha256(token))).toBe(true)
    expect(randomToken()).not.toBe(token)
  })
})

describe('recovery codes', () => {
  it('look like XXXX-XXXX-XXXX in Crockford base32', () => {
    for (let i = 0; i < 200; i++) {
      expect(recoveryCode()).toMatch(/^[0-9A-HJKMNP-TV-Z]{4}-[0-9A-HJKMNP-TV-Z]{4}-[0-9A-HJKMNP-TV-Z]{4}$/)
    }
  })

  it('are forgiving to type', () => {
    const code = '7KQ2-M9XD-4TFA'
    expect(normalizeRecoveryCode(' 7kq2 m9xd 4tfa ')).toBe(code)
    expect(normalizeRecoveryCode('7KQ2M9XD4TFA')).toBe(code)
    expect(normalizeRecoveryCode('1OIL-0000-0000')).toBe('1011-0000-0000') // O→0, I/L→1
  })

  it('refuse what cannot be a code', () => {
    for (const bad of ['', '7KQ2-M9XD-4TF', '7KQ2-M9XD-4TFAX', '7KQ2-M9XD-4TFU', 'ÄKQ2-M9XD-4TFA']) {
      expect(normalizeRecoveryCode(bad)).toBeUndefined()
    }
  })
})
