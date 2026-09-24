import { describe, expect, it } from 'vitest'

import { Problem } from '@/server/problem'
import { RateLimiter } from '@/server/ratelimit'

describe('rate limiter', () => {
  it('allows max attempts per window and key, then refuses until the window ends', () => {
    let now = 0
    const limiter = new RateLimiter(3, 60_000, () => now)
    for (let i = 0; i < 3; i++) limiter.hit('a')
    expect(() => limiter.hit('a')).toThrow(Problem)
    limiter.hit('b') // another client is not affected

    now = 30_000
    try {
      limiter.hit('a')
      throw new Error('expected a rate limit')
    } catch (error) {
      expect((error as Problem).code).toBe('rate_limited')
      expect((error as Problem).message).toContain('30 seconds')
    }

    now = 60_000
    limiter.hit('a') // a new window
  })
})
