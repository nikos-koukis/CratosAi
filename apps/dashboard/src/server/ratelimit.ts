import 'server-only'

import { Problem } from './problem'

type Window = { count: number; resetAt: number }

/**
 * Fixed-window rate limits, in memory: per process, which is enough for one
 * instance and a first line for several. Keys are bucket + client address.
 */
export class RateLimiter {
  private readonly windows = new Map<string, Window>()

  constructor(
    private readonly max: number,
    private readonly windowMs: number,
    private readonly now: () => number = Date.now,
  ) {}

  /** Counts an attempt; throws a rate_limited Problem when over the limit. */
  hit(key: string): void {
    const now = this.now()
    let window = this.windows.get(key)
    if (!window || window.resetAt <= now) {
      if (this.windows.size >= 10_000) this.prune(now)
      window = { count: 0, resetAt: now + this.windowMs }
      this.windows.set(key, window)
    }
    window.count++
    if (window.count > this.max) {
      const seconds = Math.ceil((window.resetAt - now) / 1000)
      throw new Problem('rate_limited', `Too many attempts. Try again in ${seconds} seconds.`)
    }
  }

  private prune(now: number): void {
    for (const [key, window] of this.windows) if (window.resetAt <= now) this.windows.delete(key)
  }
}

/** Starting a sign-in or sign-up (passkey ceremonies). */
export const ceremonyLimit = new RateLimiter(30, 60_000)
/** Recovery codes: few tries, as they are what an attacker would guess. */
export const recoveryLimit = new RateLimiter(5, 5 * 60_000)
