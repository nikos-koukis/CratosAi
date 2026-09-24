import 'server-only'

export type ProblemCode =
  | 'unauthenticated'
  | 'forbidden'
  | 'not_found'
  | 'invalid'
  | 'conflict'
  | 'last_owner'
  | 'last_passkey'
  | 'expired'
  | 'rate_limited'
  | 'unavailable'

/**
 * An expected failure with a message fit for the user. Anything else that is
 * thrown is a bug or an outage: it is logged, and the user sees a generic
 * message with a request id.
 */
export class Problem extends Error {
  constructor(
    readonly code: ProblemCode,
    message: string,
  ) {
    super(message)
    this.name = 'Problem'
  }
}
