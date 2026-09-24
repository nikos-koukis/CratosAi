import 'server-only'

import pino from 'pino'

/**
 * Structured JSON logs. Secrets never reach a log call by design; the
 * redaction below is a second line of defence for fields with these names.
 */
export const log = pino({
  level: process.env.LOG_LEVEL ?? 'info',
  base: { service: 'dashboard' },
  timestamp: pino.stdTimeFunctions.isoTime,
  formatters: { level: (label) => ({ level: label }) },
  redact: {
    paths: [
      'secret',
      '*.secret',
      'token',
      '*.token',
      'code',
      '*.code',
      'cookie',
      '*.cookie',
      'authorization',
      '*.authorization',
      'pairingUrl',
      '*.pairingUrl',
    ],
    censor: '[redacted]',
  },
})
