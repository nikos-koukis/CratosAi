import { fileURLToPath } from 'node:url'

import { defineConfig } from 'vitest/config'

export default defineConfig({
  resolve: {
    alias: {
      '@': fileURLToPath(new URL('./src', import.meta.url)),
      // 'server-only' refuses to load outside React Server Components; tests are server code.
      'server-only': fileURLToPath(new URL('./tests/support/empty.ts', import.meta.url)),
    },
  },
  test: {
    environment: 'node',
    // Nothing listens on port 9: tests that check audit events start a fake audit service.
    env: { LOG_LEVEL: 'silent', DASHBOARD_AUDIT_ADDR: '127.0.0.1:9' },
    include: ['tests/**/*.test.ts'],
    // PostgreSQL containers start once per file.
    testTimeout: 30_000,
    hookTimeout: 180_000,
    // Env-configured singletons (pool, gRPC clients) must not be shared across files.
    isolate: true,
  },
})
