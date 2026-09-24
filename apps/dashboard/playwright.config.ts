import { defineConfig } from '@playwright/test'

/**
 * End-to-end tests against a running dashboard and the real services behind
 * it (start them with tools/dev-stack.sh up). Passkeys come from Chrome's
 * virtual authenticator. Uses the installed Google Chrome, headless, with a
 * throwaway profile.
 */
export default defineConfig({
  testDir: 'e2e',
  timeout: 90_000,
  expect: { timeout: 15_000 },
  workers: 1,
  reporter: [['list']],
  use: {
    baseURL: process.env.E2E_BASE_URL ?? 'http://localhost:3000',
    channel: 'chrome',
    trace: 'retain-on-failure',
  },
})
