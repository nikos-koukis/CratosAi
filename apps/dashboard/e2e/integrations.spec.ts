import { randomBytes } from 'node:crypto'

import { expect, test } from '@playwright/test'

import { person, signUp } from './support'

// Connecting an MCP server through the real MCP router, with OAuth against
// the development fake server (mcpctl dev-server, which approves at once).

const FAKE_MCP = 'http://127.0.0.1:8931/mcp'

test('connect an MCP server with OAuth, see its tools, disconnect', async ({ browser }) => {
  const run = randomBytes(3).toString('hex')
  const page = await person(browser)
  const workspaceUrl = await signUp(page, `Owner ${run}`, `E2E ${run}`)

  await page.getByRole('link', { name: 'Integrations' }).click()
  await expect(page.getByTestId('catalog')).toContainText('Linear')
  await expect(page.getByText('No connections yet.')).toBeVisible()

  // Off to the server's sign-in, and back through the dashboard's callback.
  let callback = ''
  page.on('request', (request) => {
    if (request.url().includes('/integrations/callback')) callback = request.url()
  })
  await page.getByLabel('Server URL').fill(FAKE_MCP)
  await page.getByLabel('Name', { exact: true }).fill(`Tracker ${run}`)
  await page.getByRole('button', { name: 'Connect server' }).click()
  await expect(page).toHaveURL(`${workspaceUrl}/integrations?result=connected`)
  await expect(page.getByText('Connected. Jarvis can use its tools')).toBeVisible()
  expect(callback).toMatch(/[?&]state=/)

  const connection = page
    .getByTestId('integrations')
    .locator('li')
    .filter({ hasText: `Tracker ${run}` })
    .first()
  await expect(connection).toContainText('Connected')
  await connection.getByText(/\d+ tools?/).click()
  await expect(connection.getByText('echo', { exact: true })).toBeVisible()

  // The callback works once: replayed, it does nothing.
  await page.goto(callback)
  await expect(page.getByRole('heading', { name: 'Connection not completed' })).toBeVisible()

  // Disconnect.
  await page.goto(`${workspaceUrl}/integrations`)
  await page.getByRole('button', { name: `Disconnect Tracker ${run}` }).click()
  await page.getByRole('button', { name: 'Disconnect', exact: true }).click()
  await expect(page.getByText('No connections yet.')).toBeVisible()
})
