import { expect, type Browser, type Page } from '@playwright/test'

/** A browser with its own passkey device (Chrome's virtual authenticator). */
export async function person(browser: Browser): Promise<Page> {
  const context = await browser.newContext()
  const page = await context.newPage()
  const cdp = await context.newCDPSession(page)
  await cdp.send('WebAuthn.enable')
  await cdp.send('WebAuthn.addVirtualAuthenticator', {
    options: {
      protocol: 'ctap2',
      transport: 'internal',
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: true,
      automaticPresenceSimulation: true,
    },
  })
  return page
}

/** Confirms the recovery codes shown after signing up; returns them. */
export async function saveRecoveryCodes(page: Page): Promise<string[]> {
  const list = page.getByTestId('recovery-codes').locator('li')
  await expect(list).toHaveCount(10)
  const codes = await list.allTextContents()
  await page.getByLabel('I have saved my recovery codes').check()
  await page.getByRole('button', { name: 'Continue' }).click()
  return codes
}

/** Creates an account with a new workspace; returns the workspace's URL. */
export async function signUp(page: Page, name: string, workspace: string): Promise<string> {
  await page.goto('/sign-up')
  await page.getByLabel('Your name').fill(name)
  await page.getByLabel('Workspace name').fill(workspace)
  await page.getByRole('button', { name: 'Create account with a passkey' }).click()
  await saveRecoveryCodes(page)
  await expect(page).toHaveURL(/\/w\/[0-9a-f-]{36}\/keys$/)
  return page.url().replace(/\/keys$/, '')
}
