import { randomBytes } from 'node:crypto'

import { expect, test, type Browser, type Page } from '@playwright/test'

// One story through the dashboard, as two people: an owner creates an
// account and a workspace, stores and rotates a provider key in the real
// Vault, pairs a phone through the real app API, invites a member, signs out
// and in again, and recovers access with a recovery code.

/** A browser with its own passkey device (Chrome's virtual authenticator). */
async function person(browser: Browser): Promise<Page> {
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

async function saveRecoveryCodes(page: Page): Promise<string[]> {
  const list = page.getByTestId('recovery-codes').locator('li')
  await expect(list).toHaveCount(10)
  const codes = await list.allTextContents()
  await page.getByLabel('I have saved my recovery codes').check()
  await page.getByRole('button', { name: 'Continue' }).click()
  return codes
}

const fakeKey = (prefix: string) => `${prefix}-e2e-${randomBytes(12).toString('hex')}`

test('owner and member journey', async ({ browser }) => {
  const run = randomBytes(3).toString('hex')
  const owner = await person(browser)

  // Sign up: a passkey, recovery codes, a workspace.
  await owner.goto('/')
  await expect(owner).toHaveURL(/\/sign-in$/)
  await owner.getByRole('link', { name: 'Create an account' }).click()
  await owner.getByLabel('Your name').fill(`Owner ${run}`)
  await owner.getByLabel('Workspace name').fill(`E2E ${run}`)
  await owner.getByRole('button', { name: 'Create account with a passkey' }).click()
  const codes = await saveRecoveryCodes(owner)
  await expect(owner).toHaveURL(/\/w\/[0-9a-f-]{36}\/keys$/)
  const workspaceUrl = owner.url().replace(/\/keys$/, '')

  // Store a key in the Vault; only its last four characters come back.
  const first = fakeKey('sk')
  await owner.getByLabel('Label').fill('Echo')
  await owner.getByLabel('API key').fill(first)
  await owner.getByRole('button', { name: 'Store key' }).click()
  await expect(owner.getByText('OpenAI key stored.')).toBeVisible()
  const active = owner.getByTestId('active-keys')
  await expect(active).toContainText('OpenAI · Echo')
  await expect(active).toContainText(`••••${first.slice(-4)}`)
  await expect(owner.locator('body')).not.toContainText(first)

  // A second OpenAI key asks before replacing the first.
  const second = fakeKey('sk')
  await owner.getByLabel('Label').fill('Rotated')
  await owner.getByLabel('API key').fill(second)
  await owner.getByRole('button', { name: 'Store key' }).click()
  await expect(owner.getByRole('alert').filter({ hasText: 'already has an active OpenAI key' })).toBeVisible()
  await owner.getByLabel(/Replace the active OpenAI key/).check()
  await owner.getByLabel('API key').fill(second)
  await owner.getByLabel('Label').fill('Rotated')
  await owner.getByRole('button', { name: 'Store key' }).click()
  await expect(active).toContainText('OpenAI · Rotated')
  await expect(active).not.toContainText('Echo')
  await expect(owner.getByText('Replaced')).toBeVisible()

  // Revoke it, as leaked.
  await owner.getByRole('button', { name: 'Revoke Rotated' }).click()
  await owner.getByLabel('Why').selectOption('compromised')
  await owner.getByRole('button', { name: 'Revoke for good' }).click()
  await expect(owner.getByText('No keys yet.')).toBeVisible()
  await expect(owner.getByText('Leaked')).toBeVisible()

  // Pair a phone: a one-time code from the app API, as a QR code.
  await owner.getByRole('link', { name: 'Devices' }).click()
  await owner.getByRole('button', { name: 'Pair an iPhone' }).click()
  await expect(owner.getByAltText('Pairing QR code')).toBeVisible()
  await expect(owner.getByTestId('pairing-code')).toHaveText(/^[0-9A-Z]{4}-[0-9A-Z]{4}-[0-9A-Z]{4}$/)

  // Invite a member.
  await owner.getByRole('link', { name: 'Members' }).click()
  await owner.getByRole('button', { name: 'Create invitation link' }).click()
  const invitation = await owner.getByTestId('invitation-link').inputValue()
  expect(invitation).toMatch(/\/invite\/[A-Za-z0-9_-]{43}$/)

  // The member joins with a passkey of their own.
  const member = await person(browser)
  await member.goto(invitation)
  await expect(member.getByRole('heading', { name: `Join E2E ${run}` })).toBeVisible()
  await member.getByLabel('Your name').fill(`Member ${run}`)
  await member.getByRole('button', { name: 'Create account with a passkey' }).click()
  await saveRecoveryCodes(member)
  await expect(member).toHaveURL(`${workspaceUrl}/keys`)
  await expect(member.getByText('Only owners of the workspace can add or revoke keys.')).toBeVisible()
  await expect(member.getByRole('button', { name: 'Store key' })).toHaveCount(0)
  // The invitation worked once.
  await member.goto(invitation)
  await expect(member.getByText('This invitation has already been used.')).toBeVisible()
  // Other workspaces do not exist for the member.
  await member.goto('/w/0199e2e0-0000-7000-8000-000000000001/keys')
  await expect(member.getByRole('heading', { name: 'Not found' })).toBeVisible()

  // The owner sees them, and removes them.
  await owner.reload()
  await expect(owner.getByTestId('members')).toContainText(`Member ${run}`)
  await owner.getByRole('button', { name: `Remove Member ${run}` }).click()
  await owner.getByRole('button', { name: 'Remove', exact: true }).click()
  await expect(owner.getByTestId('members')).not.toContainText(`Member ${run}`)
  await member.goto(`${workspaceUrl}/keys`)
  await expect(member.getByRole('heading', { name: 'Not found' })).toBeVisible()

  // Sign out, and back in with the passkey.
  await owner.getByRole('button', { name: 'Sign out' }).click()
  await expect(owner).toHaveURL(/\/sign-in$/)
  await owner.getByRole('button', { name: 'Sign in with a passkey' }).click()
  await expect(owner).toHaveURL(`${workspaceUrl}/keys`)

  // Lost passkeys: a recovery code on a new device, which must add a passkey.
  const newDevice = await person(browser)
  await newDevice.goto('/recover')
  await newDevice.getByLabel('Recovery code').fill(codes[0]!.toLowerCase())
  await newDevice.getByRole('button', { name: 'Sign in' }).click()
  await expect(newDevice.getByText('You signed in with a recovery code.')).toBeVisible()
  await newDevice.goto(`${workspaceUrl}/keys`)
  await expect(newDevice).toHaveURL(/\/account$/) // nothing else until a passkey is added
  await newDevice.getByLabel('Name').fill('New laptop')
  await newDevice.getByRole('button', { name: 'Add a passkey' }).click()
  await expect(newDevice).toHaveURL(`${workspaceUrl}/keys`)
  await newDevice.goto('/account')
  await expect(newDevice.getByTestId('passkeys')).toContainText('New laptop')
  await expect(newDevice.getByText('9 unused codes left.', { exact: false })).toBeVisible()

  // The used code does not work twice.
  const again = await person(browser)
  await again.goto('/recover')
  await again.getByLabel('Recovery code').fill(codes[0]!)
  await again.getByRole('button', { name: 'Sign in' }).click()
  await expect(again.getByRole('alert').filter({ hasText: 'not valid, or was already used' })).toBeVisible()
})
