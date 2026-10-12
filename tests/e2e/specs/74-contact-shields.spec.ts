// The shield beside a Kutup address in Contacts: the account's list of
// people (docs/plans/drive-identity-pins.md) seen from the address book.
// Gray "Not verified" at first; comparing the safety number in person turns
// it green, as in Drive and Chat. An ordinary email address gets no shield
// (and is never looked up).

import { expect, test, type BrowserContext, type Page } from '@playwright/test'
import { apiUrl, appUrl, newAccount, registerAccount } from '../fixtures/apps'

const PASSWORD = 'Deneme123*ContactShieldPassword'

async function openContacts(context: BrowserContext): Promise<Page> {
  const page = await context.newPage()
  await page.goto(appUrl('contacts'))
  await expect(page.getByText('No contacts yet')).toBeVisible({ timeout: 120_000 })
  return page
}

async function addContact(page: Page, first: string, email: string) {
  await page.getByRole('button', { name: 'New contact' }).first().click()
  const editor = page.getByRole('dialog', { name: 'New contact' })
  await editor.getByLabel('First name').fill(first)
  await editor.getByLabel('Email address').fill(email)
  await editor.getByRole('button', { name: 'Save' }).click()
  // The newest toast: an earlier add's may still be showing.
  await expect(page.getByText('Contact added').last()).toBeVisible({ timeout: 30_000 })
  await expect(editor).toHaveCount(0)
  const card = page.getByRole('article', { name: first })
  await expect(card).toBeVisible({ timeout: 30_000 })
  return card
}

test('a Kutup contact carries the shield, verified in person', async ({ browser, request }) => {
  test.slow()
  const { chat } = (await (await request.get(apiUrl('/auth/settings'))).json()) as { chat: { serverName: string } }
  const alice = newAccount('shieldalice', PASSWORD)
  const bob = newAccount('shieldbob', PASSWORD)
  const contextA = await browser.newContext()
  const contextB = await browser.newContext()
  await registerAccount(contextA, alice)
  await registerAccount(contextB, bob)
  const aliceAddress = `${alice.username}@${chat.serverName}`
  const bobAddress = `${bob.username}@${chat.serverName}`

  // Alice saves Bob: met for the first time, not verified yet.
  const alicePage = await openContacts(contextA)
  const bobCard = await addContact(alicePage, 'Bob', bobAddress)
  const shield = bobCard.getByTestId('identity-shield')
  await expect(shield).toHaveAttribute('data-state', 'unverified', { timeout: 60_000 })
  await expect(shield).toHaveText('Not verified')

  // An outside address: no shield.
  const outside = await addContact(alicePage, 'Deniz', 'deniz@example.org')
  await expect(outside.getByRole('link', { name: 'deniz@example.org' })).toBeVisible()
  await expect(outside.getByTestId('identity-shield')).toHaveCount(0)

  // In person: Bob shows his safety QR from Alice's contact page...
  const bobPage = await openContacts(contextB)
  const aliceCard = await addContact(bobPage, 'Alice', aliceAddress)
  await aliceCard.getByTestId('identity-shield').click()
  const bobQr = bobPage.getByTestId('drive-safety-qr')
  await expect(bobQr).toBeVisible({ timeout: 30_000 })
  const payload = (await bobQr.getAttribute('data-value'))!
  const number = (await bobPage.getByTestId('drive-safety-number').textContent())!.trim()

  // ...and Alice scans it (here: pastes its text) from his.
  await alicePage.getByRole('link', { name: /^Bob/ }).click()
  await alicePage.getByRole('article', { name: 'Bob' }).getByTestId('identity-shield').click()
  await expect(alicePage.getByTestId('drive-safety-number')).toHaveText(number, { timeout: 30_000 })
  await alicePage.getByLabel(/paste/i).fill(payload)
  await alicePage.getByRole('button', { name: 'Verify exact match' }).click()
  await alicePage.keyboard.press('Escape')
  const verified = alicePage.getByRole('article', { name: 'Bob' }).getByTestId('identity-shield')
  await expect(verified).toHaveAttribute('data-state', 'verified', { timeout: 30_000 })
  await expect(verified).toHaveText('Verified')

  // The list is the account's: a fresh page says the same.
  await alicePage.reload()
  await alicePage.getByRole('link', { name: /^Bob/ }).click()
  await expect(alicePage.getByRole('article', { name: 'Bob' }).getByTestId('identity-shield')).toHaveAttribute('data-state', 'verified', { timeout: 60_000 })

  await contextA.close()
  await contextB.close()
})
