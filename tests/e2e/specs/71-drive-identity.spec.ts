import { expect, test, type Page } from '@playwright/test'
import { appUrl, finishNewKeys, newAccount, openDrive, registerAccount, signIn, signInAsAdmin, submitThroughRateLimit } from '../fixtures/apps'
import { createNote, item, noteLive, openItem } from '../fixtures/drive'

const PASSWORD = 'Deneme123*DriveIdentityPassword'
const NEW_PASSWORD = 'Deneme123*DriveIdentityAfterWipe'

/** Shares the note open on `page` with `address`; returns the dialog. */
async function shareOpenNote(page: Page, address: string) {
  await page.getByRole('button', { name: 'Share', exact: true }).click()
  const dialog = page.getByRole('dialog')
  await dialog.getByLabel('Kutup address').fill(address)
  await dialog.getByRole('button', { name: 'Share', exact: true }).click()
  return dialog
}

// docs/plans/drive-identity-pins.md: Bob's browser remembers who Alice is the
// first time she shares with him. When her account is wiped and set up again
// (a new identity under the same address, as a server handing out keys of its
// own would look), Drive warns him and asks before he shares to her, until he
// trusts the new identity.
test("a person's new identity is warned about until trusted", async ({ browser }) => {
  test.slow()
  const alice = newAccount('idalice', PASSWORD)
  const bob = newAccount('idbob', PASSWORD)
  const a = await browser.newContext()
  const b = await browser.newContext()
  await registerAccount(a, alice)
  await registerAccount(b, bob)

  // Alice shares a note; Bob opens it: her identity is pinned, nothing to say.
  let aliceDrive = await openDrive(a)
  const first = await createNote(aliceDrive)
  await noteLive(aliceDrive)
  const shared = aliceDrive.waitForResponse((r) => r.request().method() === 'POST' && /\/api\/files\/[^/]+\/share$/.test(new URL(r.url()).pathname))
  await shareOpenNote(aliceDrive, bob.address)
  expect((await shared).status()).toBe(204)
  await a.close()

  const bobPage = await b.newPage()
  await bobPage.goto(appUrl('drive', '/shared'))
  await expect(item(bobPage, first)).toBeVisible({ timeout: 60_000 })
  await expect(bobPage.getByTestId('identity-warning')).toHaveCount(0)
  await openItem(bobPage, first)
  await expect(bobPage.locator('.cm-content')).toBeVisible({ timeout: 60_000 })
  await expect(bobPage.getByTestId('identity-banner')).toHaveCount(0)

  // An administrator wipes Alice's account; she sets it up again.
  const admin = await browser.newContext()
  await signInAsAdmin(admin)
  const adminPage = await admin.newPage()
  await adminPage.goto(appUrl('account', '/admin/users'))
  await adminPage.getByPlaceholder('Search by username or address').fill(alice.username)
  await adminPage.getByRole('row').filter({ hasText: alice.username }).first().click()
  await adminPage.getByRole('button', { name: 'Wipe account', exact: true }).click()
  const confirm = adminPage.getByRole('alertdialog')
  await confirm.getByRole('textbox').fill(alice.username)
  await confirm.getByRole('button', { name: 'Wipe account', exact: true }).click()
  const copy = adminPage.getByRole('button', { name: 'Copy' }).first()
  await expect(copy).toBeVisible({ timeout: 30_000 })
  const temporary = (await copy.locator('xpath=preceding-sibling::*[1]').textContent())!.trim()
  await admin.close()

  const a2 = await browser.newContext()
  const setup = await a2.newPage()
  await setup.goto(appUrl('account', '/login'))
  await setup.getByLabel('Username', { exact: true }).fill(alice.username)
  await setup.getByLabel('Password', { exact: true }).fill(temporary)
  await submitThroughRateLimit(setup, 'Sign in', setup.getByRole('heading', { name: 'Finish setting up your account' }))
  await finishNewKeys(setup, NEW_PASSWORD)
  aliceDrive = await openDrive(a2)
  const second = await createNote(aliceDrive)
  await noteLive(aliceDrive)
  const aliceSecondUrl = aliceDrive.url()
  const reshared = aliceDrive.waitForResponse((r) => r.request().method() === 'POST' && /\/api\/files\/[^/]+\/share$/.test(new URL(r.url()).pathname))
  await shareOpenNote(aliceDrive, bob.address)
  expect((await reshared).status()).toBe(204)
  await a2.close()

  // Bob: her new share comes with a warning, in the list and on the file.
  await bobPage.goto(appUrl('drive', '/shared'))
  await expect(item(bobPage, second)).toBeVisible({ timeout: 60_000 })
  await expect(bobPage.getByTestId('identity-warning').first()).toBeVisible({ timeout: 60_000 })

  // Sharing to her asks first.
  const bobDrive = await openDrive(b)
  await createNote(bobDrive)
  await noteLive(bobDrive)
  const dialog = await shareOpenNote(bobDrive, alice.address)
  await expect(dialog.getByText(/identity changed/)).toBeVisible({ timeout: 30_000 })
  const anyway = bobDrive.waitForResponse((r) => r.request().method() === 'POST' && /\/api\/files\/[^/]+\/share$/.test(new URL(r.url()).pathname))
  await dialog.getByTestId('identity-share-anyway').click()
  expect((await anyway).status()).toBe(204)
  await bobDrive.keyboard.press('Escape')

  // On her file, Bob trusts the new identity; the warnings go.
  await bobPage.goto(appUrl('drive', '/shared'))
  await openItem(bobPage, second)
  const banner = bobPage.getByTestId('identity-banner')
  await expect(banner).toContainText('identity changed', { timeout: 60_000 })
  await banner.getByRole('button', { name: 'Trust the new identity' }).click()
  await expect(banner).toBeHidden({ timeout: 30_000 })
  await bobPage.goto(appUrl('drive', '/shared'))
  await expect(item(bobPage, second)).toBeVisible({ timeout: 60_000 })
  await expect(bobPage.getByTestId('identity-warning')).toHaveCount(0)

  // In person: Alice shows her safety QR (from the people she shares with),
  // Bob scans it (here: pastes its text). Bob sees Alice verified, everywhere.
  const a3 = await browser.newContext()
  await signIn(a3, { ...alice, password: NEW_PASSWORD })
  const alicePage = await a3.newPage()
  await alicePage.goto(aliceSecondUrl)
  await alicePage.getByRole('button', { name: 'Share', exact: true }).click()
  await alicePage.getByRole('dialog').getByTestId('identity-verify-open').first().click()
  const aliceQr = alicePage.getByTestId('drive-safety-qr')
  await expect(aliceQr).toBeVisible({ timeout: 30_000 })
  const payload = (await aliceQr.getAttribute('data-value'))!
  const aliceNumber = (await alicePage.getByTestId('drive-safety-number').textContent())!.trim()
  await a3.close()

  await openItem(bobPage, second)
  await bobPage.getByTestId('identity-verify-open').first().click()
  await expect(bobPage.getByTestId('drive-safety-number')).toHaveText(aliceNumber, { timeout: 30_000 })
  await bobPage.getByLabel(/paste/i).fill(payload)
  await bobPage.getByRole('button', { name: 'Verify exact match' }).click()
  await bobPage.keyboard.press('Escape')
  await bobPage.goto(appUrl('drive', '/shared'))
  await expect(bobPage.getByTestId('identity-verified').first()).toBeVisible({ timeout: 60_000 })

  await b.close()
})
