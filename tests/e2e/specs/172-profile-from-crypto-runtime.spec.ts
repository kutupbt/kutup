import { expect, test, type BrowserContext, type Page } from '@playwright/test'
import { appUrl, newAccount, openDrive, registerAccount, type Account } from '../fixtures/apps'
import { createNote, item, noteLive } from '../fixtures/drive'

const PASSWORD = 'Deneme123*ProfileRuntimePassword'

/** Saves `name` as the account's profile name in the Account app's settings. */
async function saveProfileName(context: BrowserContext, name: string): Promise<Page> {
  const page = await context.newPage()
  await page.goto(appUrl('account', '/settings/profile'))
  const field = page.getByTestId('account-profile-name')
  await expect(field).toBeVisible({ timeout: 60_000 })
  await field.fill(name)
  const saved = page.waitForResponse((r) => r.request().method() === 'PUT' && new URL(r.url()).pathname === '/api/chat/profile')
  await page.getByRole('button', { name: 'Save', exact: true }).click()
  expect((await saved).status()).toBeLessThan(300)
  await expect(page.getByText('Profile saved')).toBeVisible()
  return page
}

/** Waits until this Drive has handed its profile key to the people it shares with. */
function profileKeySent(page: Page) {
  return page.waitForResponse((r) => r.request().method() === 'PUT' && new URL(r.url()).pathname === '/api/drive/profile-keys', { timeout: 60_000 })
}

// docs/plans/chat-crypto-move.md: the profile is sealed and opened by the
// crypto runtime (no Chat WASM in Account or Drive). Saved in the Account
// app, it opens again there; handed over through Drive, the person shared
// with sees the name on their side, and a later edit reaches them too.
test('a profile saved in Account opens there and in the Drive of the person shared with', async ({ browser }) => {
  test.slow()
  const alice: Account = newAccount('pralice', PASSWORD)
  const bob: Account = newAccount('prbob', PASSWORD)
  const a = await browser.newContext()
  const b = await browser.newContext()
  await registerAccount(a, alice)
  await registerAccount(b, bob)

  // Alice's own profile: sealed, then opened again after a reload.
  const settings = await saveProfileName(a, 'Alice Yılmaz')
  await settings.reload()
  await expect(settings.getByTestId('account-profile-name')).toHaveValue('Alice Yılmaz', { timeout: 60_000 })
  await settings.close()

  // She shares a note with Bob; her Drive then gives him her profile key.
  const aliceDrive = await openDrive(a)
  const note = await createNote(aliceDrive)
  await noteLive(aliceDrive)
  await aliceDrive.getByRole('button', { name: 'Share', exact: true }).click()
  const dialog = aliceDrive.getByRole('dialog')
  await dialog.getByLabel('Kutup address').fill(bob.address)
  const shared = aliceDrive.waitForResponse((r) => r.request().method() === 'POST' && /\/api\/files\/[^/]+\/share$/.test(new URL(r.url()).pathname))
  await dialog.getByRole('button', { name: 'Share', exact: true }).click()
  expect((await shared).status()).toBe(204)
  const given = profileKeySent(aliceDrive)
  await aliceDrive.goto(appUrl('drive', '/'))
  expect((await given).status()).toBeLessThan(300)

  // Bob's Drive opens her profile with that key: her name, not her address.
  const bobDrive = await openDrive(b, 'primary', '/shared')
  await expect(item(bobDrive, note)).toBeVisible({ timeout: 60_000 })
  await expect(bobDrive.getByText('From Alice Yılmaz').first()).toBeVisible({ timeout: 60_000 })

  // A new revision under the same key reaches him without a new handover.
  const edited = await saveProfileName(a, 'Alice Y. Demir')
  await edited.close()
  await expect(async () => {
    await bobDrive.reload()
    await expect(bobDrive.getByText('From Alice Y. Demir').first()).toBeVisible({ timeout: 10_000 })
  }).toPass({ timeout: 90_000 })

  await a.close()
  await b.close()
})
