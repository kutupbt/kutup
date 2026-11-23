import { expect, test, type Page } from '../fixtures/test'
import { apiUrl, appUrl, newAccount, openDrive, registerAccount } from '../fixtures/apps'
import { createFolder, createNote, itemAction, noteLive, openItem, typeAtEnd } from '../fixtures/drive'

// A public link's password and expiry (docs/plans/drive-link-password.md),
// as Proton Drive's link settings: set in the share dialog, asked for by the
// public page before anything shows, the URL unchanged.

const PASSWORD = 'Deneme123*LinkPasswordSpec'
const LINK_PASSWORD = 'kar tanesi 42'

/** Makes a public link from the open file page's Share dialog; returns it and leaves the dialog open. */
async function makeFileLink(page: Page): Promise<string> {
  await page.getByRole('button', { name: 'Share', exact: true }).click()
  const dialog = page.getByRole('dialog')
  await dialog.getByRole('button', { name: 'Create a public link' }).click()
  const link = dialog.getByTestId('new-file-link')
  await expect(link).toBeVisible({ timeout: 30_000 })
  return link.inputValue()
}

/** Opens the settings of the dialog's only link, sets them, and saves. */
async function saveSettings(page: Page, change: { password?: string | null; expiry?: string }) {
  await page.getByTestId('link-settings-open').first().click()
  const form = page.getByTestId('link-settings')
  await expect(form).toBeVisible()
  if (change.expiry !== undefined) {
    const toggle = form.getByTestId('link-expiry-toggle')
    if ((await toggle.getAttribute('data-state')) !== 'checked') await toggle.click()
    await form.getByTestId('link-expiry-date').fill(change.expiry)
  }
  if (change.password !== undefined) {
    const toggle = form.getByTestId('link-password-toggle')
    await expect(toggle).toBeEnabled({ timeout: 30_000 })
    const on = (await toggle.getAttribute('data-state')) === 'checked'
    if (change.password === null) {
      if (on) await toggle.click()
    } else {
      if (!on) await toggle.click()
      await form.getByTestId('link-password-input').fill(change.password)
    }
  }
  await form.getByTestId('link-settings-save').click()
  await expect(form).toBeHidden({ timeout: 60_000 })
}

/** A day `days` from today, as a date field takes it. */
function dayAhead(days: number): string {
  const d = new Date()
  d.setDate(d.getDate() + days)
  const pad = (n: number) => String(n).padStart(2, '0')
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`
}

test('a file link with a password asks for it; the URL stays the same and removing it opens the link again', async ({ browser }) => {
  test.slow()
  const alice = newAccount('linkpw', PASSWORD)
  const owner = await browser.newContext()
  await registerAccount(owner, alice)
  const drive = await openDrive(owner)
  await createNote(drive)
  await noteLive(drive)
  await typeAtEnd(drive, 'Behind a link password')
  const saved = drive.waitForResponse((r) => r.request().method() === 'POST' && /\/api\/v1\/drive\/files\/[^/]+\/versions$/.test(new URL(r.url()).pathname))
  await drive.keyboard.press('Control+s')
  expect((await saved).ok()).toBe(true)

  const link = await makeFileLink(drive)
  await saveSettings(drive, { password: LINK_PASSWORD, expiry: dayAhead(30) })
  const dialog = drive.getByRole('dialog')
  await expect(dialog.getByText(/· Password/).first()).toBeVisible({ timeout: 30_000 })
  await expect(dialog.getByText(/Expires /).first()).toBeVisible()
  await drive.keyboard.press('Escape')

  const visitor = await browser.newContext()
  const page = await visitor.newPage()
  await page.goto(link)
  await expect(page.getByText('This link is password protected')).toBeVisible({ timeout: 60_000 })
  await expect(page.locator('.prose')).toHaveCount(0)

  // A wrong password is refused and counted; nothing shows.
  await page.getByTestId('link-password-entry').fill('not the password')
  await page.getByTestId('link-password-continue').click()
  await expect(page.getByText('Incorrect password. Please try again.')).toBeVisible({ timeout: 60_000 })

  // The note's content is read with the proof: its URL, to ask again without.
  const contentRead = page.waitForRequest((r) => /\/api\/v1\/drive\/public-links\/[^/]+\/files\/[^/]+\/(state|download)/.test(r.url()))
  await page.getByTestId('link-password-entry').fill(LINK_PASSWORD)
  await page.getByTestId('link-password-continue').click()
  await expect(page.locator('.prose')).toContainText('Behind a link password', { timeout: 60_000 })
  const read = await contentRead
  expect(read.headers()['x-kutup-link-proof']).toBeTruthy()

  // The server shows nothing of a protected link without its proof.
  const token = new URL(link).pathname.split('/')[2]
  const bare = await page.request.get(apiUrl(`/drive/public-links/${token}`))
  expect(bare.status()).toBe(401)
  expect((await bare.json()).code).toBe('linkPassword')
  // Nor any byte of its files: every read through the link needs the proof.
  const bareContent = await page.request.get(read.url(), { headers: { Range: 'bytes=0-15' } })
  expect(bareContent.status()).toBe(401)
  expect((await bareContent.json()).code).toBe('linkPassword')

  // The owner removes the password: the same link opens without one.
  await drive.getByRole('button', { name: 'Share', exact: true }).click()
  await saveSettings(drive, { password: null })
  await drive.keyboard.press('Escape')
  const again = await visitor.newPage()
  await again.goto(link)
  await expect(again.locator('.prose')).toContainText('Behind a link password', { timeout: 60_000 })
  await expect(again.getByText('This link is password protected')).toHaveCount(0)

  await visitor.close()
  await owner.close()
})

test("a folder link's password holds across the folder's re-key", async ({ browser }) => {
  test.slow()
  const alice = newAccount('linkpwdir', PASSWORD)
  const owner = await browser.newContext()
  await registerAccount(owner, alice)
  const drive = await openDrive(owner)
  const folder = `Protected ${Date.now()}`
  await createFolder(drive, folder)
  await openItem(drive, folder)
  const note = await createNote(drive)
  await noteLive(drive)
  await drive.goto(appUrl('drive', '/'))
  await itemAction(drive, folder, 'Get public link')
  let dialog = drive.getByRole('dialog')
  const field = dialog.getByRole('textbox')
  await expect(field).toHaveValue(/#v1\./, { timeout: 30_000 })
  const link = await field.inputValue()
  await drive.keyboard.press('Escape')

  // A second link, then the password on the first; removing the second
  // re-keys the folder, and the first must stay behind its password.
  await itemAction(drive, folder, 'Get public link')
  await drive.keyboard.press('Escape')
  await itemAction(drive, folder, 'Share')
  dialog = drive.getByRole('dialog')
  await saveSettings(drive, { password: LINK_PASSWORD })
  await dialog.getByRole('button', { name: 'Remove this link' }).last().click()
  await dialog.getByRole('button', { name: 'Remove', exact: true }).last().click()
  await expect(dialog.getByRole('button', { name: 'Remove this link' })).toHaveCount(1, { timeout: 60_000 })
  await drive.keyboard.press('Escape')

  const visitor = await browser.newContext()
  const page = await visitor.newPage()
  await page.goto(link)
  await expect(page.getByText('This link is password protected')).toBeVisible({ timeout: 60_000 })
  await page.getByTestId('link-password-entry').fill(LINK_PASSWORD)
  await page.getByTestId('link-password-continue').click()
  await expect(page.getByText(note)).toBeVisible({ timeout: 60_000 })

  await visitor.close()
  await owner.close()
})
