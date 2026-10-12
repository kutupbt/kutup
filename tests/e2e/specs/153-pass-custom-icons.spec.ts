import { expect, test, type Page } from '@playwright/test'
import { newAccount, registerAccount } from '../fixtures/apps'
import { addEntry, createVault, expectSaved, openEntry, openPass } from '../fixtures/pass'

const PASSWORD = 'Deneme123*PassCustomIcons'
const VAULT_PASSWORD = 'kasa-parolası-çğ-153'
// A 1×1 PNG, standing in for the website's icon (no outside website).
const PNG = Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYAAAAAYAAjCB0C8AAAAASUVORK5CYII=', 'base64')

/** A 200×100 PNG drawn in the page. */
async function widePng(page: Page): Promise<Buffer> {
  const base64 = await page.evaluate(async () => {
    const canvas = document.createElement('canvas')
    canvas.width = 200
    canvas.height = 100
    const context = canvas.getContext('2d')!
    context.fillStyle = '#0a7'
    context.fillRect(0, 0, 200, 100)
    const blob = await new Promise<Blob>((resolve) => canvas.toBlob((b) => resolve(b!), 'image/png'))
    const bytes = new Uint8Array(await blob.arrayBuffer())
    let binary = ''
    for (const byte of bytes) binary += String.fromCharCode(byte)
    return btoa(binary)
  })
  return Buffer.from(base64, 'base64')
}

test('pass: entries and groups take their own pictures, kept in the vault', async ({ browser }) => {
  test.slow()
  const context = await browser.newContext()
  await registerAccount(context, newAccount('pass153', PASSWORD))
  const page = await context.newPage()
  await page.route('**/api/pass/icon', (route) => route.fulfill({ status: 200, contentType: 'image/png', body: PNG }))
  await openPass(page)
  await createVault(page, 'Kişisel', VAULT_PASSWORD)
  await addEntry(page, { title: 'GitHub', url: 'https://github.com/login' })
  await expectSaved(page)
  const article = page.getByRole('article', { name: 'GitHub' })
  const row = page.getByRole('list', { name: 'Entries' }).getByRole('button', { name: 'GitHub' })

  // The website's icon, kept in the vault.
  await article.getByRole('button', { name: 'Change icon' }).click()
  let dialog = page.getByRole('dialog', { name: 'Icon for GitHub' })
  await dialog.getByRole('button', { name: "Use the website's icon" }).click()
  await expect(dialog).toBeHidden()
  await expect(article.locator('img')).toHaveAttribute('src', /^data:image\/png;base64,/)
  await expect(row.locator('img')).toHaveAttribute('src', /^data:image\/png;base64,/)
  await expectSaved(page)

  // An uploaded picture is redrawn at most 64 px a side.
  await article.getByRole('button', { name: 'Change icon' }).click()
  dialog = page.getByRole('dialog', { name: 'Icon for GitHub' })
  await expect(dialog.getByRole('list', { name: 'Pictures in this vault' }).getByRole('button')).toHaveCount(1)
  await dialog.getByLabel('Upload a picture').setInputFiles({ name: 'logo.png', mimeType: 'image/png', buffer: await widePng(page) })
  await expect(dialog).toBeHidden()
  await expect.poll(() => row.locator('img').evaluate((img: HTMLImageElement) => `${img.naturalWidth}×${img.naturalHeight}`)).toBe('64×32')
  await expectSaved(page)

  // Not a picture: refused, nothing changed.
  await article.getByRole('button', { name: 'Change icon' }).click()
  dialog = page.getByRole('dialog', { name: 'Icon for GitHub' })
  await expect(dialog.getByRole('list', { name: 'Pictures in this vault' }).getByRole('button')).toHaveCount(2)
  await dialog.getByLabel('Upload a picture').setInputFiles({ name: 'notes.png', mimeType: 'image/png', buffer: Buffer.from('not an image') })
  await expect(dialog.getByText('That file could not be read as a picture.')).toBeVisible()
  await dialog.getByRole('button', { name: 'Close' }).last().click()

  // A group takes one of the vault's pictures.
  const groupRow = page.getByRole('navigation', { name: 'Groups' }).getByRole('listitem').filter({ hasText: 'Kişisel' })
  await groupRow.hover()
  await groupRow.getByRole('button', { name: 'Actions for Kişisel' }).click()
  await page.getByRole('menuitem', { name: 'Change icon' }).click()
  dialog = page.getByRole('dialog', { name: 'Icon for Kişisel' })
  await expect(dialog.getByRole('button', { name: "Use the website's icon" })).toHaveCount(0)
  await dialog.getByRole('button', { name: 'Picture 1' }).click()
  await expect(dialog).toBeHidden()
  await expect(groupRow.locator('img')).toHaveAttribute('src', /^data:image\/png;base64,/)
  await expectSaved(page)

  // Kept in the vault: there after a reload.
  await page.reload()
  await expect(page.getByRole('heading', { name: 'Kişisel', exact: true, level: 1 })).toBeVisible({ timeout: 60_000 })
  await expect(row.locator('img')).toHaveAttribute('src', /^data:image\/png;base64,/)
  await expect(groupRow.locator('img')).toHaveAttribute('src', /^data:image\/png;base64,/)

  // The default icon again; the pictures stay in the vault, as in KeePass apps.
  await openEntry(page, 'GitHub')
  await article.getByRole('button', { name: 'Change icon' }).click()
  dialog = page.getByRole('dialog', { name: 'Icon for GitHub' })
  await dialog.getByRole('button', { name: 'Default icon' }).click()
  await expect(dialog).toBeHidden()
  // Its website's icon shows again (through Kutup, not kept in the vault).
  await expect(row.locator('img')).toHaveAttribute('src', /^blob:/)
  await article.getByRole('button', { name: 'Change icon' }).click()
  await expect(page.getByRole('dialog', { name: 'Icon for GitHub' }).getByRole('list', { name: 'Pictures in this vault' }).getByRole('button')).toHaveCount(2)
  await context.close()
})
