// Your own marks on photos (docs/plans/photos.md): a favourite is stored as
// the account's Photos library record (an account record of this account,
// docs/plans/w1-account-record.md) and comes back after a reload, and the next
// mark is that record's successor.
import { expect, test } from '@playwright/test'
import { appUrl, newAccount, registerAccount } from '../fixtures/apps'

const PASSWORD = 'correct horse battery staple 121'
// A 1×1 PNG.
const PNG = Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYAAAAAYAAjCB0C8AAAAASUVORK5CYII=', 'base64')

test('a favourite is kept in the library record and survives a reload', async ({ browser }) => {
  test.slow()
  const account = newAccount('marks', PASSWORD)
  const context = await browser.newContext()
  await registerAccount(context, account)
  const page = await context.newPage()
  await page.goto(appUrl('photos'))
  const upload = page.getByRole('button', { name: 'Upload', exact: true }).first()
  await expect(upload).toBeVisible({ timeout: 120_000 })

  const names = ['first.png', 'second.png']
  const [chooser] = await Promise.all([page.waitForEvent('filechooser'), upload.click()])
  await chooser.setFiles(names.map((name) => ({ name, mimeType: 'image/png', buffer: PNG })))
  await expect(page.getByText('Uploads complete')).toBeVisible({ timeout: 120_000 })

  const tile = (name: string) => page.getByRole('button', { name: new RegExp(`^${name.replace('.', '\\.')},`) })
  const heart = (name: string) => tile(name).locator('xpath=..').getByLabel('Favourite', { exact: true })
  const favourite = async (name: string) => {
    await page.getByRole('checkbox', { name: `Select ${name}` }).click()
    const stored = page.waitForResponse((r) => r.request().method() === 'PUT' && new URL(r.url()).pathname === '/api/photos/library')
    await page.getByRole('button', { name: 'Favourite', exact: true }).click()
    expect((await stored).status()).toBe(200)
    await expect(page.getByText('Added to favourites')).toBeVisible()
    await page.keyboard.press('Escape')
  }

  // The first mark starts the record; the second is its successor.
  await expect(tile(names[0])).toBeVisible({ timeout: 60_000 })
  await favourite(names[0])
  await expect(heart(names[0])).toBeVisible()
  await favourite(names[1])

  // Read back from the server and opened with the account's key.
  await page.reload()
  await expect(tile(names[0])).toBeVisible({ timeout: 60_000 })
  await expect(heart(names[0])).toBeVisible({ timeout: 30_000 })
  await expect(heart(names[1])).toBeVisible()

  // The Favourites page lists both.
  await page.goto(appUrl('photos', '/favourites'))
  await expect(tile(names[0])).toBeVisible({ timeout: 30_000 })
  await expect(tile(names[1])).toBeVisible()
  await context.close()
})
