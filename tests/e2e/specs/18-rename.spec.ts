import { expect, test } from '@playwright/test'
import { newAccount, openDrive, registerAccount } from '../fixtures/apps'
import { backFromEditor, createNote, item, openItem, renameItem } from '../fixtures/drive'

const PASSWORD = 'Deneme123*RenamePassword'

test('drive: rename a note from its menu; the name persists', async ({ browser }) => {
  const context = await browser.newContext()
  await registerAccount(context, newAccount('rename', PASSWORD))
  const page = await openDrive(context)

  const original = await createNote(page)
  await backFromEditor(page)
  const renamed = `renamed-${Date.now()}.md`
  await renameItem(page, original, renamed)
  await expect(item(page, original)).toHaveCount(0)

  // The name is encrypted metadata: a reload decrypts it again from the server.
  await page.reload()
  await expect(item(page, renamed)).toBeVisible({ timeout: 60_000 })
  await context.close()
})

test('editor: rename a note from its header; the name persists across reload', async ({ browser }) => {
  const context = await browser.newContext()
  await registerAccount(context, newAccount('inlinerename', PASSWORD))
  const page = await openDrive(context)

  const original = await createNote(page)
  const renamed = `inline-${Date.now()}.md`
  await page.getByRole('button', { name: original, exact: true }).click()
  const dialog = page.getByRole('dialog')
  await dialog.getByLabel('Name').fill(renamed)
  await dialog.getByRole('button', { name: 'Rename', exact: true }).click()
  await expect(page.getByRole('button', { name: renamed, exact: true })).toBeVisible({ timeout: 15_000 })

  await page.reload()
  await expect(page.getByRole('button', { name: renamed, exact: true })).toBeVisible({ timeout: 60_000 })
  await backFromEditor(page)
  await expect(item(page, renamed)).toBeVisible()
  await openItem(page, renamed)
  await expect(page.getByRole('button', { name: renamed, exact: true })).toBeVisible({ timeout: 60_000 })
  await context.close()
})
