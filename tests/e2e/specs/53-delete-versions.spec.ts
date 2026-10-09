import { expect, test } from '@playwright/test'
import { appUrl, newAccount, openDrive, registerAccount } from '../fixtures/apps'
import { addRectangle, createWhiteboard, elementCount, historyPanel, saveState } from '../fixtures/whiteboard'

const PASSWORD = 'Deneme123*DeleteVersionsPassword'

test('earlier versions are deleted one by one in Drive, or in bulk from Free up space', async ({ browser }) => {
  test.slow()
  const context = await browser.newContext()
  await registerAccount(context, newAccount('versions', PASSWORD))
  const page = await openDrive(context)

  // Four saved versions of one whiteboard.
  await createWhiteboard(page)
  await saveState(page)
  for (let n = 1; n <= 3; n++) {
    await addRectangle(page)
    await expect.poll(() => elementCount(page)).toBe(n)
    await saveState(page)
  }
  await page.getByRole('button', { name: 'History', exact: true }).click()
  const history = historyPanel(page)
  const restore = history.getByRole('button', { name: 'Restore', exact: true })
  await expect.poll(() => restore.count(), { timeout: 30_000 }).toBeGreaterThanOrEqual(4)
  const versions = await restore.count()

  // The newest is the file itself: every other version can be deleted.
  const remove = history.getByRole('button', { name: 'Delete', exact: true })
  await expect(remove).toHaveCount(versions - 1)
  await remove.last().click()
  const confirm = page.getByRole('alertdialog', { name: 'Delete this version?' })
  await confirm.getByRole('button', { name: 'Delete permanently' }).click()
  await expect(page.getByText('Version deleted')).toBeVisible({ timeout: 30_000 })
  await expect.poll(() => restore.count()).toBe(versions - 1)

  // The rest of the earlier versions, in bulk.
  const account = await context.newPage()
  await account.goto(appUrl('account', '/settings/storage?cleanup=1'))
  const cleanup = account.getByRole('dialog', { name: 'Free up space' })
  await expect(cleanup.getByText('Any age')).toBeVisible({ timeout: 60_000 })
  const left = versions - 2
  await expect(cleanup.getByText(new RegExp(`^${left} versions · `))).toBeVisible()
  await expect(cleanup.getByText("Each file's newest version always stays")).toBeVisible()
  await cleanup.getByRole('button', { name: `Delete ${left} versions` }).click()
  const bulk = account.getByRole('alertdialog', { name: 'Delete earlier versions?' })
  await bulk.getByRole('button', { name: 'Delete permanently' }).click()
  await expect(account.getByText(new RegExp(`^${left} versions deleted, .* freed$`))).toBeVisible({ timeout: 30_000 })
  await expect(cleanup.getByText('You have no earlier versions to delete.')).toBeVisible({ timeout: 30_000 })

  // Only the newest is left, and it still opens.
  await page.reload()
  await page.getByRole('button', { name: 'History', exact: true }).click()
  await expect.poll(() => historyPanel(page).getByRole('button', { name: 'Restore', exact: true }).count(), { timeout: 30_000 }).toBe(1)
  await expect.poll(() => elementCount(page), { timeout: 30_000 }).toBe(3)
  await context.close()
})
