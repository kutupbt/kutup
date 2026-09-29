import { expect, test, type BrowserContext } from '@playwright/test'
import { appUrl, newAccount, openDrive, registerAccount } from '../fixtures/apps'
import { item, itemAction, openSection } from '../fixtures/drive'
import { addImage, createWhiteboard, ONE_PX_PNG } from '../fixtures/whiteboard'

const PASSWORD = 'Deneme123*WhiteboardQuotaPassword'

/**
 * The account's charged storage, read in the account app's own tab so the
 * Drive tab's session is left alone.
 */
async function usedBytes(context: BrowserContext): Promise<number> {
  const page = await context.newPage()
  await page.goto(appUrl('account', '/'))
  const used = await page.evaluate(async () => {
    const refreshed = await fetch('/api/auth/refresh', { method: 'POST', credentials: 'include' })
    if (!refreshed.ok) throw new Error(`refresh ${refreshed.status}`)
    const { accessToken } = (await refreshed.json()) as { accessToken: string }
    const me = await fetch('/api/user/me', { headers: { Authorization: `Bearer ${accessToken}` } })
    return ((await me.json()) as { storageUsedBytes: number }).storageUsedBytes
  })
  await page.close()
  return used
}

test('a pasted image is charged to storage; deleting the whiteboard releases it', async ({ browser }) => {
  test.slow()
  const context = await browser.newContext()
  await registerAccount(context, newAccount('wbquota', PASSWORD))
  const drive = await openDrive(context)
  await createWhiteboard(drive)
  const before = await usedBytes(context)

  await addImage(drive)
  await expect.poll(() => usedBytes(context), { timeout: 30_000 }).toBeGreaterThanOrEqual(before + ONE_PX_PNG.length)

  await drive.getByRole('link', { name: /^Back to / }).click()
  const name = 'Untitled whiteboard.excalidraw'
  await expect(item(drive, name)).toBeVisible({ timeout: 60_000 })
  await itemAction(drive, name, 'Move to trash')
  await openSection(drive, 'Trash')
  await itemAction(drive, name, 'Delete forever')
  await drive.getByRole('alertdialog').getByRole('button', { name: 'Delete forever', exact: true }).click()
  await expect.poll(() => usedBytes(context), { timeout: 30_000 }).toBeLessThanOrEqual(before)
  await context.close()
})
