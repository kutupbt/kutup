import { expect, test } from '@playwright/test'
import { newAccount, openDrive, registerAccount } from '../fixtures/apps'
import { addRectangle, createWhiteboard, elementCount, historyPanel, saveState, whiteboardReady } from '../fixtures/whiteboard'

const PASSWORD = 'Deneme123*WhiteboardPassword'

test('a saved whiteboard keeps its version and survives a reload', async ({ browser }) => {
  const context = await browser.newContext()
  await registerAccount(context, newAccount('wboard', PASSWORD))
  const page = await openDrive(context)
  await createWhiteboard(page)
  await addRectangle(page)
  await saveState(page)
  await page.getByRole('button', { name: 'History', exact: true }).click()
  await expect(historyPanel(page).getByRole('button', { name: 'Restore', exact: true }).first()).toBeVisible({ timeout: 30_000 })

  await page.reload()
  await whiteboardReady(page)
  await expect.poll(() => elementCount(page), { timeout: 30_000 }).toBe(1)
  await context.close()
})

test('restoring an older version brings back that scene, not the latest', async ({ browser }) => {
  test.slow()
  const context = await browser.newContext()
  await registerAccount(context, newAccount('wbrestore', PASSWORD))
  const page = await openDrive(context)
  await createWhiteboard(page)
  await saveState(page)
  await addRectangle(page)
  await expect.poll(() => elementCount(page)).toBe(1)
  await saveState(page)

  await page.getByRole('button', { name: 'History', exact: true }).click()
  const restore = historyPanel(page).getByRole('button', { name: 'Restore', exact: true })
  await expect.poll(() => restore.count(), { timeout: 30_000 }).toBeGreaterThanOrEqual(2)
  await restore.last().click()
  await page.getByRole('dialog').getByRole('button', { name: 'Restore only' }).click()
  // The empty first version, not overwritten by replaying later changes.
  await expect.poll(() => elementCount(page).catch(() => -1), { timeout: 30_000 }).toBe(0)
  await page.reload()
  await whiteboardReady(page)
  await expect.poll(() => elementCount(page), { timeout: 30_000 }).toBe(0)
  await context.close()
})
