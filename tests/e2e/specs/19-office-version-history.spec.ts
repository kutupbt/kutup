import { test, expect } from '@playwright/test'
import { signInOrBootstrap } from '../fixtures/auth'

// Office files now have version history parity with notes:
// - Save creates a new version row (already worked)
// - History sidebar mounts the existing VersionHistoryPanel
// - Restore = re-snapshot the old blob as a new version + reload
//
// This spec covers: save twice → list shows two rows → restore the older.

test('office xlsx — save twice, history shows two versions, restore round-trips', async ({ context }) => {
  const page = await signInOrBootstrap(context)

  const tabAPromise = context.waitForEvent('page', { timeout: 30_000 })
  await page.locator('button:has-text("New")').first().click()
  await page.waitForTimeout(500)
  await page.locator('[role=menuitem]:has-text("Spreadsheet")').first().click()
  const tabA = await tabAPromise
  await tabA.waitForLoadState('domcontentloaded')

  // OO bootstrap.
  await tabA.waitForTimeout(30_000)

  // Type something so the snapshot has content.
  await tabA.bringToFront()
  await tabA.mouse.click(440, 263)  // dismiss "Cell text direction" tutorial popup
  await tabA.waitForTimeout(300)
  await tabA.mouse.click(200, 250)
  await tabA.waitForTimeout(300)
  await tabA.keyboard.type('first', { delay: 60 })
  await tabA.keyboard.press('Enter')
  await tabA.waitForTimeout(1_000)

  // Save (creates version 1).
  await tabA.locator('header button[title="Save current state (⌘/Ctrl+S)"]').click()
  await tabA.waitForTimeout(3_000)

  // Type more.
  await tabA.mouse.click(200, 250)
  await tabA.waitForTimeout(300)
  await tabA.keyboard.type('second', { delay: 60 })
  await tabA.keyboard.press('Enter')
  await tabA.waitForTimeout(1_000)

  // Save again (version 2).
  await tabA.locator('header button[title="Save current state (⌘/Ctrl+S)"]').click()
  await tabA.waitForTimeout(3_000)

  // Open History sidebar.
  await tabA.locator('header button:has-text("History")').click()
  await tabA.waitForTimeout(2_000)

  // Sidebar should appear with the version-history heading + at least 2 rows.
  await expect(tabA.locator('aside h2:has-text("Version history")')).toBeVisible()
  // VersionRow renders a Restore button per row; count = number of versions.
  const restoreBtns = tabA.locator('aside button:has-text("Restore")')
  const count = await restoreBtns.count()
  expect(count, 'at least 2 version rows in sidebar').toBeGreaterThanOrEqual(2)

  // Restore the OLDEST version (last button in the newest-first list) to
  // exercise the round-trip. RestoreConfirmDialog opens; click "Save &
  // restore" to back up the current state then apply the old one.
  await restoreBtns.last().click()
  await expect(tabA.locator('[role=dialog]:has-text("Restore this version?")')).toBeVisible()
  await tabA.locator('[role=dialog] button:has-text("Save & restore")').click()

  // The restore handler reloads the page; wait for it.
  await tabA.waitForLoadState('domcontentloaded')
  await tabA.waitForTimeout(20_000)

  // Post-reload sanity: the editor mounted with some content (canvas count > 0
  // means OO is up). We don't pixel-diff the OOXML — that's opaque.
  const canvases = await tabA.evaluate(() => {
    const ifr = document.querySelector('iframe') as HTMLIFrameElement | null
    const inner = ifr?.contentDocument?.querySelector('iframe') as HTMLIFrameElement | null
    return inner?.contentDocument?.querySelectorAll('canvas').length ?? 0
  })
  expect(canvases, 'OO loaded post-restore').toBeGreaterThan(0)
})
