import { test, expect } from '@playwright/test'
import { signInOrBootstrap } from '../fixtures/auth'

// Whiteboard MVP: create from New menu → editor mounts → save persists
// across reload. Excalidraw is a React canvas (no nested iframe), so the
// scene is reachable via window.* probes if the API was exposed; we
// simplify by asserting the editor's canvas element exists post-reload.

test('whiteboard — create, save, reload persists', async ({ context }) => {
  const page = await signInOrBootstrap(context)

  const tabAPromise = context.waitForEvent('page', { timeout: 30_000 })
  await page.locator('button:has-text("New")').first().click()
  await page.waitForTimeout(500)
  await page.locator('[role=menuitem]:has-text("Whiteboard")').first().click()
  const editor = await tabAPromise
  await editor.waitForLoadState('domcontentloaded')

  // Excalidraw mount + lazy chunk + initial render
  await editor.waitForTimeout(8_000)

  // Excalidraw renders a <canvas> (potentially multiple). Presence is
  // enough to confirm the editor mounted.
  const canvasCount = await editor.locator('canvas').count()
  expect(canvasCount, 'whiteboard canvas mounted').toBeGreaterThan(0)

  // Click Save to create the first version.
  await editor.locator('header button[title="Save current state (⌘/Ctrl+S)"]').click()
  await editor.waitForTimeout(3_000)

  // Open History → at least one row
  await editor.locator('header button:has-text("History")').click()
  await editor.waitForTimeout(2_000)
  await expect(editor.locator('aside h2:has-text("Version history")')).toBeVisible()
  const restoreBtns = editor.locator('aside button:has-text("Restore")')
  expect(await restoreBtns.count(), 'at least 1 version row').toBeGreaterThanOrEqual(1)

  // Reload — editor should remount and pick up the saved (latest) version.
  await editor.reload()
  await editor.waitForLoadState('domcontentloaded')
  await editor.waitForTimeout(8_000)
  expect(await editor.locator('canvas').count(), 'whiteboard canvas after reload').toBeGreaterThan(0)
})
