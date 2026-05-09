import { test, expect } from '@playwright/test'
import { signInOrBootstrap } from '../fixtures/auth'

// Restore regression: when a user restores an older whiteboard snapshot,
// the page reloads and the scene must match the restored snapshot —
// NOT the most-recent live state.
//
// Pre-fix the EXCALIDRAW_OP frames were persisted, so on reconnect the
// server replayed every historical element delta and reconcileElements
// re-applied them by versionNonce — clobbering the freshly-restored
// scene with whatever was last drawn. Making EXCALIDRAW_OP ephemeral
// fixed this. Spec freezes that contract.

test('whiteboard — restore picks up the older scene, not the latest', async ({ context }) => {
  const page = await signInOrBootstrap(context)

  const tabPromise = context.waitForEvent('page', { timeout: 30_000 })
  await page.locator('button:has-text("New")').first().click()
  await page.waitForTimeout(500)
  await page.locator('[role=menuitem]:has-text("Whiteboard")').first().click()
  const editor = await tabPromise
  await editor.waitForLoadState('domcontentloaded')
  await editor.waitForTimeout(8_000)

  // V1: empty save (initial empty scene).
  await editor.locator('header button[title="Save current state (⌘/Ctrl+S)"]').click()
  await editor.waitForTimeout(2_000)

  // Add an element via the imperative API, then save → V2.
  await editor.evaluate(() => {
    const api = (window as any).__EXCALIDRAW_API__
    const el = {
      id: 'kutup-restore-' + Math.random().toString(36).slice(2, 10),
      type: 'rectangle',
      x: 100, y: 100, width: 200, height: 100, angle: 0,
      strokeColor: '#000000', backgroundColor: 'transparent',
      fillStyle: 'solid', strokeWidth: 2, strokeStyle: 'solid',
      roughness: 1, opacity: 100,
      groupIds: [], frameId: null, roundness: null,
      seed: 1, version: 1, versionNonce: 1, isDeleted: false,
      boundElements: null, updated: Date.now(), link: null,
      locked: false, index: 'a0',
    }
    api.updateScene({ elements: [...api.getSceneElements(), el] })
  })
  // Let the EXCALIDRAW_OP broadcast happen (200ms debounce + relay).
  await editor.waitForTimeout(1_500)
  await editor.locator('header button[title="Save current state (⌘/Ctrl+S)"]').click()
  await editor.waitForTimeout(2_000)

  // Confirm V2 has 1 element on screen.
  const beforeRestore = await editor.evaluate(() => {
    const api = (window as any).__EXCALIDRAW_API__
    return api.getSceneElements().length
  })
  expect(beforeRestore, 'V2 has the rectangle').toBe(1)

  // Open history. The list is newest-first, so the BOTTOM row is V1
  // (empty). Click its Restore button.
  await editor.locator('header button:has-text("History")').click()
  await editor.waitForTimeout(1_500)
  const restoreBtns = editor.locator('aside button:has-text("Restore")')
  const n = await restoreBtns.count()
  expect(n, 'at least 2 versions in history').toBeGreaterThanOrEqual(2)
  await restoreBtns.nth(n - 1).click()
  // RestoreConfirmDialog → Restore only (don't pre-save current).
  await editor.locator('button:has-text("Restore only")').click()

  // performBlobRestore reloads the page. Wait for new scene.
  await editor.waitForTimeout(8_000)

  const afterRestore = await editor.evaluate(() => {
    const api = (window as any).__EXCALIDRAW_API__
    return api ? api.getSceneElements().length : -1
  })
  expect(afterRestore, 'restored scene is empty (V1) — not clobbered by replay').toBe(0)
})
