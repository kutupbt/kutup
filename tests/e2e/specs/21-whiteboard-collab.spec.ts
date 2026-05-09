import { test, expect } from '@playwright/test'
import { signInOrBootstrap } from '../fixtures/auth'

// Whiteboard collab regression: an element added via tab A's imperative
// API reaches tab B via the EXCALIDRAW_OP envelope kind. Excalidraw's
// reconcileElements does the merge.
//
// Probe via window.__EXCALIDRAW_API__ exposed by WhiteboardEditor.

test('whiteboard — element added on tab A appears on tab B', async ({ context }) => {
  const page = await signInOrBootstrap(context)

  const tabAPromise = context.waitForEvent('page', { timeout: 30_000 })
  await page.locator('button:has-text("New")').first().click()
  await page.waitForTimeout(500)
  await page.locator('[role=menuitem]:has-text("Whiteboard")').first().click()
  const tabA = await tabAPromise
  await tabA.waitForLoadState('domcontentloaded')
  const fileUrl = tabA.url()

  const tabB = await context.newPage()
  await tabB.goto(fileUrl)
  await tabB.waitForLoadState('domcontentloaded')

  await tabA.waitForTimeout(8_000)
  await tabB.waitForTimeout(8_000)

  // Inject a rectangle on tab A via the imperative API. Forge minimal
  // OrderedExcalidrawElement fields — Excalidraw fills the rest in
  // updateScene + restoreElements.
  const beforeB = await tabB.evaluate(() => {
    const api = (window as any).__EXCALIDRAW_API__
    return api ? api.getSceneElements().length : -1
  })

  await tabA.evaluate(() => {
    const api = (window as any).__EXCALIDRAW_API__
    if (!api) throw new Error('no api on tab A')
    const el = {
      id: 'kutup-test-' + Math.random().toString(36).slice(2, 10),
      type: 'rectangle',
      x: 100, y: 100,
      width: 200, height: 100,
      angle: 0,
      strokeColor: '#000000',
      backgroundColor: 'transparent',
      fillStyle: 'solid',
      strokeWidth: 2,
      strokeStyle: 'solid',
      roughness: 1,
      opacity: 100,
      groupIds: [],
      frameId: null,
      roundness: null,
      seed: 1,
      version: 1,
      versionNonce: 1,
      isDeleted: false,
      boundElements: null,
      updated: Date.now(),
      link: null,
      locked: false,
      index: 'a0',
    }
    api.updateScene({ elements: [...api.getSceneElements(), el] })
  })

  // Wait for the broadcast (debounced 200ms) + WS round-trip.
  await tabA.waitForTimeout(2_500)

  const afterB = await tabB.evaluate(() => {
    const api = (window as any).__EXCALIDRAW_API__
    return api ? api.getSceneElements().length : -1
  })

  expect(beforeB, 'tab B api available pre-broadcast').toBeGreaterThanOrEqual(0)
  expect(afterB, 'tab B element count grew after tab A added one').toBeGreaterThan(beforeB)
})
