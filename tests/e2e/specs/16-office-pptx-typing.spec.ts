import { test, expect } from '@playwright/test'
import { signInOrBootstrap, attachCollabLogs } from '../fixtures/auth'

// Mirrors spec 09 (docx typing) for pptx. The wire is format-agnostic but
// no canary covers pptx typing specifically — this guards against a
// future change that breaks pptx without breaking docx/xlsx.
//
// Single-tab: enter text-edit mode in the title placeholder, type, assert
// outbound saveChanges count grows. The docx test additionally checks
// post-Enter typing because that was the original docx repro; pptx Enter
// behaviour in placeholders is more nuanced (creates a new line in the
// same shape, doesn't request a new lock-block) and not worth gating.
test('pptx accepts input in a slide text placeholder', async ({ context }) => {
  const page = await signInOrBootstrap(context)

  const tabAPromise = context.waitForEvent('page', { timeout: 30_000 })
  await page.locator('button:has-text("New")').first().click()
  await page.waitForTimeout(500)
  await page.locator('[role=menuitem]:has-text("Presentation")').first().click()
  const tabA = await tabAPromise
  await tabA.waitForLoadState('domcontentloaded')

  const aLogs = attachCollabLogs(tabA, 'A')

  await tabA.waitForTimeout(30_000)

  // Single click selects the placeholder shape; double-click enters
  // text-edit mode.
  await tabA.bringToFront()
  await tabA.mouse.click(640, 280)
  await tabA.waitForTimeout(500)
  await tabA.mouse.dblclick(640, 280)
  await tabA.waitForTimeout(500)

  await tabA.keyboard.type('hello pptx', { delay: 80 })
  await tabA.waitForTimeout(3_000)

  const out = aLogs.filter((l) => l.includes('outbound saveChanges') && /raw=([1-9]\d*)/.test(l)).length
  expect(out, 'pptx outbound saveChanges from typing').toBeGreaterThan(0)
})
