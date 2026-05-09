import { test, expect } from '@playwright/test'
import { signInOrBootstrap, attachCollabLogs } from '../fixtures/auth'

// Mirrors 08-office-refresh for docx. The fix in 47501b2 (send oo-self on
// bridge ready) is format-agnostic, but the docx canary catches future
// drift and confirms the maybeStart() handshake works for all 3 types.
test.describe('office docx — page refresh', () => {
  test('refresh keeps OnlyOffice loaded (no maybeStart deadlock)', async ({ context }) => {
    const page = await signInOrBootstrap(context)

    const tabAPromise = context.waitForEvent('page', { timeout: 30_000 })
    await page.locator('button:has-text("New")').first().click()
    await page.waitForTimeout(500)
    await page.locator('[role=menuitem]:has-text("Document")').first().click()
    const tabA = await tabAPromise
    await tabA.waitForLoadState('domcontentloaded')

    attachCollabLogs(tabA, 'A')

    await tabA.waitForTimeout(20_000)

    const canvasesBefore = await tabA.evaluate(() => {
      const ifr = document.querySelector('iframe') as HTMLIFrameElement | null
      const inner = ifr?.contentDocument?.querySelector('iframe') as HTMLIFrameElement | null
      return inner?.contentDocument?.querySelectorAll('canvas').length ?? 0
    })
    expect(canvasesBefore, 'canvases before refresh').toBeGreaterThan(0)

    await tabA.reload()
    await tabA.waitForLoadState('domcontentloaded')
    await tabA.waitForTimeout(20_000)

    const canvasesAfter = await tabA.evaluate(() => {
      const ifr = document.querySelector('iframe') as HTMLIFrameElement | null
      const inner = ifr?.contentDocument?.querySelector('iframe') as HTMLIFrameElement | null
      return inner?.contentDocument?.querySelectorAll('canvas').length ?? 0
    })
    expect(canvasesAfter, 'canvases after refresh').toBeGreaterThan(0)
  })
})
