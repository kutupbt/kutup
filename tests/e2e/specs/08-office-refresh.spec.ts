import { test, expect } from '@playwright/test'
import { signInOrBootstrap, attachCollabLogs } from '../fixtures/auth'

// Regression: refreshing /file/:cid/:fid for an xlsx left OnlyOffice unloaded.
//
// Root cause: on first login the WS effect in OfficeEditor awaits
// registerDevice(), which gives inner.html time to attach its postMessage
// listener before 'oo-self' is sent. On a refresh, currentDeviceId is hydrated
// from sessionStorage so registration is skipped — 'oo-self' was fired
// synchronously before the iframe loaded and silently dropped, leaving
// maybeStart() permanently gated on selfDeviceId/selfUserId.
//
// Fix: send 'oo-self' in response to inner.html's 'ready' message (alongside
// 'init'), guaranteeing the iframe is listening.
test.describe('office xlsx — page refresh', () => {
  test('refresh keeps OnlyOffice loaded (no maybeStart deadlock)', async ({ context }) => {
    const page = await signInOrBootstrap(context)

    const tabAPromise = context.waitForEvent('page', { timeout: 30_000 })
    await page.locator('button:has-text("New")').first().click()
    await page.waitForTimeout(500)
    await page.locator('[role=menuitem]:has-text("Spreadsheet")').first().click()
    const tabA = await tabAPromise
    await tabA.waitForLoadState('domcontentloaded')

    attachCollabLogs(tabA, 'A')

    // Wait for the OnlyOffice editor to fully bootstrap pre-refresh so we
    // can baseline the canvas count.
    await tabA.waitForTimeout(20_000)

    const canvasesBefore = await tabA.evaluate(() => {
      const ifr = document.querySelector('iframe') as HTMLIFrameElement | null
      const inner = ifr?.contentDocument?.querySelector('iframe') as HTMLIFrameElement | null
      return inner?.contentDocument?.querySelectorAll('canvas').length ?? 0
    })
    expect(canvasesBefore, 'canvases before refresh').toBeGreaterThan(0)

    await tabA.reload()
    await tabA.waitForLoadState('domcontentloaded')
    // OO needs the same bootstrap budget on refresh.
    await tabA.waitForTimeout(20_000)

    const canvasesAfter = await tabA.evaluate(() => {
      const ifr = document.querySelector('iframe') as HTMLIFrameElement | null
      const inner = ifr?.contentDocument?.querySelector('iframe') as HTMLIFrameElement | null
      return inner?.contentDocument?.querySelectorAll('canvas').length ?? 0
    })
    expect(canvasesAfter, 'canvases after refresh').toBeGreaterThan(0)
  })
})
