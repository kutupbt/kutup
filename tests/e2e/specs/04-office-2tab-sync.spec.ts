import { test, expect } from '@playwright/test'
import { signInOrBootstrap, attachCollabLogs } from '../fixtures/auth'

// Phase 5b: two tabs editing the same xlsx see each other's changes.
//
// This is the happy path (sequential open with breathing room between).
// The race-condition variants are in 06-tab-race.spec.ts.
test.describe('office xlsx — two-tab sync (happy path)', () => {
  test('one-way: type in A → tab B applies the remote op', async ({ context }) => {
    const page = await signInOrBootstrap(context)

    // Create + open in tab A.
    const tabAPromise = context.waitForEvent('page', { timeout: 30_000 })
    await page.locator('button:has-text("New")').first().click()
    await page.waitForTimeout(500)
    await page.locator('[role=menuitem]:has-text("Spreadsheet")').first().click()
    const tabA = await tabAPromise
    await tabA.waitForLoadState('domcontentloaded')
    const fileUrl = tabA.url()

    // Open same file in tab B.
    const tabB = await context.newPage()
    await tabB.goto(fileUrl)
    await tabB.waitForLoadState('domcontentloaded')

    const aLogs = attachCollabLogs(tabA, 'A')
    const bLogs = attachCollabLogs(tabB, 'B')

    // Both editors need time to fully bootstrap.
    await tabA.waitForTimeout(30_000)

    // Type in tab A.
    await tabA.bringToFront()
    await tabA.mouse.click(200, 250)
    await tabA.waitForTimeout(500)
    await tabA.keyboard.type('hello', { delay: 80 })
    await tabA.keyboard.press('Enter')
    await tabA.waitForTimeout(5_000)

    const outA = aLogs.filter((l) => l.includes('outbound saveChanges') && /raw=([1-9]\d*)/.test(l)).length
    const appliedB = bLogs.filter((l) => l.includes('applying remote op')).length
    expect(outA, 'tab A outbound saveChanges with content').toBeGreaterThan(0)
    expect(appliedB, 'tab B applied remote op count').toBeGreaterThan(0)
  })

  test('two-way: concurrent edits in different cells sync both directions', async ({ context }) => {
    const page = await signInOrBootstrap(context)

    const tabAPromise = context.waitForEvent('page', { timeout: 30_000 })
    await page.locator('button:has-text("New")').first().click()
    await page.waitForTimeout(500)
    await page.locator('[role=menuitem]:has-text("Spreadsheet")').first().click()
    const tabA = await tabAPromise
    await tabA.waitForLoadState('domcontentloaded')
    const fileUrl = tabA.url()

    const tabB = await context.newPage()
    await tabB.goto(fileUrl)
    await tabB.waitForLoadState('domcontentloaded')

    const aLogs = attachCollabLogs(tabA, 'A')
    const bLogs = attachCollabLogs(tabB, 'B')

    await tabA.waitForTimeout(30_000)

    await Promise.all([
      (async () => {
        await tabA.bringToFront()
        await tabA.mouse.click(200, 250)
        await tabA.waitForTimeout(300)
        await tabA.keyboard.type('alpha', { delay: 80 })
        await tabA.keyboard.press('Enter')
      })(),
      (async () => {
        await tabB.bringToFront()
        await tabB.mouse.click(400, 250)
        await tabB.waitForTimeout(300)
        await tabB.keyboard.type('beta', { delay: 80 })
        await tabB.keyboard.press('Enter')
      })(),
    ])
    await tabA.waitForTimeout(5_000)

    const outA = aLogs.filter((l) => l.includes('outbound saveChanges') && /raw=([1-9]\d*)/.test(l)).length
    const outB = bLogs.filter((l) => l.includes('outbound saveChanges') && /raw=([1-9]\d*)/.test(l)).length
    const appA = aLogs.filter((l) => l.includes('applying remote op')).length
    const appB = bLogs.filter((l) => l.includes('applying remote op')).length

    expect(outA, 'tab A outbound').toBeGreaterThan(0)
    expect(outB, 'tab B outbound').toBeGreaterThan(0)
    expect(appA, 'tab A applied B\'s op').toBeGreaterThan(0)
    expect(appB, 'tab B applied A\'s op').toBeGreaterThan(0)
  })
})
