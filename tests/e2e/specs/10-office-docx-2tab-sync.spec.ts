import { test, expect } from '@playwright/test'
import { signInOrBootstrap, attachCollabLogs } from '../fixtures/auth'

// Two-tab sync for docx — mirrors 04-office-2tab-sync (xlsx). Skips the
// simultaneous-edit case (same flake we live with on xlsx). Verifies that
// the docx-specific lock-shape fix in 09 also unblocks cross-tab op
// propagation, not just self-side typing.
test.describe('office docx — two-tab sync (happy path)', () => {
  test('one-way: type in A → tab B applies the remote op', async ({ context }) => {
    const page = await signInOrBootstrap(context)

    const tabAPromise = context.waitForEvent('page', { timeout: 30_000 })
    await page.locator('button:has-text("New")').first().click()
    await page.waitForTimeout(500)
    await page.locator('[role=menuitem]:has-text("Document")').first().click()
    const tabA = await tabAPromise
    await tabA.waitForLoadState('domcontentloaded')
    const fileUrl = tabA.url()

    const tabB = await context.newPage()
    await tabB.goto(fileUrl)
    await tabB.waitForLoadState('domcontentloaded')

    const aLogs = attachCollabLogs(tabA, 'A')
    const bLogs = attachCollabLogs(tabB, 'B')

    await tabA.waitForTimeout(30_000)

    await tabA.bringToFront()
    await tabA.mouse.click(640, 380)
    await tabA.waitForTimeout(500)
    await tabA.keyboard.type('hello world', { delay: 80 })
    await tabA.waitForTimeout(5_000)

    const outA = aLogs.filter((l) => l.includes('outbound saveChanges') && /raw=([1-9]\d*)/.test(l)).length
    const appliedB = bLogs.filter((l) => l.includes('applying remote op')).length
    expect(outA, 'tab A outbound saveChanges').toBeGreaterThan(0)
    expect(appliedB, 'tab B applied remote op').toBeGreaterThan(0)
  })

  test('sequential: A→B works, then B→A also works', async ({ context }) => {
    const page = await signInOrBootstrap(context)

    const tabAPromise = context.waitForEvent('page', { timeout: 30_000 })
    await page.locator('button:has-text("New")').first().click()
    await page.waitForTimeout(500)
    await page.locator('[role=menuitem]:has-text("Document")').first().click()
    const tabA = await tabAPromise
    await tabA.waitForLoadState('domcontentloaded')
    const fileUrl = tabA.url()

    const tabB = await context.newPage()
    await tabB.goto(fileUrl)
    await tabB.waitForLoadState('domcontentloaded')

    const aLogs = attachCollabLogs(tabA, 'A')
    const bLogs = attachCollabLogs(tabB, 'B')

    await tabA.waitForTimeout(30_000)

    // Phase 1: A types, B should receive.
    await tabA.bringToFront()
    await tabA.mouse.click(640, 380)
    await tabA.waitForTimeout(500)
    await tabA.keyboard.type('first', { delay: 80 })
    await tabA.waitForTimeout(5_000)

    const appliedBPhase1 = bLogs.filter((l) => l.includes('applying remote op')).length
    expect(appliedBPhase1, 'tab B applied phase-1 op from A').toBeGreaterThan(0)

    // Phase 2: B types, A should receive.
    const appliedABefore = aLogs.filter((l) => l.includes('applying remote op')).length
    await tabB.bringToFront()
    await tabB.mouse.click(640, 380)
    await tabB.waitForTimeout(500)
    await tabB.keyboard.type('second', { delay: 80 })
    await tabB.waitForTimeout(5_000)

    const outBPhase2 = bLogs.filter((l) => l.includes('outbound saveChanges') && /raw=([1-9]\d*)/.test(l)).length
    const appliedAAfter = aLogs.filter((l) => l.includes('applying remote op')).length

    expect(outBPhase2, 'tab B outbound saveChanges in phase-2').toBeGreaterThan(0)
    expect(appliedAAfter - appliedABefore, 'tab A applied phase-2 op from B').toBeGreaterThan(0)
  })
})
