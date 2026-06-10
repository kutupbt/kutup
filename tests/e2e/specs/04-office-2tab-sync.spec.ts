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

    // Serialize the cell click + cell focus across both tabs first; only
    // the typing runs concurrently. Earlier this block called bringToFront
    // inside Promise.all, racing for OS-level focus — whichever lost ended
    // up with its keystrokes going to a tab OnlyOffice didn't treat as
    // active, dropping all saveChanges. Click + 300ms wait per tab,
    // sequentially, picks the cell on each side without the focus race.
    await tabA.bringToFront()
    await tabA.mouse.click(200, 250)
    await tabA.waitForTimeout(300)
    await tabB.bringToFront()
    await tabB.mouse.click(400, 250)
    await tabB.waitForTimeout(300)
    // Now type concurrently. Page.keyboard targets a specific Page object
    // regardless of OS focus, so this part is safe to parallelise.
    await Promise.all([
      tabA.keyboard.type('alpha', { delay: 80 }),
      tabB.keyboard.type('beta', { delay: 80 }),
    ])
    await Promise.all([
      tabA.keyboard.press('Enter'),
      tabB.keyboard.press('Enter'),
    ])
    // Poll the (continuously-appended) collab logs until both directions have
    // synced, rather than a fixed sleep + one-shot assert — concurrent
    // OnlyOffice saveChanges timing is jittery, so a hard 5 s wait was flaky.
    const outbound = (logs: string[]) =>
      logs.filter((l) => l.includes('outbound saveChanges') && /raw=([1-9]\d*)/.test(l)).length
    const applied = (logs: string[]) => logs.filter((l) => l.includes('applying remote op')).length

    await expect.poll(() => outbound(aLogs), { timeout: 30_000, message: 'tab A outbound' }).toBeGreaterThan(0)
    await expect.poll(() => outbound(bLogs), { timeout: 30_000, message: 'tab B outbound' }).toBeGreaterThan(0)
    await expect.poll(() => applied(aLogs), { timeout: 30_000, message: "tab A applied B's op" }).toBeGreaterThan(0)
    await expect.poll(() => applied(bLogs), { timeout: 30_000, message: "tab B applied A's op" }).toBeGreaterThan(0)
  })

  // Reproduces the user-reported xlsx stall: A types and B receives,
  // then B types and A is supposed to receive. The "two-way" test above
  // exercises simultaneous edits, which masks this failure mode.
  test('sequential: A→B works, then B→A also works', async ({ context }) => {
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

    // Phase 1: A types, B should receive.
    await tabA.bringToFront()
    await tabA.mouse.click(200, 250)
    await tabA.waitForTimeout(500)
    await tabA.keyboard.type('first', { delay: 80 })
    await tabA.keyboard.press('Enter')
    await tabA.waitForTimeout(5_000)

    const appliedBPhase1 = bLogs.filter((l) => l.includes('applying remote op')).length
    expect(appliedBPhase1, 'tab B applied phase-1 op from A').toBeGreaterThan(0)

    // Phase 2: B types in a different cell, A should receive.
    const appliedABefore = aLogs.filter((l) => l.includes('applying remote op')).length
    await tabB.bringToFront()
    await tabB.mouse.click(400, 250)
    await tabB.waitForTimeout(500)
    await tabB.keyboard.type('second', { delay: 80 })
    await tabB.keyboard.press('Enter')
    await tabB.waitForTimeout(5_000)

    const outBPhase2 = bLogs.filter((l) => l.includes('outbound saveChanges') && /raw=([1-9]\d*)/.test(l)).length
    const appliedAAfter = aLogs.filter((l) => l.includes('applying remote op')).length

    expect(outBPhase2, 'tab B outbound saveChanges in phase-2').toBeGreaterThan(0)
    expect(appliedAAfter - appliedABefore, 'tab A applied phase-2 op from B').toBeGreaterThan(0)
  })
})
