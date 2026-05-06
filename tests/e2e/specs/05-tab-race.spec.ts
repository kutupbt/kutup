import { test, expect } from '@playwright/test'
import { signInOrBootstrap, attachCollabLogs } from '../fixtures/auth'

// User report (2026-05-06): "if I open 2 tabs very very speedly … sometimes
// it is not working … in notes if I open 2 tabs very quickly sometimes it
// did not connect I need to refresh."
//
// Each test below opens both tabs as close together as possible (Promise.all
// on the goto), so the race window for both tabs hitting the WS / hello /
// log-replay sequence simultaneously is hit on every run, not occasionally.

const RUNS = 5  // bump if we want to push the race window harder

test.describe('two-tab race — notes', () => {
  for (let i = 1; i <= RUNS; i++) {
    test(`run ${i}/${RUNS}: simultaneous open + edit syncs both ways`, async ({ context }) => {
      const driver = await signInOrBootstrap(context)

      // Create the note (so both A and B open the SAME file).
      const tabAPromise = context.waitForEvent('page', { timeout: 30_000 })
      await driver.locator('button:has-text("New")').first().click()
      await driver.waitForTimeout(500)
      await driver.locator('[role=menuitem]:has-text("Note")').first().click()
      await driver.waitForTimeout(500)
      await driver.locator('button:has-text("Create")').last().click()
      const tabA = await tabAPromise
      await tabA.waitForLoadState('domcontentloaded')
      const fileUrl = tabA.url()
      await tabA.close()  // close A so we can re-open A and B truly simultaneously

      // Race window: both tabs open at almost the same instant.
      const tabA2 = await context.newPage()
      const tabB = await context.newPage()
      const aLogs = attachCollabLogs(tabA2, `note-A.${i}`)
      const bLogs = attachCollabLogs(tabB, `note-B.${i}`)
      await Promise.all([tabA2.goto(fileUrl), tabB.goto(fileUrl)])
      await Promise.all([tabA2.waitForLoadState('domcontentloaded'), tabB.waitForLoadState('domcontentloaded')])

      // Wait for both editors to mount + WS connect.
      await tabA2.waitForTimeout(7_000)

      // Type in tab A.
      await tabA2.bringToFront()
      await tabA2.locator('.cm-content').click()
      await tabA2.keyboard.type(' edit-from-A', { delay: 60 })
      // Give the YJS_UPDATE → relay → tab B → applyUpdate chain time.
      await tabA2.waitForTimeout(3_000)

      const aText = await tabA2.evaluate(() => {
        const el = document.querySelector('.cm-content')
        return el ? (el as HTMLElement).innerText : ''
      })
      const bText = await tabB.evaluate(() => {
        const el = document.querySelector('.cm-content')
        return el ? (el as HTMLElement).innerText : ''
      })

      // Both tabs should show A's edit. The bug shows up as either:
      //   - tabB doesn't receive A's edit (one-way / no sync)
      //   - tabB shows duplicated content
      expect(aText, `tab A self-text (run ${i})`).toContain('edit-from-A')
      expect(bText, `tab B remote-text (run ${i})`).toContain('edit-from-A')
      // Heading shouldn't be duplicated either.
      const headingCount = (bText.match(/# Untitled/g) ?? []).length
      expect(headingCount, `# Untitled count in tab B (run ${i})`).toBe(1)
    })
  }
})

test.describe('two-tab race — xlsx', () => {
  for (let i = 1; i <= RUNS; i++) {
    test(`run ${i}/${RUNS}: simultaneous open + edits propagate both ways`, async ({ context }) => {
      const driver = await signInOrBootstrap(context)

      const tabAPromise = context.waitForEvent('page', { timeout: 30_000 })
      await driver.locator('button:has-text("New")').first().click()
      await driver.waitForTimeout(500)
      await driver.locator('[role=menuitem]:has-text("Spreadsheet")').first().click()
      const tabA = await tabAPromise
      await tabA.waitForLoadState('domcontentloaded')
      const fileUrl = tabA.url()
      await tabA.close()

      // Race window.
      const tabA2 = await context.newPage()
      const tabB = await context.newPage()
      const aLogs = attachCollabLogs(tabA2, `xlsx-A.${i}`)
      const bLogs = attachCollabLogs(tabB, `xlsx-B.${i}`)
      await Promise.all([tabA2.goto(fileUrl), tabB.goto(fileUrl)])
      await Promise.all([tabA2.waitForLoadState('domcontentloaded'), tabB.waitForLoadState('domcontentloaded')])

      // OnlyOffice spreadsheet bootstrap is slow.
      await tabA2.waitForTimeout(30_000)

      // Type concurrently in different cells from BOTH tabs.
      await Promise.all([
        (async () => {
          await tabA2.bringToFront()
          await tabA2.mouse.click(200, 250)
          await tabA2.waitForTimeout(300)
          await tabA2.keyboard.type('alpha', { delay: 80 })
          await tabA2.keyboard.press('Enter')
        })(),
        (async () => {
          await tabB.bringToFront()
          await tabB.mouse.click(400, 250)
          await tabB.waitForTimeout(300)
          await tabB.keyboard.type('beta', { delay: 80 })
          await tabB.keyboard.press('Enter')
        })(),
      ])
      await tabA2.waitForTimeout(8_000)

      const outA = aLogs.filter((l) => l.includes('outbound saveChanges') && /raw=([1-9]\d*)/.test(l)).length
      const outB = bLogs.filter((l) => l.includes('outbound saveChanges') && /raw=([1-9]\d*)/.test(l)).length
      const appA = aLogs.filter((l) => l.includes('applying remote op')).length
      const appB = bLogs.filter((l) => l.includes('applying remote op')).length

      // The race-condition symptom is: outA/outB > 0 (both can send) but
      // appA == 0 or appB == 0 (one-way sync only).
      expect(outA, `run ${i}: tab A outbound`).toBeGreaterThan(0)
      expect(outB, `run ${i}: tab B outbound`).toBeGreaterThan(0)
      expect(appA, `run ${i}: tab A applied B's op (sync direction B→A)`).toBeGreaterThan(0)
      expect(appB, `run ${i}: tab B applied A's op (sync direction A→B)`).toBeGreaterThan(0)
    })
  }
})
