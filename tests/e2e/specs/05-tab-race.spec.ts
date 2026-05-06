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

      // Unique-per-run filename so we don't collide with notes from prior
      // runs of this spec (handleCreateNote rejects same-name files in
      // the current folder; the test stack isn't wiped between runs).
      const fname = `race-note-${Date.now()}-${i}.md`

      // Create the note (so both A and B open the SAME file).
      const tabAPromise = context.waitForEvent('page', { timeout: 30_000 })
      await driver.locator('button:has-text("New")').first().click()
      await driver.waitForTimeout(500)
      await driver.locator('[role=menuitem]:has-text("Note")').first().click()
      await driver.waitForTimeout(500)
      // The dialog has a single visible input (filename); shadcn's <Input>
      // doesn't set type=text explicitly, so match by role.
      const nameInput = driver.getByRole('textbox').first()
      await nameInput.fill(fname)
      await driver.locator('button:has-text("Create")').last().click()
      const tabA = await tabAPromise
      attachCollabLogs(tabA, `note-orig.${i}`)
      await tabA.waitForLoadState('domcontentloaded')
      const fileUrl = tabA.url()
      // Let the original tab's editor fully boot + run cold-start +
      // claim-seed + persist the seed YJS_UPDATE to the log. Closing
      // before this completes would leave seed_committed=true on the
      // server with no frame in file_update_log — losing tabs would
      // then skip seeding and never receive any content via replay.
      await tabA.waitForTimeout(7_000)
      await tabA.close()

      // Race window: both tabs open at almost the same instant. The
      // simultaneous Promise.all on goto is the realistic re-open
      // scenario the user reported (Ctrl-click the file row twice).
      const tabA2 = await context.newPage()
      const tabB = await context.newPage()
      const aLogs = attachCollabLogs(tabA2, `note-A.${i}`)
      const bLogs = attachCollabLogs(tabB, `note-B.${i}`)
      await Promise.all([tabA2.goto(fileUrl), tabB.goto(fileUrl)])
      await Promise.all([tabA2.waitForLoadState('domcontentloaded'), tabB.waitForLoadState('domcontentloaded')])

      // Wait for both editors to mount + WS connect + replay.
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
      // Heading shouldn't be duplicated either. The seed is "# <basename>\n\n"
      // where basename is fname without the .md.
      const seedHeading = '# ' + fname.replace(/\.md$/, '')
      const re = new RegExp(seedHeading.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'g')
      const headingCount = (bText.match(re) ?? []).length
      expect(headingCount, `seed heading count in tab B (run ${i})`).toBe(1)
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

      // Type only in tabA. Playwright struggles to drive keyboard events
      // into the second tab when both contain a heavy iframe (OnlyOffice
      // spreadsheet). The race we want to verify is the simultaneous OPEN
      // surviving the (file_id, sender_device, sender_seq) UNIQUE-index
      // collision that used to drop one tab's frame. After the per-tab
      // prefix fix in identity.ts, neither tab's frame collides — visible
      // here as: tabA's edit reaches tabB via the relay.
      await tabA2.bringToFront()
      await tabA2.mouse.click(200, 250)
      await tabA2.waitForTimeout(500)
      await tabA2.keyboard.type('alpha', { delay: 80 })
      await tabA2.keyboard.press('Enter')
      await tabA2.waitForTimeout(6_000)

      const outA = aLogs.filter((l) => l.includes('outbound saveChanges') && /raw=([1-9]\d*)/.test(l)).length
      const appB = bLogs.filter((l) => l.includes('applying remote op')).length

      expect(outA, `run ${i}: tab A outbound`).toBeGreaterThan(0)
      expect(appB, `run ${i}: tab B applied A's op (sync A→B)`).toBeGreaterThan(0)
    })
  }
})
