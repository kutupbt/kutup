import { test, expect } from '@playwright/test'
import { signInOrBootstrap, attachCollabLogs } from '../fixtures/auth'

// Regression for commit 21a7af3 (Phase 5a).
//
// Bug: OnlyOffice v9's spreadsheet emits `obj.changes` as a JSON-encoded
// string, but `inner.html` did `Array.isArray(obj.changes) ? … : []` and
// always fell through to empty — every commit looked like a heartbeat.
// Fix: JSON.parse before mapping.
test.describe('office xlsx — outbound saveChanges carries content', () => {
  test('typing into a fresh xlsx emits non-empty saveChanges', async ({ context }) => {
    const page = await signInOrBootstrap(context)

    const editorPromise = context.waitForEvent('page', { timeout: 30_000 })
    await page.locator('button:has-text("New")').first().click()
    await page.waitForTimeout(500)
    await page.locator('[role=menuitem]:has-text("Spreadsheet")').first().click()
    const editor = await editorPromise
    await editor.waitForLoadState('domcontentloaded')

    const logs = attachCollabLogs(editor)

    // OnlyOffice spreadsheet needs ~25 s to fully bootstrap (auth + load + render).
    await editor.waitForTimeout(25_000)

    // Click roughly into A1 area + type. OO renders cells on canvas;
    // we use viewport coords because the spreadsheet iframe is nested
    // (editor tab → inner.html → spreadsheeteditor).
    await editor.mouse.click(200, 250)
    await editor.waitForTimeout(500)
    await editor.keyboard.type('hello', { delay: 80 })
    await editor.waitForTimeout(1_000)
    await editor.keyboard.press('Enter')
    await editor.waitForTimeout(5_000)

    const outbound = logs.filter((l) => l.includes('outbound saveChanges'))
    const nonEmpty = outbound.filter((l) => /raw=([1-9]\d*)/.test(l))
    expect(outbound.length, 'expected at least one outbound saveChanges').toBeGreaterThan(0)
    expect(nonEmpty.length, 'expected non-empty saveChanges (raw>0)').toBeGreaterThan(0)
  })
})
