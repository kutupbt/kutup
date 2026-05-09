import { test, expect } from '@playwright/test'
import { signInOrBootstrap, attachCollabLogs } from '../fixtures/auth'

// Cross-tab cell-formatting sync for xlsx. xlsx's lock-grant for cell-level
// operations had a 3-attempt fix history (PR #9 + research file 08), so this
// gates the path against future regression.
//
// Currently exercises Ctrl+U (underline). Bold/italic exhibit a flake on
// the FIRST xlsx open per browser session because OO v9 shows a one-shot
// "Cell text direction" feature-callout tooltip that intercepts the
// initial Ctrl+B/I; underline runs after the popup is dismissed and works
// reliably. The lock path is identical for all three; one passing test is
// enough to gate it. (We can add bold/italic once a reliable pre-test
// popup-dismiss is found — toolbar selectors or localStorage flag.)

async function openTwoTabs(context: any) {
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
  attachCollabLogs(tabA, 'A')
  attachCollabLogs(tabB, 'B')
  await tabA.waitForTimeout(30_000)
  return { tabA, tabB }
}

async function probeActiveCell(tab: any) {
  return tab.evaluate(`(() => {
    const outerIfr = document.querySelector('iframe');
    const innerIfr = outerIfr && outerIfr.contentDocument && outerIfr.contentDocument.querySelector('iframe');
    const w = innerIfr && innerIfr.contentWindow;
    const editor = w && (w.editor || w.editorCell);
    if (!editor) return { state: 'no-editor' };
    const wb = editor.wb || editor.WB || (editor.controller && editor.controller.wb);
    if (!wb) return { state: 'no-wb' };
    const model = wb.model || wb.Model;
    const ws = model && model.getActiveWs && model.getActiveWs();
    if (!ws) return { state: 'no-ws' };
    const wsView = wb.getWorksheet && wb.getWorksheet();
    const activeRange = wsView && wsView.activeRange;
    const row = activeRange ? activeRange.r1 : 0;
    const col = activeRange ? activeRange.c1 : 0;
    const cell = ws.getCell3 ? ws.getCell3(row, col) : (ws.getCell ? ws.getCell(row, col) : null);
    if (!cell) return { state: 'no-cell' };
    const font = cell.getFont ? cell.getFont() : null;
    if (!font) return { state: 'no-font' };
    return {
      state: 'ok',
      row, col,
      bold: font.getBold ? !!font.getBold() : null,
      italic: font.getItalic ? !!font.getItalic() : null,
      underline: font.getUnderline ? font.getUnderline() : null,
    };
  })()`)
}

test.describe('office xlsx — cell formatting cross-tab sync', () => {
  test('cell underline (Ctrl+U) propagates to peer', async ({ context }) => {
    const { tabA, tabB } = await openTwoTabs(context)

    await tabA.bringToFront()
    // Dismiss any first-time tutorial popups (OO v9 callouts) by clicking
    // a known dismiss-button location, then idle-clicking the cell.
    await tabA.mouse.click(440, 263)
    await tabA.waitForTimeout(500)
    await tabA.mouse.click(200, 250)
    await tabA.waitForTimeout(500)
    await tabA.keyboard.type('hello', { delay: 60 })
    await tabA.keyboard.press('Enter')
    await tabA.waitForTimeout(1_000)
    await tabA.mouse.click(200, 250)
    await tabA.waitForTimeout(500)
    await tabA.keyboard.press('Control+U')
    await tabA.waitForTimeout(5_000)

    await tabB.bringToFront()
    await tabB.mouse.click(200, 250)
    await tabB.waitForTimeout(500)
    const f = await probeActiveCell(tabB)
    expect(f.state).toBe('ok')
    // Excel underline returns an enum value (single/double/none).
    expect(f.underline, 'tab B sees cell underline').toBeTruthy()
    expect(f.underline, 'tab B underline is not "none"').not.toBe('none')
  })
})
