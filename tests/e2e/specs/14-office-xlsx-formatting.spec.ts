import { test, expect } from '@playwright/test'
import { signInOrBootstrap, attachCollabLogs } from '../fixtures/auth'

// Cross-tab cell-formatting sync for xlsx. xlsx's lock-grant for cell-level
// operations had a 3-attempt fix history (PR #9 + research file 08), so this
// gates the path against future regression.
//
// Underline uses the keyboard shortcut Ctrl+U; bold + italic use the OO
// public API (`WorkbookView.prototype.setFontAttributes(prop, val)`) to
// bypass the OO v9 first-time "Cell text direction" tutorial popup that
// intercepts Ctrl+B/Ctrl+I once per browser session. The setter routes
// through the same lock-grant + saveChanges path so it gates the same
// regression class as a keyboard shortcut would.

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
    // Active cell: prefer the WS model's selectionRange.activeCell which
    // is the canonical "currently focused" cell. Fall back to the worksheet
    // view's activeRange.r1/c1 only if that's missing. Earlier the view
    // path returned (0,0) when selection had moved to an entry-only cell;
    // model path is more reliable.
    const sr = ws.selectionRange || (wb.getWorksheet && wb.getWorksheet() && wb.getWorksheet().model && wb.getWorksheet().model.selectionRange);
    const activeCell = sr && sr.activeCell;
    const row = activeCell ? activeCell.row : 0;
    const col = activeCell ? activeCell.col : 0;
    const cell = ws.getCell3 ? ws.getCell3(row, col) : (ws.getCell ? ws.getCell(row, col) : null);
    if (!cell) return { state: 'no-cell', row, col };
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

// Apply a font attribute via OO's public API. Bypasses keyboard shortcuts
// so OO's first-time "Cell text direction" tutorial popup can't intercept.
// prop: 'b' = bold, 'i' = italic, 'u' = underline.
async function applyFontAttr(tab: any, prop: 'b' | 'i' | 'u') {
  return tab.evaluate(`(() => {
    const outerIfr = document.querySelector('iframe');
    const innerIfr = outerIfr && outerIfr.contentDocument && outerIfr.contentDocument.querySelector('iframe');
    const w = innerIfr && innerIfr.contentWindow;
    const editor = w && (w.editor || w.editorCell);
    if (!editor) return { state: 'no-editor' };
    const wb = editor.wb || editor.WB;
    if (!wb || typeof wb.setFontAttributes !== 'function') return { state: 'no-setter' };
    const val = '${prop}' === 'u' ? (w.Asc && w.Asc.EUnderline && w.Asc.EUnderline.underlineSingle) : true;
    wb.setFontAttributes('${prop}', val);
    return { state: 'ok' };
  })()`)
}

test.describe('office xlsx — cell formatting cross-tab sync', () => {
  test('cell bold via API propagates to peer', async ({ context }) => {
    const { tabA, tabB } = await openTwoTabs(context)

    await tabA.bringToFront()
    // Dismiss any first-time tutorial popups by clicking the "Got it"
    // location — even though we use the API for the actual format,
    // the popup can hold a global lock that makes setSelectionInfo no-op.
    await tabA.mouse.click(440, 263)
    await tabA.waitForTimeout(500)
    await tabA.mouse.click(200, 250)
    await tabA.waitForTimeout(500)
    await tabA.keyboard.type('hello', { delay: 60 })
    await tabA.keyboard.press('Enter')
    await tabA.waitForTimeout(1_000)
    await tabA.mouse.click(200, 250)
    await tabA.waitForTimeout(500)
    const setResult = await applyFontAttr(tabA, 'b')
    expect(setResult.state, 'tab A apply bold').toBe('ok')
    await tabA.waitForTimeout(5_000)

    // Verify locally first — narrows wire vs apply if cross-tab fails.
    const aFmt = await probeActiveCell(tabA)
    expect(aFmt.state, 'tab A probe').toBe('ok')
    expect(aFmt.bold, 'tab A applied bold locally').toBe(true)

    await tabB.bringToFront()
    await tabB.mouse.click(200, 250)
    await tabB.waitForTimeout(500)
    const f = await probeActiveCell(tabB)
    expect(f.state).toBe('ok')
    expect(f.bold, 'tab B sees cell bold').toBe(true)
  })

  test('cell italic via API propagates to peer', async ({ context }) => {
    const { tabA, tabB } = await openTwoTabs(context)

    await tabA.bringToFront()
    await tabA.mouse.click(440, 263)
    await tabA.waitForTimeout(500)
    await tabA.mouse.click(200, 250)
    await tabA.waitForTimeout(500)
    await tabA.keyboard.type('hello', { delay: 60 })
    await tabA.keyboard.press('Enter')
    await tabA.waitForTimeout(1_000)
    await tabA.mouse.click(200, 250)
    await tabA.waitForTimeout(500)
    const setResult = await applyFontAttr(tabA, 'i')
    expect(setResult.state, 'tab A apply italic').toBe('ok')
    await tabA.waitForTimeout(5_000)

    const aFmt = await probeActiveCell(tabA)
    expect(aFmt.state, 'tab A probe').toBe('ok')
    expect(aFmt.italic, 'tab A applied italic locally').toBe(true)

    await tabB.bringToFront()
    await tabB.mouse.click(200, 250)
    await tabB.waitForTimeout(500)
    const f = await probeActiveCell(tabB)
    expect(f.state).toBe('ok')
    expect(f.italic, 'tab B sees cell italic').toBe(true)
  })

  test('cell underline (Ctrl+U) propagates to peer', async ({ context }) => {
    const { tabA, tabB } = await openTwoTabs(context)

    await tabA.bringToFront()
    // Dismiss any first-time tutorial popups (OO v9 callouts) so Ctrl+U
    // isn't intercepted. Underline-only kept on the keyboard path because
    // it confirms the keyboard route stays wired alongside the API route.
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
    expect(f.underline, 'tab B sees cell underline').toBeTruthy()
    expect(f.underline, 'tab B underline is not "none"').not.toBe('none')
  })
})
